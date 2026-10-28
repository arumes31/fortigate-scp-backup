package fgtconftail

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	maxPollEvents             = 100_000
	maxPollNormalizedBytes    = 64 << 20
	firewallPollConcurrency   = 8
	firewallPollTimeout       = 15 * time.Second
	firewallWriteTimeout      = 3 * time.Second
	maxFirewallPollWindow     = time.Hour
	minFirewallPollWindow     = time.Second
	maxFirewallHistoryWindows = 4
)

type graylogFetcher interface {
	fetch(
		ctx context.Context,
		baseQuery string,
		sourceAliases []string,
		from time.Time,
		to time.Time,
	) ([]RawEvent, FetchStats, error)
}

type pollCycleStats struct {
	Pages       int
	Fetched     int
	Quarantined int
	Retries     int
	Skipped     int
	Inserted    int
	Duplicates  int
	Ignored     int
	Sealed      int
}

type pollWorker struct {
	store               *store
	logger              *slog.Logger
	graylog             graylogFetcher
	loadCatalog         func(context.Context) (sourceCatalog, error)
	publishCatalog      func(sourceCatalog)
	query               string
	overlap             time.Duration
	idle                time.Duration
	maxDescriptionBytes int
	missingUserWindow   time.Duration
	maxEvents           int
	maxNormalizedBytes  int64
	now                 func() time.Time
}

func (w *pollWorker) poll(ctx context.Context, pollEnd time.Time) (pollCycleStats, error) {
	if err := w.validate(); err != nil {
		return pollCycleStats{}, err
	}
	pollEnd = pollEnd.UTC()
	if pollEnd.IsZero() {
		return pollCycleStats{}, errors.New("conftail poll end is required")
	}
	startedAt := w.currentTime()
	if err := w.store.markPollStarted(ctx, startedAt); err != nil {
		return pollCycleStats{}, err
	}
	catalog, err := w.loadCatalog(ctx)
	if err != nil {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, err)
	}
	if w.publishCatalog != nil {
		w.publishCatalog(catalog)
	}
	if len(catalog.aliases) == 0 {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, errors.New("conftail source catalog has no queryable aliases"))
	}
	state, err := w.store.pollState(ctx)
	if err != nil {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, err)
	}
	if pollEnd.Before(state.Watermark) {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, errors.New("conftail poll end precedes the stored watermark"))
	}
	checkpoints, err := w.store.firewallCheckpoints(ctx, catalog, state)
	if err != nil {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, err)
	}
	type outcome struct {
		stats pollCycleStats
		err   error
	}
	jobs := make(chan firewallCheckpoint)
	results := make(chan outcome, len(checkpoints))
	var workers sync.WaitGroup
	for range min(firewallPollConcurrency, len(checkpoints)) {
		workers.Go(func() {
			for cp := range jobs {
				stats, err := w.pollFirewall(ctx, catalog, cp, state.ActivationAt, pollEnd)
				results <- outcome{stats, err}
			}
		})
	}
	for _, cp := range checkpoints {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- cp:
		case <-ctx.Done():
		}
	}
	close(jobs)
	workers.Wait()
	close(results)
	stats := pollCycleStats{}
	var failures []error
	for result := range results {
		stats.add(result.stats)
		if result.err != nil {
			failures = append(failures, result.err)
		}
	}
	if ctx.Err() != nil {
		failures = append(failures, ctx.Err())
	}
	var pollErr error
	if len(failures) != 0 {
		pollErr = fmt.Errorf("%d firewall poll failure(s): %w", len(failures), errors.Join(failures...))
	}
	// Persist aggregate health even if the cycle's deadline expired. Individual
	// successful transactions and their checkpoints are already durable.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := w.store.finishPoll(finishCtx, startedAt, w.currentTime(), stats, pollErr); err != nil {
		return stats, errors.Join(pollErr, err)
	}
	return stats, pollErr
}

func (s *pollCycleStats) add(other pollCycleStats) {
	s.Pages += other.Pages
	s.Fetched += other.Fetched
	s.Quarantined += other.Quarantined
	s.Retries += other.Retries
	s.Skipped += other.Skipped
	s.Inserted += other.Inserted
	s.Duplicates += other.Duplicates
	s.Ignored += other.Ignored
	s.Sealed += other.Sealed
}

func (w *pollWorker) pollFirewall(parent context.Context, catalog sourceCatalog, cp firewallCheckpoint, activation, pollEnd time.Time) (pollCycleStats, error) {
	ctx, cancel := context.WithTimeout(parent, firewallPollTimeout)
	defer cancel()
	if _, err := w.store.db.ExecContext(ctx, `UPDATE firewall_poll_state SET last_attempt_ns = ? WHERE firewall_id = ?`, unixNanos(pollEnd), cp.ID); err != nil {
		return pollCycleStats{}, err
	}
	stats := pollCycleStats{}
	var failures []error
	// Always collect the newest changes before working on older history. The
	// historical cursor remains intact until every intervening window commits.
	from := pollEnd.Add(-min(w.overlap, cp.RecentWindow))
	if from.Before(activation) {
		from = activation
	}
	recentFrom := from
	sealFrom := from
	if !cp.RecentFrom.IsZero() && !cp.RecentTo.Before(from) {
		sealFrom = minTime(sealFrom, cp.RecentFrom)
	}
	if !cp.Watermark.Before(sealFrom) {
		sealFrom = time.Time{}
	}
	recentCtx, recentCancel := context.WithTimeout(ctx, firewallPollTimeout/2)
	recent, recentErr := w.pollFirewallWindow(recentCtx, catalog, pollBatch{
		FirewallID: cp.ID, RangeFrom: from, EndedAt: pollEnd, Recent: true, SealFrom: sealFrom,
	}, activation, pollEnd)
	recentCancel()
	stats.add(recent)
	if recentErr != nil {
		failures = append(failures, fmt.Errorf("recent changes: %w", recentErr))
	} else {
		if !cp.RecentFrom.IsZero() && !cp.RecentTo.Before(from) {
			from = minTime(from, cp.RecentFrom)
		}
		cp.RecentFrom, cp.RecentTo = from, pollEnd
		if !cp.Watermark.Before(from) {
			cp.Watermark = pollEnd
		}
	}
	var historyErr error
	historyAttempted := false
	// A failed recent query does not suppress historical recovery, and vice versa.
	for range maxFirewallHistoryWindows {
		if ctx.Err() != nil {
			break
		}
		replay := !cp.Watermark.Before(pollEnd)
		to := minTime(cp.Watermark.Add(cp.Window), pollEnd)
		if !cp.RecentFrom.IsZero() && cp.RecentFrom.After(cp.Watermark) {
			to = minTime(to, cp.RecentFrom)
		}
		from := cp.Watermark
		if replay {
			// Sweep look-back periods longer than the recent window in bounded
			// pieces too. This retains late-indexing coverage without multi-day queries.
			from = maxTime(activation, pollEnd.Add(-w.overlap))
			if !from.Before(recentFrom) {
				break
			}
			if cp.ReplayTo.After(from) && cp.ReplayTo.Before(recentFrom) {
				from = cp.ReplayTo
			}
			to = minTime(from.Add(cp.Window), recentFrom)
		}
		history, err := w.pollFirewallWindow(ctx, catalog, pollBatch{
			FirewallID: cp.ID, RangeFrom: from, EndedAt: to, Replay: replay,
			ReplayComplete: replay && !to.Before(recentFrom),
		}, activation, pollEnd)
		historyAttempted = true
		stats.add(history)
		if err != nil {
			historyErr = err
			failures = append(failures, fmt.Errorf("history %s..%s: %w", from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano), err))
			break
		}
		if replay {
			cp.ReplayTo = to
			if !to.Before(recentFrom) {
				break
			}
			continue
		}
		cp.Watermark = to
		if !cp.RecentFrom.IsZero() && !to.Before(cp.RecentFrom) {
			cp.Watermark = maxTime(to, cp.RecentTo)
		}
	}
	pollErr := errors.Join(failures...)
	message := ""
	window := cp.Window
	if historyAttempted {
		window = min(maxFirewallPollWindow, cp.Window*2)
		if historyErr != nil {
			window = max(minFirewallPollWindow, cp.Window/2)
		}
	}
	recentWindow := min(maxFirewallPollWindow, cp.RecentWindow*2)
	if recentErr != nil {
		recentWindow = max(minFirewallPollWindow, cp.RecentWindow/2)
	}
	if pollErr != nil {
		message = sanitizeDeliveryError(pollErr)
		if w.logger != nil {
			w.logger.Error("conftail firewall poll failed", "firewall_id", cp.ID, "err", message, "next_window", window)
		}
	}
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer finishCancel()
	_, finishErr := w.store.db.ExecContext(finishCtx, `UPDATE firewall_poll_state SET window_ns = ?, recent_window_ns = ?, last_error = ? WHERE firewall_id = ?`, int64(window), int64(recentWindow), message, cp.ID)
	if err := errors.Join(pollErr, finishErr); err != nil {
		return stats, fmt.Errorf("firewall %d: %w", cp.ID, err)
	}
	return stats, nil
}

func (w *pollWorker) pollFirewallWindow(ctx context.Context, catalog sourceCatalog, batch pollBatch, activation, pollEnd time.Time) (pollCycleStats, error) {
	firewallID, from, to := batch.FirewallID, batch.RangeFrom, batch.EndedAt
	// Fetch full neighboring context even when the committed window shrinks to
	// a second. Context rows inform attribution but are not committed or sealed
	// ahead of the historical cursor.
	queryFrom := maxTime(activation, from.Add(-w.missingUserWindow))
	queryTo := minTime(pollEnd, to.Add(w.missingUserWindow))
	stats := pollCycleStats{}
	var events []Event
	var inWindow []bool
	var normalizedBytes int64
	maxEvents := w.maxEvents
	if maxEvents == 0 {
		maxEvents = maxPollEvents / firewallPollConcurrency
	}
	maxBytes := w.maxNormalizedBytes
	if maxBytes == 0 {
		maxBytes = maxPollNormalizedBytes / firewallPollConcurrency
	}
	aliases := catalog.byID[firewallID].Aliases
	for start := 0; start < len(aliases); start += maxSourceAliasesPerGroup {
		sources := aliases[start:min(start+maxSourceAliasesPerGroup, len(aliases))]
		if w.logger != nil {
			w.logger.Info("conftail Graylog query started", "firewall_id", firewallID, "recent", batch.Recent,
				"query_sha256", graylogQueryFingerprint(w.query), "query_bytes", len(w.query), "source_count", len(sources), "from", queryFrom, "to", queryTo)
		}
		rawEvents, fetched, err := w.graylog.fetch(ctx, w.query, sources, queryFrom, queryTo)
		stats.Pages += fetched.Pages
		stats.Fetched += fetched.Rows
		stats.Quarantined += fetched.Quarantined
		stats.Retries += fetched.Retries
		if err != nil {
			return stats, err
		}
		if w.logger != nil {
			w.logger.Info("conftail Graylog query completed", "firewall_id", firewallID,
				"query_sha256", graylogQueryFingerprint(w.query), "query_bytes", len(w.query), "source_count", len(sources), "from", queryFrom, "to", queryTo,
				"pages", fetched.Pages, "rows", fetched.Rows, "quarantined_rows", fetched.Quarantined, "retries", fetched.Retries)
		}
		if stats.Fetched > maxEvents {
			return stats, fmt.Errorf("conftail poll exceeds the %d-event safety limit", maxEvents)
		}
		for _, raw := range rawEvents {
			if raw.Timestamp.Before(queryFrom) || raw.Timestamp.After(queryTo) {
				stats.Quarantined++
				continue
			}
			firewall, ok := catalog.resolve(raw.Source)
			if !ok || firewall.ID != firewallID {
				if !raw.Timestamp.Before(from) && !raw.Timestamp.After(to) {
					stats.Skipped++
				}
				continue
			}
			event, err := normalizeRawEvent(raw, firewall, pollEnd)
			if err != nil {
				stats.Quarantined++
				continue
			}
			normalizedBytes += normalizedEventBytes(event)
			if normalizedBytes > maxBytes {
				return stats, fmt.Errorf("conftail poll exceeds the %d-byte normalized-data safety limit", maxBytes)
			}
			events = append(events, event)
			inWindow = append(inWindow, !raw.Timestamp.Before(from) && !raw.Timestamp.After(to))
		}
	}
	if err := recoverMissingUsers(ctx, events, w.missingUserWindow); err != nil {
		return stats, err
	}
	committed := events[:0]
	for i, event := range events {
		if inWindow[i] {
			committed = append(committed, event)
		}
	}
	batch.StartedAt, batch.Pages, batch.Fetched, batch.Events = pollEnd, stats.Pages, stats.Fetched, committed
	batch.Companies = map[int]string{firewallID: catalog.byID[firewallID].Company}
	result, err := w.store.applyPoll(ctx, batch, w.idle, w.maxDescriptionBytes)
	if err != nil {
		return stats, err
	}
	stats.Inserted, stats.Duplicates, stats.Ignored, stats.Sealed = result.Inserted, result.Duplicates, result.Ignored, result.Sealed
	return stats, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func graylogQueryFingerprint(query string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(query)))
}

func normalizedEventBytes(event Event) int64 {
	return int64(len(event.GraylogID) + len(event.SemanticHash) + len(event.CorrelationHash) +
		len(event.FirewallName) + len(event.Source) + len(event.DeviceName) +
		len(event.DeviceID) + len(event.VDOM) + len(event.User) +
		len(event.UserAttribution) + len(event.UI) + len(event.Action) +
		len(event.TransactionID) + len(event.Path) + len(event.Object) +
		len(event.ConfigAttribute) + len(event.LogID) +
		len(event.LogDescription) + len(event.Message) + len(event.UUID))
}

func (w *pollWorker) validate() error {
	if w.store == nil {
		return errors.New("conftail store is required")
	}
	if w.graylog == nil {
		return errors.New("conftail Graylog client is required")
	}
	if w.loadCatalog == nil {
		return errors.New("conftail source catalog loader is required")
	}
	if strings.TrimSpace(w.query) == "" {
		return errors.New("conftail Graylog query is required")
	}
	if w.overlap <= 0 {
		return errors.New("conftail overlap must be positive")
	}
	if w.idle <= 0 {
		return errors.New("conftail idle duration must be positive")
	}
	if w.maxDescriptionBytes <= 0 {
		return errors.New("conftail ticket description limit must be positive")
	}
	if w.missingUserWindow <= 0 {
		return errors.New("conftail missing-user correlation window must be positive")
	}
	if w.maxEvents < 0 || w.maxNormalizedBytes < 0 {
		return errors.New("conftail poll safety limits must not be negative")
	}
	return nil
}

func (w *pollWorker) recordFailure(
	parent context.Context,
	startedAt time.Time,
	pollErr error,
) error {
	failureCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	if err := w.store.markPollFailed(failureCtx, startedAt, w.currentTime(), pollErr); err != nil {
		return errors.Join(pollErr, err)
	}
	return pollErr
}

func (w *pollWorker) currentTime() time.Time {
	if w.now != nil {
		return w.now().UTC()
	}
	return time.Now().UTC()
}
