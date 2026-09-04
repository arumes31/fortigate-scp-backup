package fgtconftail

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

const (
	maxPollEvents          = 100_000
	maxPollNormalizedBytes = 64 << 20
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
	sourceGroups := catalog.sourceGroups()
	if len(sourceGroups) == 0 {
		return pollCycleStats{}, w.recordFailure(
			ctx,
			startedAt,
			errors.New("conftail source catalog has no queryable aliases"),
		)
	}
	state, err := w.store.pollState(ctx)
	if err != nil {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, err)
	}
	if pollEnd.Before(state.Watermark) {
		return pollCycleStats{}, w.recordFailure(
			ctx,
			startedAt,
			errors.New("conftail poll end precedes the stored watermark"),
		)
	}

	from := state.Watermark.Add(-w.overlap)
	if from.Before(state.ActivationAt) {
		from = state.ActivationAt
	}
	events := make([]Event, 0)
	maxEvents := w.maxEvents
	if maxEvents == 0 {
		maxEvents = maxPollEvents
	}
	maxNormalizedBytes := w.maxNormalizedBytes
	if maxNormalizedBytes == 0 {
		maxNormalizedBytes = maxPollNormalizedBytes
	}
	var normalizedBytes int64
	stats := pollCycleStats{}
	queryFingerprint := graylogQueryFingerprint(w.query)
	for _, sources := range sourceGroups {
		if w.logger != nil {
			w.logger.Info(
				"conftail Graylog query started",
				"query_sha256", queryFingerprint,
				"query_bytes", len(w.query),
				"source_count", len(sources),
				"from", from,
				"to", pollEnd,
			)
		}
		rawEvents, fetchStats, fetchErr := w.graylog.fetch(ctx, w.query, sources, from, pollEnd)
		stats.Pages += fetchStats.Pages
		stats.Fetched += fetchStats.Rows
		stats.Quarantined += fetchStats.Quarantined
		stats.Retries += fetchStats.Retries
		if fetchErr != nil {
			return pollCycleStats{}, w.recordFailure(ctx, startedAt, fetchErr)
		}
		if w.logger != nil {
			w.logger.Info(
				"conftail Graylog query completed",
				"query_sha256", queryFingerprint,
				"query_bytes", len(w.query),
				"source_count", len(sources),
				"from", from,
				"to", pollEnd,
				"pages", fetchStats.Pages,
				"rows", fetchStats.Rows,
				"quarantined_rows", fetchStats.Quarantined,
				"retries", fetchStats.Retries,
			)
		}
		if stats.Fetched > maxEvents {
			return pollCycleStats{}, w.recordFailure(
				ctx,
				startedAt,
				fmt.Errorf("conftail poll exceeds the %d-event safety limit", maxEvents),
			)
		}
		for index := range rawEvents {
			eventTime := rawEvents[index].Timestamp.UTC()
			if eventTime.Before(from) || eventTime.After(pollEnd) {
				stats.Quarantined++
				continue
			}
			firewall, ok := catalog.resolve(rawEvents[index].Source)
			if !ok {
				stats.Skipped++
				continue
			}
			event, normalizeErr := normalizeRawEvent(rawEvents[index], firewall, pollEnd)
			if normalizeErr != nil {
				stats.Quarantined++
				continue
			}
			normalizedBytes += normalizedEventBytes(event)
			if normalizedBytes > maxNormalizedBytes {
				return pollCycleStats{}, w.recordFailure(
					ctx,
					startedAt,
					fmt.Errorf("conftail poll exceeds the %d-byte normalized-data safety limit", maxNormalizedBytes),
				)
			}
			events = append(events, event)
		}
	}
	if err := recoverMissingUsers(ctx, events, w.missingUserWindow); err != nil {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, err)
	}

	result, err := w.store.applyPoll(ctx, pollBatch{
		StartedAt:   startedAt,
		EndedAt:     pollEnd,
		CompletedAt: w.currentTime(),
		Pages:       stats.Pages,
		Fetched:     stats.Fetched,
		Events:      events,
	}, w.idle, w.maxDescriptionBytes)
	if err != nil {
		return pollCycleStats{}, w.recordFailure(ctx, startedAt, err)
	}
	stats.Inserted = result.Inserted
	stats.Duplicates = result.Duplicates
	stats.Ignored = result.Ignored
	stats.Sealed = result.Sealed
	return stats, nil
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
