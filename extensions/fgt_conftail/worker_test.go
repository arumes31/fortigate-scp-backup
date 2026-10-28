package fgtconftail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPollWorkerFreezesADMCompanyInTicket(t *testing.T) {
	ctx := context.Background()
	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, activation)
	dataDir := t.TempDir()
	createADMDatabase(t, dataDir, []admTestRow{{
		FirewallName: "cluster-fw", DNSNameFull: "cluster.example.test",
		ClusterHostnames: "node-a,node-b", Company: "Acme-Europe",
	}})
	worker := pollWorker{
		store: s,
		loadCatalog: func(ctx context.Context) (sourceCatalog, error) {
			return buildSourceCatalog(ctx, []firewallRef{{ID: 7, Name: "cluster.example.test"}}, dataDir)
		},
		graylog: &scriptedGraylogFetcher{fn: func(call int, _ []string) ([]RawEvent, FetchStats, error) {
			if call > 0 {
				return nil, FetchStats{}, nil
			}
			return []RawEvent{rawConfigEvent("company-event", "node-a", "operator", "tx-1", activation.Add(time.Minute))}, FetchStats{Pages: 1, Rows: 1}, nil
		}},
		query: "type:event", overlap: time.Hour, idle: 30 * time.Minute,
		maxDescriptionBytes: maxTicketDescriptionBytes,
		missingUserWindow:   5 * time.Minute,
	}
	// Seal on a later, empty poll: company routing cannot depend on new events.
	for _, offset := range []time.Duration{5 * time.Minute, 40 * time.Minute} {
		if _, err := worker.poll(ctx, activation.Add(offset)); err != nil {
			t.Fatal(err)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(onlyPayload(t, s), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["company"] != "Acme-Europe" {
		t.Fatalf("ticket company = %v, want ADM company identifier", payload["company"])
	}
}

type graylogFetchCall struct {
	query   string
	sources []string
	from    time.Time
	to      time.Time
}

type scriptedGraylogFetcher struct {
	mu    sync.Mutex
	calls []graylogFetchCall
	fn    func(call int, sources []string) ([]RawEvent, FetchStats, error)
}

func (f *scriptedGraylogFetcher) fetch(
	_ context.Context,
	query string,
	sources []string,
	from time.Time,
	to time.Time,
) ([]RawEvent, FetchStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, graylogFetchCall{
		query:   query,
		sources: append([]string{}, sources...),
		from:    from,
		to:      to,
	})
	return f.fn(len(f.calls)-1, sources)
}

func TestPollWorkerPersistsAttributedAndUnattributedChanges(t *testing.T) {
	t.Parallel()
	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	pollEnd := activation.Add(15 * time.Minute)
	s := newTestStore(t, activation)
	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 7, Name: "fw-a.example.com"}},
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}

	fetcher := &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
		return []RawEvent{
			rawConfigEvent("m-1", "FW-A", "admin-a", "tx-1", activation.Add(time.Minute)),
			rawConfigEvent("m-2", "fw-a.example.com", "", "tx-1", activation.Add(2*time.Minute)),
			rawConfigEvent("m-3", "fw-a", "", "tx-unknown", activation.Add(3*time.Minute)),
		}, FetchStats{Pages: 2, Rows: 4, Quarantined: 1}, nil
	}}
	var published sourceCatalog
	clockCalls := 0
	worker := pollWorker{
		store:               s,
		graylog:             fetcher,
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
		publishCatalog:      func(value sourceCatalog) { published = value },
		query:               "type:event AND logid:0100044544",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
		now: func() time.Time {
			clockCalls++
			return pollEnd.Add(time.Duration(clockCalls-1) * 2 * time.Second)
		},
	}

	stats, err := worker.poll(context.Background(), pollEnd)
	if err != nil {
		t.Fatalf("poll() error = %v", err)
	}
	if stats.Fetched != 4 || stats.Quarantined != 1 || stats.Inserted != 3 || stats.Pages != 2 {
		t.Fatalf("poll stats = %+v, want fetched/quarantined/inserted/pages 4/1/3/2", stats)
	}
	if len(fetcher.calls) != 1 {
		t.Fatalf("fetch calls = %d, want 1", len(fetcher.calls))
	}
	call := fetcher.calls[0]
	if !call.from.Equal(activation) || !call.to.Equal(pollEnd) {
		t.Fatalf("fetch range = %s..%s, want activation..poll end", call.from, call.to)
	}
	if call.query != worker.query {
		t.Fatalf("fetch query = %q, want %q", call.query, worker.query)
	}
	if !reflect.DeepEqual(call.sources, []string{"fw-a", "fw-a.example.com"}) {
		t.Fatalf("fetch sources = %v", call.sources)
	}
	if len(published.coverage()) != 1 {
		t.Fatalf("published catalog coverage = %+v", published.coverage())
	}

	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatalf("pollState() error = %v", err)
	}
	if !state.Watermark.Equal(pollEnd) || state.LastFetched != 4 || state.LastInserted != 3 {
		t.Fatalf("poll state = %+v", state)
	}
	if !state.LastSuccessAt.Equal(pollEnd.Add(2*time.Second)) || state.LastDuration != 2*time.Second {
		t.Fatalf("poll completion metrics = success %s duration %s", state.LastSuccessAt, state.LastDuration)
	}
	if got := countRowsWhere(t, s, "events", "user = 'admin-a'"); got != 2 {
		t.Fatalf("admin-attributed events = %d, want 2", got)
	}
	if got := countRowsWhere(t, s, "events", "user = '[unattributed]'"); got != 1 {
		t.Fatalf("unattributed events = %d, want 1", got)
	}
	if got := countRows(t, s, "chains"); got != 2 {
		t.Fatalf("chains = %d, want separate admin and unattributed chains", got)
	}
}

func TestPollWorkerLogsGraylogQueries(t *testing.T) {
	t.Parallel()

	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	pollEnd := activation.Add(15 * time.Minute)
	s := newTestStore(t, activation)
	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 7, Name: "fw-a.example.com"}},
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	worker := pollWorker{
		store:  s,
		logger: slog.New(slog.NewJSONHandler(&output, nil)),
		graylog: &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
			return nil, FetchStats{Pages: 2, Rows: 3}, nil
		}},
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
		query:               "type:event AND logid:0100044544",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
	}
	if _, err := worker.poll(context.Background(), pollEnd); err != nil {
		t.Fatal(err)
	}

	logs := output.String()
	queryFingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(worker.query)))
	for _, want := range []string{
		`"msg":"conftail Graylog query started"`,
		`"msg":"conftail Graylog query completed"`,
		`"query_sha256":"` + queryFingerprint + `"`,
		fmt.Sprintf(`"query_bytes":%d`, len(worker.query)),
		`"source_count":2`,
		`"pages":2`,
		`"rows":3`,
		`"from":"2026-09-01T08:00:00Z"`,
		`"to":"2026-09-01T08:15:00Z"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("ConfTail logs do not contain %q:\n%s", want, logs)
		}
	}
	for _, unsafe := range []string{
		"type:event AND logid:0100044544",
		"graylog-token",
		"fw-a",
		"fw-a.example.com",
	} {
		if strings.Contains(logs, unsafe) {
			t.Errorf("ConfTail logs expose %q:\n%s", unsafe, logs)
		}
	}
}

func TestGraylogQueryFingerprintDoesNotExposeConfiguredQuery(t *testing.T) {
	t.Parallel()

	const query = `type:event AND password:"super-secret"`
	if got := graylogQueryFingerprint(query); got == "" || strings.Contains(got, "super-secret") {
		t.Fatalf("graylogQueryFingerprint() = %q", got)
	}
}

func TestPollWorkerCommitsHealthyFirewallsOnPartialGraylogFailure(t *testing.T) {
	t.Parallel()
	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, activation)
	registered := make([]firewallRef, 0, 13)
	for id := 1; id <= 13; id++ {
		registered = append(registered, firewallRef{ID: id, Name: fmt.Sprintf("fw-%02d.example.com", id)})
	}
	catalog, err := buildSourceCatalog(context.Background(), registered, t.TempDir())
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}
	fetcher := &scriptedGraylogFetcher{fn: func(_ int, sources []string) ([]RawEvent, FetchStats, error) {
		if sources[0] == "fw-02" {
			return nil, FetchStats{Pages: 1}, errors.New("graylog page failed")
		}
		return []RawEvent{
			rawConfigEvent(sources[0], sources[0], "admin-a", "tx-1", activation.Add(time.Minute)),
		}, FetchStats{Pages: 1, Rows: 1}, nil
	}}
	worker := pollWorker{
		store: s, graylog: fetcher,
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
		query:               "type:event",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
	}

	if _, err := worker.poll(context.Background(), activation.Add(15*time.Minute)); err == nil {
		t.Fatal("poll() succeeded after one Graylog source group failed")
	}
	if got := countRows(t, s, "events"); got != 12 {
		t.Fatalf("events persisted from healthy firewalls = %d, want 12", got)
	}
	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatalf("pollState() error = %v", err)
	}
	if !state.Watermark.Equal(activation) {
		t.Fatalf("watermark = %s, want unchanged %s", state.Watermark, activation)
	}
	if state.LastFailureAt.IsZero() || state.LastError == "" {
		t.Fatalf("poll failure was not recorded: %+v", state)
	}
}

func TestPollWorkerQuarantinesUnexpectedOrUnsupportedRows(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*RawEvent)
	}{
		{name: "unsupported log id", mutate: func(event *RawEvent) { event.LogID = "0100044548" }},
		{name: "unsupported event type", mutate: func(event *RawEvent) { event.Type = "traffic" }},
		{name: "unsupported event subtype", mutate: func(event *RawEvent) { event.Subtype = "vpn" }},
		{name: "before requested range", mutate: func(event *RawEvent) {
			event.Timestamp = event.Timestamp.Add(-2 * time.Minute)
		}},
		{name: "after requested range", mutate: func(event *RawEvent) {
			event.Timestamp = event.Timestamp.Add(15 * time.Minute)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
			s := newTestStore(t, activation)
			catalog, err := buildSourceCatalog(
				context.Background(),
				[]firewallRef{{ID: 1, Name: "fw-a.example.com"}},
				t.TempDir(),
			)
			if err != nil {
				t.Fatalf("buildSourceCatalog() error = %v", err)
			}
			raw := rawConfigEvent("m-1", "fw-a", "admin-a", "tx-1", activation.Add(time.Minute))
			test.mutate(&raw)
			valid := rawConfigEvent("m-2", "fw-a", "admin-a", "tx-2", activation.Add(2*time.Minute))
			pollEnd := activation.Add(15 * time.Minute)
			worker := pollWorker{
				store: s,
				graylog: &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
					return []RawEvent{raw, valid}, FetchStats{Pages: 1, Rows: 2}, nil
				}},
				loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
				query:               "type:event",
				overlap:             time.Hour,
				idle:                30 * time.Minute,
				maxDescriptionBytes: 60_000,
				missingUserWindow:   5 * time.Minute,
			}
			stats, err := worker.poll(context.Background(), pollEnd)
			if err != nil {
				t.Fatalf("poll() failed instead of quarantining one row: %v", err)
			}
			if stats.Quarantined != 1 || stats.Inserted != 1 {
				t.Fatalf("poll stats = %+v, want one quarantined and one inserted", stats)
			}
			if got := countRows(t, s, "events"); got != 1 {
				t.Fatalf("events = %d, want only the valid row", got)
			}
			state, err := s.pollState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !state.Watermark.Equal(pollEnd) {
				t.Fatalf("watermark = %s, want %s", state.Watermark, pollEnd)
			}
		})
	}
}

func TestPollWorkerSkipsUnregisteredSources(t *testing.T) {
	t.Parallel()
	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	pollEnd := activation.Add(15 * time.Minute)
	s := newTestStore(t, activation)
	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 1, Name: "fw-a.example.com"}},
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worker := pollWorker{
		store: s,
		graylog: &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
			return []RawEvent{
				rawConfigEvent("unknown", "not-registered", "admin-a", "tx-1", activation.Add(time.Minute)),
				rawConfigEvent("known", "fw-a", "admin-a", "tx-1", activation.Add(2*time.Minute)),
			}, FetchStats{Pages: 1, Rows: 2}, nil
		}},
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
		query:               "type:event",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
	}

	stats, err := worker.poll(context.Background(), pollEnd)
	if err != nil {
		t.Fatalf("poll() error = %v", err)
	}
	if stats.Fetched != 2 || stats.Skipped != 1 || stats.Inserted != 1 {
		t.Fatalf("poll stats = %+v, want fetched/skipped/inserted 2/1/1", stats)
	}
	if got := countRows(t, s, "events"); got != 1 {
		t.Fatalf("events = %d, want 1", got)
	}
	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Watermark.Equal(pollEnd) || state.LastFetched != 2 || state.LastInserted != 1 {
		t.Fatalf("poll state = %+v", state)
	}
}

func TestPollWorkerDoesNotAdvanceWithoutQueryableSources(t *testing.T) {
	t.Parallel()
	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, activation)
	worker := pollWorker{
		store: s,
		graylog: &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
			t.Fatal("Graylog fetch must not run without queryable source aliases")
			return nil, FetchStats{}, nil
		}},
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return sourceCatalog{}, nil },
		query:               "type:event",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
	}

	if _, err := worker.poll(context.Background(), activation.Add(15*time.Minute)); err == nil {
		t.Fatal("poll() succeeded without queryable source aliases")
	}
	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Watermark.Equal(activation) {
		t.Fatalf("watermark = %s, want unchanged %s", state.Watermark, activation)
	}
	if state.LastFailureAt.IsZero() || state.LastError == "" {
		t.Fatalf("poll failure was not recorded: %+v", state)
	}
}

func TestPollWorkerDoesNotAdvanceWhenPollSafetyLimitIsExceeded(t *testing.T) {
	t.Parallel()
	activation := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, activation)
	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 1, Name: "fw-a.example.com"}},
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worker := pollWorker{
		store: s,
		graylog: &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
			return []RawEvent{
				rawConfigEvent("m-1", "fw-a", "admin-a", "tx-1", activation.Add(time.Minute)),
				rawConfigEvent("m-2", "fw-a", "admin-a", "tx-1", activation.Add(2*time.Minute)),
			}, FetchStats{Pages: 1, Rows: 2}, nil
		}},
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
		query:               "type:event",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
		maxEvents:           1,
	}
	if _, err := worker.poll(context.Background(), activation.Add(15*time.Minute)); err == nil {
		t.Fatal("poll() succeeded after exceeding its event safety limit")
	}
	if got := countRows(t, s, "events"); got != 0 {
		t.Fatalf("events = %d, want none after safety-limit failure", got)
	}
	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Watermark.Equal(activation) {
		t.Fatalf("watermark = %s, want unchanged %s", state.Watermark, activation)
	}
}

func rawConfigEvent(id, source, user, transactionID string, eventAt time.Time) RawEvent {
	return RawEvent{
		Timestamp:           eventAt,
		MessageID:           id,
		Type:                "event",
		Subtype:             "system",
		Source:              source,
		User:                user,
		ConfigTransactionID: transactionID,
		ConfigPath:          "firewall.policy",
		ConfigObject:        "1",
		ConfigAttribute:     "name[old->new]",
		LogID:               "0100044544",
	}
}

type rangeGraylogFetcher func(context.Context, []string, time.Time, time.Time) ([]RawEvent, FetchStats, error)

func (f rangeGraylogFetcher) fetch(ctx context.Context, _ string, sources []string, from, to time.Time) ([]RawEvent, FetchStats, error) {
	return f(ctx, sources, from, to)
}

func recoveryWorker(t *testing.T, s *store, activation time.Time, fetcher graylogFetcher, ids ...int) *pollWorker {
	t.Helper()
	var registered []firewallRef
	for _, id := range ids {
		registered = append(registered, firewallRef{ID: id, Name: fmt.Sprintf("fw-%d.example.test", id)})
	}
	catalog, err := buildSourceCatalog(context.Background(), registered, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &pollWorker{store: s, graylog: fetcher,
		loadCatalog: func(context.Context) (sourceCatalog, error) { return catalog, nil },
		query:       "type:event", overlap: time.Hour, idle: 30 * time.Minute,
		maxDescriptionBytes: maxTicketDescriptionBytes, missingUserWindow: missingUserWindow}
}

func TestPollWorkerRecoversEightDayBacklogWhileCollectingRecentChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	activation := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	now := activation.Add(8 * 24 * time.Hour)
	s := newTestStore(t, activation)
	raw := []RawEvent{
		rawConfigEvent("old", "fw-1", "admin", "1", activation.Add(10*time.Minute)),
		rawConfigEvent("middle", "fw-1", "admin", "2", activation.Add(4*24*time.Hour)),
		rawConfigEvent("recent", "fw-1", "admin", "3", now.Add(-5*time.Minute)),
	}
	fetcher := rangeGraylogFetcher(func(_ context.Context, _ []string, from, to time.Time) ([]RawEvent, FetchStats, error) {
		if to.Sub(from) > maxFirewallPollWindow+2*missingUserWindow {
			t.Errorf("unbounded range: %s..%s", from, to)
		}
		var selected []RawEvent
		for _, event := range raw {
			if !event.Timestamp.Before(from) && !event.Timestamp.After(to) {
				selected = append(selected, event)
			}
		}
		return selected, FetchStats{Pages: 1, Rows: len(selected)}, nil
	})
	worker := recoveryWorker(t, s, activation, fetcher, 1)
	stats, err := worker.poll(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 2 {
		t.Fatalf("first pass inserted %d, want old and recent changes", stats.Inserted)
	}
	state, err := s.pollState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.BacklogFirewalls != 1 || !state.Watermark.After(activation) || !state.Watermark.Before(now) {
		t.Fatalf("first pass did not checkpoint bounded progress: %+v", state)
	}
	for cycle := 0; cycle < 80 && state.Watermark.Before(now); cycle++ {
		before := state.Watermark
		// Recreate the worker to exercise durable rather than in-memory progress.
		worker = recoveryWorker(t, s, activation, fetcher, 1)
		if _, err := worker.poll(ctx, now); err != nil {
			t.Fatal(err)
		}
		state, err = s.pollState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !state.Watermark.After(before) {
			t.Fatalf("history stuck at %s", before)
		}
	}
	if !state.Watermark.Equal(now) || state.BacklogFirewalls != 0 {
		t.Fatalf("backlog did not catch up: %+v", state)
	}
	if got := countRows(t, s, "events"); got != 3 {
		t.Fatalf("events = %d, want all three without duplicates", got)
	}
}

func TestPollWorkerHistoricalFailureDoesNotBlockRecentChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	activation := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	now := activation.Add(8 * 24 * time.Hour)
	s := newTestStore(t, activation)
	var previousHistoryWidth time.Duration
	fetcher := rangeGraylogFetcher(func(_ context.Context, _ []string, from, to time.Time) ([]RawEvent, FetchStats, error) {
		if to.Before(now.Add(-time.Hour)) {
			width := to.Sub(from)
			if previousHistoryWidth != 0 && width >= previousHistoryWidth {
				t.Errorf("failed range did not shrink: %s >= %s", width, previousHistoryWidth)
			}
			previousHistoryWidth = width
			return nil, FetchStats{}, errors.New("historical lookup unavailable")
		}
		return []RawEvent{rawConfigEvent(to.String(), "fw-1", "admin", "recent", to.Add(-time.Minute))}, FetchStats{Pages: 1, Rows: 1}, nil
	})
	worker := recoveryWorker(t, s, activation, fetcher, 1)
	for cycle := range 3 {
		stats, err := worker.poll(ctx, now.Add(time.Duration(cycle)*time.Minute))
		if err == nil || stats.Inserted != 1 {
			t.Fatalf("recent changes blocked by history: stats=%+v err=%v", stats, err)
		}
	}
	state, err := s.pollState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Watermark.Equal(activation) || state.FailedFirewalls != 1 || state.BacklogFirewalls != 1 {
		t.Fatalf("failed history was skipped or hidden: %+v", state)
	}
	if got := countRows(t, s, "events"); got != 3 {
		t.Fatalf("recent events = %d, want 3", got)
	}
}

func TestPollWorkerBlockedFirewallDoesNotBlockHealthyFirewall(t *testing.T) {
	t.Parallel()
	activation := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	now := activation.Add(time.Hour)
	s := newTestStore(t, activation)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	fetcher := rangeGraylogFetcher(func(ctx context.Context, sources []string, _, to time.Time) ([]RawEvent, FetchStats, error) {
		if sources[0] == "fw-1" {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, FetchStats{}, errors.New("firewall lookup blocked")
		}
		return []RawEvent{rawConfigEvent("healthy", sources[0], "admin", "1", to.Add(-45*time.Minute))}, FetchStats{Pages: 1, Rows: 1}, nil
	})
	worker := recoveryWorker(t, s, activation, fetcher, 1, 2)
	done := make(chan error, 1)
	go func() { _, err := worker.poll(ctx, now); done <- err }()
	// Observe a committed event and sealed session while the first fetch is
	// still blocked, rather than merely checking that its neighbor was queried.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		if err := s.readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("healthy firewall failed to commit while its neighbor was blocked")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("blocked collector returned early: %v", err)
	default:
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("blocked firewall failure was hidden")
	}
}

func TestPollWorkerSealsRecentSessionWhileHistoryKeepsFailing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	activation := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	now := activation.Add(8 * 24 * time.Hour)
	s := newTestStore(t, activation)
	event := rawConfigEvent("recent-session", "fw-1", "admin", "recent", now.Add(-time.Minute))
	fetcher := rangeGraylogFetcher(func(_ context.Context, _ []string, from, to time.Time) ([]RawEvent, FetchStats, error) {
		if to.Before(now.Add(-time.Hour)) {
			return nil, FetchStats{}, errors.New("old range unavailable")
		}
		if to.Sub(from) != time.Hour+missingUserWindow {
			t.Errorf("history failure shrank recent collection to %s", to.Sub(from))
		}
		return []RawEvent{event}, FetchStats{Pages: 1, Rows: 1}, nil
	})
	worker := recoveryWorker(t, s, activation, fetcher, 1)
	for cycle := range 32 {
		if _, err := worker.poll(ctx, now.Add(time.Duration(cycle)*time.Minute)); err == nil {
			t.Fatal("historical failure was hidden")
		}
	}
	if got := countRows(t, s, "outbox"); got != 1 {
		t.Fatalf("recent session did not seal independently: %d deliveries", got)
	}
}

func TestPollWorkerSweepsLongOverlapWithoutUnboundedQueries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	activation := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	now := activation.Add(8 * 24 * time.Hour)
	s := newTestStore(t, activation)
	// History is already caught up, but Graylog indexed an older event late.
	if _, err := s.applyPoll(ctx, pollBatch{EndedAt: now}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	event := rawConfigEvent("late-indexed", "fw-1", "admin", "late", now.Add(-150*time.Minute))
	indexed := false
	fetcher := rangeGraylogFetcher(func(_ context.Context, _ []string, from, to time.Time) ([]RawEvent, FetchStats, error) {
		if to.Sub(from) > maxFirewallPollWindow+2*missingUserWindow {
			t.Errorf("unbounded look-back query: %s..%s", from, to)
		}
		if !indexed || event.Timestamp.Before(from) || event.Timestamp.After(to) {
			return nil, FetchStats{Pages: 1}, nil
		}
		return []RawEvent{event}, FetchStats{Pages: 1, Rows: 1}, nil
	})
	worker := recoveryWorker(t, s, activation, fetcher, 1)
	worker.overlap = 3 * time.Hour
	if _, err := worker.poll(ctx, now); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s, "events"); got != 0 {
		t.Fatalf("event was visible before indexing: %d", got)
	}
	indexed = true
	now = now.Add(time.Minute)
	if _, err := worker.poll(ctx, now); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s, "events"); got != 1 {
		t.Fatalf("late-indexed event outside recent window was lost: %d", got)
	}
	state, err := s.pollState(ctx)
	if err != nil || !state.Watermark.Equal(now) {
		t.Fatalf("replay moved history checkpoint backwards: %+v, %v", state, err)
	}
}

func TestPollWorkerTinyHistoryWindowsRetainAttributionContext(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset time.Duration
	}{
		{name: "earlier companion", offset: -4 * time.Minute},
		{name: "later companion", offset: 4 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			activation := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
			cursor := activation.Add(10 * time.Minute)
			now := activation.Add(8 * 24 * time.Hour)
			s := newTestStore(t, activation)
			if _, err := s.applyPoll(ctx, pollBatch{EndedAt: cursor}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
				t.Fatal(err)
			}
			missing := rawConfigEvent("missing", "fw-1", "", "shared", cursor.Add(500*time.Millisecond))
			companion := rawConfigEvent("companion", "fw-1", "operator", "shared", missing.Timestamp.Add(test.offset))
			fetcher := rangeGraylogFetcher(func(_ context.Context, _ []string, from, to time.Time) ([]RawEvent, FetchStats, error) {
				var selected []RawEvent
				for _, event := range []RawEvent{missing, companion} {
					if !event.Timestamp.Before(from) && !event.Timestamp.After(to) {
						selected = append(selected, event)
					}
				}
				return selected, FetchStats{Pages: 1, Rows: len(selected)}, nil
			})
			worker := recoveryWorker(t, s, activation, fetcher, 1)
			catalog, err := worker.loadCatalog(ctx)
			if err != nil {
				t.Fatal(err)
			}
			state, err := s.pollState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.firewallCheckpoints(ctx, catalog, state); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`UPDATE firewall_poll_state SET window_ns = ?`, int64(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := worker.poll(ctx, now); err != nil {
				t.Fatal(err)
			}
			if got := countRowsWhere(t, s, "events", "graylog_id = 'missing' AND user = 'operator' AND user_attribution = 'recovered'"); got != 1 {
				t.Fatal("small recovery window lost administrator attribution")
			}
			if got := countRowsWhere(t, s, "events", "graylog_id = 'companion'"); got != 0 {
				t.Fatal("context-only event committed outside checkpoint range")
			}
		})
	}
}
