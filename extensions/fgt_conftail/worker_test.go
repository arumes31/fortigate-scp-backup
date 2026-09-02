package fgtconftail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

type graylogFetchCall struct {
	query   string
	sources []string
	from    time.Time
	to      time.Time
}

type scriptedGraylogFetcher struct {
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

func TestPollWorkerDoesNotAdvanceOnPartialGraylogFailure(t *testing.T) {
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
	fetcher := &scriptedGraylogFetcher{fn: func(call int, sources []string) ([]RawEvent, FetchStats, error) {
		if call == 1 {
			return nil, FetchStats{Pages: 1}, errors.New("graylog page failed")
		}
		return []RawEvent{
			rawConfigEvent("first-page", sources[0], "admin-a", "tx-1", activation.Add(time.Minute)),
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
	if got := countRows(t, s, "events"); got != 0 {
		t.Fatalf("events persisted from partial result = %d, want 0", got)
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
