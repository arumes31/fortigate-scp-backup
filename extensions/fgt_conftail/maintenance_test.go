package fgtconftail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestQueuedIndexMaintenanceWaitsAndRetainsNewObservations(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	filters := dashboardFilters{FirewallID: 7}
	s.queueDashboardIndexUse(filters, now)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.flushDashboardIndexUse(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled flush = %v", err)
	}

	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `UPDATE poll_state SET last_pages = 1`); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	e := &Extension{store: s, ctx: ctx}
	waitCount := s.db.Stats().WaitCount
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runIndexMaintenance()
	}()
	t.Cleanup(func() { stop(); <-done })
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for s.db.Stats().WaitCount == waitCount {
		select {
		case <-done:
			t.Fatal("maintenance returned instead of waiting for the writer")
		case <-ctx.Done():
			t.Fatal("maintenance never queued for the writer")
		case <-ticker.C:
		}
	}
	// A page read and a newer index observation must not wait for maintenance.
	readCtx, cancelRead := context.WithTimeout(t.Context(), time.Second)
	defer cancelRead()
	if got := e.storeHealth(readCtx); got != "healthy" {
		t.Fatalf("store health during maintenance = %s", got)
	}
	later := now.Add(time.Minute)
	s.queueDashboardIndexUse(filters, later)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("maintenance did not finish after writer committed")
	}
	var lastNeeded int64
	if err := s.readDB.QueryRow(`SELECT last_needed_at_ns FROM managed_indexes`).Scan(&lastNeeded); err != nil || lastNeeded != unixNanos(now) {
		t.Fatalf("queued maintenance did not complete: timestamp=%d err=%v", lastNeeded, err)
	}
	e.runIndexMaintenance()
	if err := s.readDB.QueryRow(`SELECT last_needed_at_ns FROM managed_indexes`).Scan(&lastNeeded); err != nil || lastNeeded != unixNanos(later) {
		t.Fatalf("newer observation lost during flush: timestamp=%d err=%v", lastNeeded, err)
	}
}

func TestObserveDashboardQueryCreatesOnlyAllowlistedIndexes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	if _, err := s.db.Exec(`CREATE INDEX ct_auto_foreign_keep ON chains(user)`); err != nil {
		t.Fatal(err)
	}
	filters := dashboardFilters{FirewallID: 7, State: dashboardStateAll, Page: 1}
	s.queueDashboardIndexUse(filters, now)
	if err := s.flushDashboardIndexUse(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"ct_auto_chains_state_firewall_last", "ct_auto_foreign_keep"} {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("index %s count = %d, want 1", name, count)
		}
	}
	var managedCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM managed_indexes`).Scan(&managedCount); err != nil {
		t.Fatal(err)
	}
	if managedCount != 1 {
		t.Fatalf("managed index rows = %d, want 1", managedCount)
	}
}

func TestRetireManagedIndexesRemovesOnlyOwnedIndexesAfterThirtyDays(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	s.queueDashboardIndexUse(dashboardFilters{FirewallID: 7}, now)
	if err := s.flushDashboardIndexUse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE INDEX ct_auto_foreign_keep ON chains(user)`); err != nil {
		t.Fatal(err)
	}
	retired, err := s.retireManagedIndexes(context.Background(), now.Add(31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if retired != 1 {
		t.Fatalf("retired = %d, want 1", retired)
	}
	for name, want := range map[string]int{
		"ct_auto_chains_state_firewall_last": 0,
		"ct_auto_foreign_keep":               1,
		"chains_state_last_event":            1,
	} {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Errorf("index %s count = %d, want %d", name, count, want)
		}
	}
}

func TestManagedFirewallIndexChangesQueryPlan(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	queryPlan := func() string {
		t.Helper()
		rows, err := s.db.Query(`EXPLAIN QUERY PLAN SELECT id FROM chains
			WHERE state = ? AND firewall_id = ? ORDER BY last_event_at_ns DESC, id`, chainStateSealed, 7)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var plan strings.Builder
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(detail)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return plan.String()
	}
	before := queryPlan()
	if strings.Contains(before, "ct_auto_") {
		t.Fatalf("baseline query plan unexpectedly uses managed index: %q", before)
	}
	s.queueDashboardIndexUse(dashboardFilters{FirewallID: 7}, now)
	if err := s.flushDashboardIndexUse(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := queryPlan()
	if !strings.Contains(after, "ct_auto_chains_state_firewall_last") {
		t.Fatalf("query plan before = %q, after = %q; want managed index after observation", before, after)
	}
}

func TestDashboardLastIngestedUsesCoveringIndex(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC))
	var id, parent, unused int
	var plan string
	if err := s.db.QueryRow(`EXPLAIN QUERY PLAN SELECT MAX(ingested_at_ns) FROM events`).Scan(&id, &parent, &unused, &plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "COVERING INDEX events_ingested_at") {
		t.Fatalf("dashboard poll state scans event history: %s", plan)
	}
}

func TestShouldRunFullVacuumOnlyOnSundayAtTwentyPercent(t *testing.T) {
	t.Parallel()
	sunday := time.Date(2026, 9, 6, 3, 30, 0, 0, time.UTC)
	if !shouldRunFullVacuum(sunday, databaseMaintenanceStats{PageCount: 100, FreelistCount: 20}) {
		t.Fatal("Sunday with 20% reclaimable pages should run full vacuum")
	}
	if shouldRunFullVacuum(sunday, databaseMaintenanceStats{PageCount: 100, FreelistCount: 19}) {
		t.Fatal("Sunday below 20% should not run full vacuum")
	}
	if shouldRunFullVacuum(sunday.Add(24*time.Hour), databaseMaintenanceStats{PageCount: 100, FreelistCount: 50}) {
		t.Fatal("non-Sunday should not run full vacuum")
	}
}

func TestIncrementalVacuumUsesIncrementalAutoVacuumMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	stats, err := s.maintenanceStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.AutoVacuum != 2 {
		t.Fatalf("auto_vacuum = %d, want incremental mode 2", stats.AutoVacuum)
	}
	if err := s.incrementalVacuum(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceCompletesWithOpenReaderSnapshot(t *testing.T) {
	s := newTestStore(t, time.Now().UTC())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := s.readDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snapshot.Rollback() }()
	var pages int
	if err := snapshot.QueryRowContext(ctx, `SELECT last_pages FROM poll_state`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE poll_state SET last_pages = 42`); err != nil {
		t.Fatal(err)
	}
	s.queueDashboardIndexUse(dashboardFilters{FirewallID: 7}, time.Now().UTC())
	if err := s.flushDashboardIndexUse(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.fullVacuum(ctx); err != nil {
		t.Fatalf("maintenance blocked by reader: %v", err)
	}
	if err := snapshot.QueryRowContext(ctx, `SELECT last_pages FROM poll_state`).Scan(&pages); err != nil || pages != 0 {
		t.Fatalf("reader snapshot changed during maintenance: pages=%d err=%v", pages, err)
	}
	state, err := s.pollState(ctx)
	if err != nil || state.LastPages != 42 {
		t.Fatalf("new reader after maintenance: pages=%d err=%v", state.LastPages, err)
	}
}

func TestMaintenanceSkipsWhileConfTailOperationIsActive(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	var output bytes.Buffer
	e := &Extension{
		ctx:    context.Background(),
		store:  s,
		logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})),
		tz:     time.UTC,
	}
	e.operationMu.RLock()
	e.runMaintenance()
	e.operationMu.RUnlock()
	if !strings.Contains(output.String(), `"code":"CT-MAINT-002"`) {
		t.Fatalf("maintenance skip log = %s", output.String())
	}
}

func TestMaintenanceCronIsRegisteredWhenAvailable(t *testing.T) {
	var cronID, cronSpec string
	var cronJob func()
	deps := validConftailDeps(t)
	deps.ScheduleCron = func(id, spec string, fn func()) error {
		cronID, cronSpec, cronJob = id, spec, fn
		return nil
	}
	deps.Schedule = func(string, time.Duration, time.Duration, func()) {}
	e := New(validConftailConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		if e.store != nil {
			_ = e.store.close()
		}
	})
	if err := e.Mount(chi.NewRouter(), deps); err != nil {
		t.Fatal(err)
	}
	if cronID != conftailMaintenanceJobID || cronSpec != conftailMaintenanceCron || cronJob == nil {
		t.Fatalf("cron = %q/%q/%v", cronID, cronSpec, cronJob != nil)
	}
}
