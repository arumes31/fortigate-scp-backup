package fgtconftail

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestObserveDashboardQueryCreatesOnlyAllowlistedIndexes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, now)
	if _, err := s.db.Exec(`CREATE INDEX ct_auto_foreign_keep ON chains(user)`); err != nil {
		t.Fatal(err)
	}
	filters := dashboardFilters{FirewallID: 7, State: dashboardStateAll, Page: 1}
	if err := s.observeDashboardQuery(context.Background(), filters, now); err != nil {
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
	if err := s.observeDashboardQuery(context.Background(), dashboardFilters{FirewallID: 7}, now); err != nil {
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
	if err := s.observeDashboardQuery(context.Background(), dashboardFilters{FirewallID: 7}, now); err != nil {
		t.Fatal(err)
	}
	after := queryPlan()
	if !strings.Contains(after, "ct_auto_chains_state_firewall_last") {
		t.Fatalf("query plan before = %q, after = %q; want managed index after observation", before, after)
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
