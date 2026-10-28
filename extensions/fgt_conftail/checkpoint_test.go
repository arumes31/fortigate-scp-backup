package fgtconftail

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFirewallCheckpointMigrationAndRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "conftail.db")
	s, err := openStore(ctx, path, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	watermark := base.Add(time.Hour)
	if _, err := s.applyPoll(ctx, pollBatch{EndedAt: watermark,
		Events: []Event{testEvent(1, "fw-1", "admin", "preserved", base)}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	payload := string(onlyPayload(t, s))
	if _, err := s.db.Exec(`DROP TABLE firewall_poll_state; UPDATE schema_meta SET version = 7`); err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStore(ctx, path, base.Add(8*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	worker := recoveryWorker(t, s, base, nil, 1, 2)
	catalog, err := worker.loadCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.pollState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints, err := s.firewallCheckpoints(ctx, catalog, state)
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range checkpoints {
		if !cp.Watermark.Equal(watermark) {
			t.Fatalf("migration reset checkpoint: %+v", cp)
		}
	}
	next := watermark.Add(time.Hour)
	if _, err := s.applyPoll(ctx, pollBatch{FirewallID: 1, EndedAt: next}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStore(ctx, path, base.Add(9*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	checkpoints, err = s.firewallCheckpoints(ctx, catalog, state)
	if err != nil {
		t.Fatal(err)
	}
	if !checkpoints[0].Watermark.Equal(next) || !checkpoints[1].Watermark.Equal(watermark) {
		t.Fatalf("restart lost independent progress: %+v", checkpoints)
	}
	if string(onlyPayload(t, s)) != payload {
		t.Fatal("migration or checkpoint advance rewrote queued ticket")
	}
}

func TestFirewallPollDoesNotSealNeighborOrClearCompany(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	if _, err := s.applyPoll(ctx, pollBatch{EndedAt: base.Add(time.Minute),
		Companies: map[int]string{1: "First", 2: "Second"},
		Events:    []Event{testEvent(1, "fw-1", "admin", "first", base), testEvent(2, "fw-2", "admin", "second", base)}},
		30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	worker := recoveryWorker(t, s, base, nil, 1, 2)
	catalog, _ := worker.loadCatalog(ctx)
	state, _ := s.pollState(ctx)
	if _, err := s.firewallCheckpoints(ctx, catalog, state); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyPoll(ctx, pollBatch{FirewallID: 1, EndedAt: base.Add(time.Hour),
		Companies: map[int]string{1: "Updated"}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if got := countRowsWhere(t, s, "chains", "firewall_id = 1 AND state = 'sealed'"); got != 1 {
		t.Fatal("healthy firewall did not seal")
	}
	if got := countRowsWhere(t, s, "chains", "firewall_id = 2 AND state = 'active'"); got != 1 {
		t.Fatal("uncollected neighbor was sealed")
	}
	var company string
	if err := s.readDB.QueryRow(`SELECT company FROM firewall_companies WHERE firewall_id = 2`).Scan(&company); err != nil || company != "Second" {
		t.Fatalf("neighbor company lost: %q, %v", company, err)
	}
}

func TestFirewallCheckpointsPrioritizeUnattemptedFirewalls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	worker := recoveryWorker(t, s, base, nil, 1, 2, 3)
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
	if _, err := s.db.Exec(`UPDATE firewall_poll_state SET last_attempt_ns = ? WHERE firewall_id IN (1,2)`, unixNanos(base.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := s.firewallCheckpoints(ctx, catalog, state)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoints[0].ID != 3 {
		t.Fatalf("unattempted firewall would starve after cycle deadline: %+v", checkpoints)
	}
}
