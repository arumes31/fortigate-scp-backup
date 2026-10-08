package fgtconftail

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Keep history large enough to expose work repeated for every session before LIMIT.
func BenchmarkDashboardHistory(b *testing.B) {
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s, err := openStore(ctx, filepath.Join(b.TempDir(), "history.sqlite"), base)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.close() })
	_, err = s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<17000)
		INSERT INTO chains(id,firewall_id,firewall_name,user,first_event_at_ns,last_event_at_ns,event_count,state,created_at_ns)
		SELECT 'chain-'||i, (i%150)+1, 'fixture-fw', 'operator', ?+i*1000000000, ?+i*1000000000+4000000, 5, 'sealed', ? FROM n`, unixNanos(base), unixNanos(base), unixNanos(base))
	if err != nil {
		b.Fatal(err)
	}
	_, err = s.db.Exec(`WITH n(i) AS (VALUES(0),(1),(2),(3),(4))
		INSERT INTO events(semantic_hash,correlation_hash,chain_id,firewall_id,firewall_name,source,user,user_attribution,user_was_missing,log_id,event_at_ns,ingested_at_ns,config_attribute)
		SELECT c.id||'-'||n.i,c.id||'-'||n.i,c.id,c.firewall_id,c.firewall_name,'fixture-source',c.user,'exact',0,'0100044547',c.first_event_at_ns+n.i*1000000,c.first_event_at_ns,'keep' FROM chains c CROSS JOIN n`)
	if err != nil {
		b.Fatal(err)
	}
	_, err = s.db.Exec(`WITH n(i) AS (VALUES(1),(2),(3),(4),(5),(6),(7))
		INSERT INTO global_ignore_rules(kind,config_attribute,created_by,created_at_ns) SELECT 'attribute','noise-'||i,'operator',? FROM n`, unixNanos(base))
	if err != nil {
		b.Fatal(err)
	}
	b.Run("poll-state", func(b *testing.B) {
		for b.Loop() {
			if _, err := s.pollState(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
	for _, filter := range []struct {
		name     string
		firewall int
	}{{"all", 0}, {"firewall", 7}} {
		b.Run(filter.name, func(b *testing.B) {
			for b.Loop() {
				data, err := s.queryDashboard(ctx, dashboardFilters{State: dashboardStateAll, Page: 1, FirewallID: filter.firewall})
				if err != nil || len(data.History) != dashboardPageSize {
					b.Fatalf("dashboard: count=%d err=%v", len(data.History), err)
				}
			}
		})
	}
}
