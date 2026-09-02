package fgtconftail

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	managedIndexRetirementAge = 30 * 24 * time.Hour
	fullVacuumReclaimRatio    = 0.20
)

type managedIndexCandidate struct {
	name       string
	createSQL  string
	dropSQL    string
	isRequired func(dashboardFilters) bool
}

var managedIndexCandidates = []managedIndexCandidate{
	{
		name:      "ct_auto_chains_state_firewall_last",
		createSQL: `CREATE INDEX IF NOT EXISTS ct_auto_chains_state_firewall_last ON chains(state, firewall_id, last_event_at_ns DESC, id)`,
		dropSQL:   `DROP INDEX IF EXISTS ct_auto_chains_state_firewall_last`,
		isRequired: func(filters dashboardFilters) bool {
			return filters.FirewallID > 0
		},
	},
}

type databaseMaintenanceStats struct {
	PageCount     int64
	FreelistCount int64
	AutoVacuum    int
}

func (stats databaseMaintenanceStats) reclaimRatio() float64 {
	if stats.PageCount <= 0 || stats.FreelistCount <= 0 {
		return 0
	}
	return float64(stats.FreelistCount) / float64(stats.PageCount)
}

func (s *store) observeDashboardQuery(ctx context.Context, filters dashboardFilters, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("conftail dashboard index store is unavailable")
	}
	required := make([]managedIndexCandidate, 0, len(managedIndexCandidates))
	for _, candidate := range managedIndexCandidates {
		if candidate.isRequired(filters) {
			required = append(required, candidate)
		}
	}
	if len(required) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin managed index observation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, candidate := range required {
		if _, err := tx.ExecContext(ctx, candidate.createSQL); err != nil {
			return fmt.Errorf("create managed index %s: %w", candidate.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO managed_indexes(name, created_at_ns, last_needed_at_ns)
			VALUES (?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET last_needed_at_ns = excluded.last_needed_at_ns`,
			candidate.name, unixNanos(now), unixNanos(now)); err != nil {
			return fmt.Errorf("record managed index %s: %w", candidate.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit managed index observation: %w", err)
	}
	return nil
}

func (s *store) retireManagedIndexes(ctx context.Context, now time.Time) (int, error) {
	cutoff := unixNanos(now.Add(-managedIndexRetirementAge))
	retired := 0
	for _, candidate := range managedIndexCandidates {
		var lastNeeded int64
		err := s.db.QueryRowContext(ctx,
			`SELECT last_needed_at_ns FROM managed_indexes WHERE name = ?`, candidate.name,
		).Scan(&lastNeeded)
		if err == sql.ErrNoRows || lastNeeded >= cutoff {
			continue
		}
		if err != nil {
			return retired, fmt.Errorf("read managed index %s: %w", candidate.name, err)
		}
		if _, err := s.db.ExecContext(ctx, candidate.dropSQL); err != nil {
			return retired, fmt.Errorf("drop managed index %s: %w", candidate.name, err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM managed_indexes WHERE name = ?`, candidate.name); err != nil {
			return retired, fmt.Errorf("forget managed index %s: %w", candidate.name, err)
		}
		retired++
	}
	return retired, nil
}

func (s *store) maintenanceStats(ctx context.Context) (databaseMaintenanceStats, error) {
	var stats databaseMaintenanceStats
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&stats.PageCount); err != nil {
		return databaseMaintenanceStats{}, fmt.Errorf("read conftail page count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&stats.FreelistCount); err != nil {
		return databaseMaintenanceStats{}, fmt.Errorf("read conftail freelist count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&stats.AutoVacuum); err != nil {
		return databaseMaintenanceStats{}, fmt.Errorf("read conftail auto vacuum mode: %w", err)
	}
	return stats, nil
}

func (s *store) incrementalVacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(200)`); err != nil {
		return fmt.Errorf("incremental vacuum conftail database: %w", err)
	}
	return nil
}

func (s *store) fullVacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
		return fmt.Errorf("enable incremental vacuum: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("full vacuum conftail database: %w", err)
	}
	return nil
}

func shouldRunFullVacuum(now time.Time, stats databaseMaintenanceStats) bool {
	return now.Weekday() == time.Sunday && stats.reclaimRatio() >= fullVacuumReclaimRatio
}
