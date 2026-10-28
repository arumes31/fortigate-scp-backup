package fgtconftail

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"
)

const firewallPollSchema = `CREATE TABLE IF NOT EXISTS firewall_poll_state (
	firewall_id INTEGER PRIMARY KEY,
	watermark_ns INTEGER NOT NULL,
	recent_from_ns INTEGER NOT NULL DEFAULT 0,
	recent_to_ns INTEGER NOT NULL DEFAULT 0,
	replay_to_ns INTEGER NOT NULL DEFAULT 0,
	window_ns INTEGER NOT NULL,
	recent_window_ns INTEGER NOT NULL DEFAULT 3600000000000,
	last_attempt_ns INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	active INTEGER NOT NULL DEFAULT 1
)`

type firewallCheckpoint struct {
	ID           int
	Watermark    time.Time
	RecentFrom   time.Time
	RecentTo     time.Time
	ReplayTo     time.Time
	Window       time.Duration
	RecentWindow time.Duration
	LastAttempt  time.Time
}

// Seed existing installations from their last committed global watermark.
// Catalog changes never reset a previously saved firewall checkpoint.
func (s *store) firewallCheckpoints(ctx context.Context, catalog sourceCatalog, state PollState) ([]firewallCheckpoint, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE firewall_poll_state SET active = 0`); err != nil {
		return nil, err
	}
	for id, fw := range catalog.byID {
		if len(fw.Aliases) == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO firewall_poll_state(firewall_id, watermark_ns, window_ns)
			VALUES (?, ?, ?) ON CONFLICT(firewall_id) DO UPDATE SET active = 1`,
			id, unixNanos(state.Watermark), int64(maxFirewallPollWindow)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	rows, err := s.readDB.QueryContext(ctx, `SELECT firewall_id, watermark_ns, recent_from_ns, recent_to_ns, replay_to_ns,
		window_ns, recent_window_ns, last_attempt_ns FROM firewall_poll_state WHERE active = 1`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var checkpoints []firewallCheckpoint
	for rows.Next() {
		var cp firewallCheckpoint
		var watermark, from, to, replay, attempted int64
		if err := rows.Scan(&cp.ID, &watermark, &from, &to, &replay, &cp.Window, &cp.RecentWindow, &attempted); err != nil {
			return nil, err
		}
		cp.Watermark, cp.RecentFrom, cp.RecentTo = timeFromNanos(watermark), timeFromNanos(from), timeFromNanos(to)
		cp.LastAttempt = timeFromNanos(attempted)
		cp.ReplayTo = timeFromNanos(replay)
		checkpoints = append(checkpoints, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// A cycle deadline must not repeatedly starve firewalls at the end of the list.
	sort.Slice(checkpoints, func(i, j int) bool {
		if checkpoints[i].LastAttempt.Equal(checkpoints[j].LastAttempt) {
			return checkpoints[i].ID < checkpoints[j].ID
		}
		return checkpoints[i].LastAttempt.Before(checkpoints[j].LastAttempt)
	})
	return checkpoints, nil
}

func advanceFirewallPoll(ctx context.Context, tx *sql.Tx, batch pollBatch) error {
	if batch.Replay {
		cursor := unixNanos(batch.EndedAt)
		if batch.ReplayComplete {
			cursor = 0
		}
		_, err := tx.ExecContext(ctx, `UPDATE firewall_poll_state SET replay_to_ns = ? WHERE firewall_id = ?`, cursor, batch.FirewallID)
		return err
	}
	if batch.Recent {
		_, err := tx.ExecContext(ctx, `UPDATE firewall_poll_state SET
			recent_from_ns = CASE WHEN recent_to_ns >= ? AND recent_from_ns > 0
				THEN MIN(recent_from_ns, ?) ELSE ? END,
			recent_to_ns = MAX(recent_to_ns, ?)
			WHERE firewall_id = ?`, unixNanos(batch.RangeFrom), unixNanos(batch.RangeFrom),
			unixNanos(batch.RangeFrom), unixNanos(batch.EndedAt), batch.FirewallID)
		if err != nil {
			return fmt.Errorf("save conftail recent coverage: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE firewall_poll_state SET watermark_ns = MAX(watermark_ns, ?)
			WHERE firewall_id = ?`, unixNanos(batch.EndedAt), batch.FirewallID); err != nil {
			return fmt.Errorf("advance conftail firewall history: %w", err)
		}
	}
	// Only join ranges when they actually touch; never jump over uncollected history.
	_, err := tx.ExecContext(ctx, `UPDATE firewall_poll_state SET watermark_ns = MAX(watermark_ns, recent_to_ns)
		WHERE firewall_id = ? AND recent_from_ns > 0 AND watermark_ns >= recent_from_ns`, batch.FirewallID)
	return err
}

func (s *store) finishPoll(ctx context.Context, started, completed time.Time, stats pollCycleStats, pollErr error) error {
	message := ""
	if pollErr != nil {
		message = sanitizeDeliveryError(pollErr)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE poll_state SET
		watermark_ns = COALESCE((SELECT MIN(watermark_ns) FROM firewall_poll_state WHERE active = 1), watermark_ns),
		last_success_at_ns = CASE WHEN ? = '' THEN ? ELSE last_success_at_ns END,
		last_failure_at_ns = CASE WHEN ? != '' THEN ? ELSE last_failure_at_ns END,
		last_duration_ns = ?, last_pages = ?, last_fetched = ?, last_inserted = ?, last_error = ?, updated_at_ns = ?
		WHERE id = 1`, message, unixNanos(completed), message, unixNanos(completed),
		max(int64(0), int64(completed.Sub(started))), stats.Pages, stats.Fetched, stats.Inserted, message, unixNanos(completed))
	return err
}
