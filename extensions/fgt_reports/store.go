package fgt_reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// A firewall has exactly one desired source and one published report set.
// Replacing all three encrypted PDFs and their assessment is one transaction.
// There is deliberately no report history, version directory, or artifact cache.
const reportSchema = `
CREATE TABLE IF NOT EXISTS report_targets (
 firewall_id INTEGER PRIMARY KEY,
 backup_id INTEGER NOT NULL,
 backup_ns INTEGER NOT NULL,
 checksum TEXT NOT NULL,
 generation TEXT NOT NULL,
 status TEXT NOT NULL,
 error TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0,
 retry_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS report_latest (
 firewall_id INTEGER PRIMARY KEY REFERENCES report_targets(firewall_id) ON DELETE CASCADE,
 backup_id INTEGER NOT NULL,
 backup_ns INTEGER NOT NULL,
 generated_ns INTEGER NOT NULL,
 generation TEXT NOT NULL,
 checksum TEXT NOT NULL,
 limited INTEGER NOT NULL,
 assessment BLOB NOT NULL,
 forwarding BLOB NOT NULL,
 technical BLOB NOT NULL,
 customer BLOB NOT NULL
);`

type target struct {
	FirewallID int
	BackupID   int
	BackupNS   int64
	Checksum   string
	Generation string
	Status     string
	Error      string
	Attempts   int
	RetryNS    int64
}

type encryptedSet struct {
	Limited    bool
	Assessment []byte
	Forwarding []byte
	Technical  []byte
	Customer   []byte
}

func initDB(ctx context.Context, db *sql.DB) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000",
		"PRAGMA journal_mode=DELETE", "PRAGMA secure_delete=ON",
		"PRAGMA auto_vacuum=INCREMENTAL", reportSchema,
		"UPDATE report_targets SET status='queued' WHERE status='running'",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize report store: %w", err)
		}
	}
	return nil
}

const enqueueSQL = `INSERT INTO report_targets
 (firewall_id,backup_id,backup_ns,checksum,generation,status)
 VALUES (?,?,?,?,?,'queued') ON CONFLICT(firewall_id) DO UPDATE SET
 backup_id=excluded.backup_id,backup_ns=excluded.backup_ns,checksum=excluded.checksum,
 generation=excluded.generation,status='queued',error='',attempts=0,retry_ns=0
 WHERE excluded.backup_ns>report_targets.backup_ns
 OR (excluded.backup_ns=report_targets.backup_ns AND excluded.backup_id>report_targets.backup_id)
 OR (excluded.backup_ns=report_targets.backup_ns AND excluded.backup_id=report_targets.backup_id
     AND (excluded.generation<>report_targets.generation OR excluded.checksum<>report_targets.checksum))`

// reconcile persists new sources and removes reports for deleted firewalls or
// firewalls with no remaining backup. A failed catalog lookup must never call it.
func reconcile(ctx context.Context, db *sql.DB, sources []reportmodel.Source, generation string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	seen := make(map[int]bool, len(sources))
	for _, source := range sources {
		if source.FirewallID <= 0 || source.BackupID <= 0 || source.BackupAt.IsZero() {
			return errors.New("invalid report source catalog")
		}
		seen[source.FirewallID] = true
		if _, err := tx.ExecContext(ctx, enqueueSQL, source.FirewallID, source.BackupID,
			source.BackupAt.UnixNano(), source.Checksum, generation); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT firewall_id FROM report_targets")
	if err != nil {
		return err
	}
	var removed []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		if !seen[id] {
			removed = append(removed, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range removed {
		if _, err := tx.ExecContext(ctx, "DELETE FROM report_targets WHERE firewall_id=?", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nextTarget(ctx context.Context, db *sql.DB, now time.Time) (target, error) {
	var t target
	err := db.QueryRowContext(ctx, `SELECT firewall_id,backup_id,backup_ns,checksum,generation,status,error,attempts,retry_ns
 FROM report_targets WHERE status='queued' OR (status='failed' AND attempts<3 AND retry_ns<=?)
 ORDER BY backup_ns,firewall_id LIMIT 1`, now.UnixNano()).Scan(&t.FirewallID, &t.BackupID,
		&t.BackupNS, &t.Checksum, &t.Generation, &t.Status, &t.Error, &t.Attempts, &t.RetryNS)
	if err != nil {
		return t, err
	}
	result, err := db.ExecContext(ctx, `UPDATE report_targets SET status='running',error='',attempts=attempts+1
 WHERE firewall_id=? AND backup_id=? AND backup_ns=? AND generation=? AND checksum=? AND status=?`,
		t.FirewallID, t.BackupID, t.BackupNS, t.Generation, t.Checksum, t.Status)
	if err != nil {
		return t, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return t, err
	}
	if n != 1 {
		return t, sql.ErrNoRows
	}
	t.Status = "running"
	t.Attempts++
	return t, nil
}

func failTarget(ctx context.Context, db *sql.DB, t target, message string, now time.Time) error {
	// Bounded retries also cover temporarily pruned/unavailable source files.
	delay := time.Duration(t.Attempts) * time.Minute
	_, err := db.ExecContext(ctx, `UPDATE report_targets SET status='failed',error=?,retry_ns=?
 WHERE firewall_id=? AND backup_id=? AND backup_ns=? AND generation=? AND checksum=? AND status='running'`,
		message, now.Add(delay).UnixNano(), t.FirewallID, t.BackupID, t.BackupNS, t.Generation, t.Checksum)
	return err
}

func publish(ctx context.Context, db *sql.DB, t target, generated time.Time, set encryptedSet) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var matches int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_targets
 WHERE firewall_id=? AND backup_id=? AND backup_ns=? AND generation=? AND checksum=? AND status='running'`,
		t.FirewallID, t.BackupID, t.BackupNS, t.Generation, t.Checksum).Scan(&matches)
	if err != nil || matches != 1 {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO report_latest
 (firewall_id,backup_id,backup_ns,generated_ns,generation,checksum,limited,assessment,forwarding,technical,customer)
 VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(firewall_id) DO UPDATE SET
 backup_id=excluded.backup_id,backup_ns=excluded.backup_ns,generated_ns=excluded.generated_ns,
 generation=excluded.generation,checksum=excluded.checksum,limited=excluded.limited,assessment=excluded.assessment,forwarding=excluded.forwarding,
 technical=excluded.technical,customer=excluded.customer`, t.FirewallID, t.BackupID, t.BackupNS,
		generated.UnixNano(), t.Generation, t.Checksum, set.Limited, set.Assessment, set.Forwarding, set.Technical, set.Customer)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE report_targets SET status='ready',error='',retry_ns=0 WHERE firewall_id=?", t.FirewallID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func forceRetry(ctx context.Context, db *sql.DB, firewallID int) error {
	_, err := db.ExecContext(ctx, `UPDATE report_targets SET status='queued',error='',attempts=0,retry_ns=0
 WHERE firewall_id=? AND status<>'running'`, firewallID)
	return err
}
