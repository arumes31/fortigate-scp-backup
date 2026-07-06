// Package database provides the shared PostgreSQL store. Its schema and the
// exact TEXT timestamp formats match the original Python application so an
// existing database keeps working unchanged.
package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// Timestamp layouts, kept byte-identical to the Python strftime formats.
const (
	BackupTimeLayout   = "20060102_150405"     // backups.timestamp
	ActivityTimeLayout = "2006-01-02 15:04:05" // activity_logs.timestamp
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Store wraps the connection pool and exposes typed operations.
type Store struct {
	pool   *pgxpool.Pool
	tz     *time.Location
	logger *slog.Logger
}

// NewStore opens a pooled connection to PostgreSQL.
func NewStore(ctx context.Context, dsn string, tz *time.Location, logger *slog.Logger) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 50
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool, tz: tz, logger: logger}, nil
}

// Pool exposes the underlying pool (used by extensions that share the store).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

// Now returns the current time in the configured timezone.
func (s *Store) Now() time.Time { return time.Now().In(s.tz) }

// InitSchema creates every table if missing and applies the same idempotent
// migrations the Python init_db performed. Safe to run on an empty database or
// one created by the previous Python version.
func (s *Store) InitSchema(ctx context.Context, totpEnabled bool, totpSecret string) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS firewalls (
			id SERIAL PRIMARY KEY,
			fqdn TEXT,
			username TEXT,
			password TEXT,
			interval_minutes INTEGER CHECK (interval_minutes > 0),
			retention_count INTEGER,
			last_backup TEXT,
			status TEXT,
			ssh_port INTEGER DEFAULT 9422
		)`,
		`CREATE TABLE IF NOT EXISTS backups (
			id SERIAL PRIMARY KEY,
			fw_id INTEGER REFERENCES firewalls(id),
			timestamp TEXT,
			filename TEXT,
			UNIQUE(fw_id, filename)
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE,
			password TEXT,
			first_login INTEGER DEFAULT 1,
			totp_secret TEXT,
			is_radius_user BOOLEAN DEFAULT FALSE
		)`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id SERIAL PRIMARY KEY,
			username TEXT,
			action TEXT,
			details TEXT,
			timestamp TEXT
		)`,
	}
	for _, q := range stmts {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
	}

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO users (username, password, first_login, is_radius_user)
		 VALUES ('admin', 'changeme', 1, FALSE) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}

	if totpEnabled {
		if _, err := s.pool.Exec(ctx,
			`UPDATE users SET totp_secret = $1 WHERE username = 'admin'`, totpSecret); err != nil {
			return fmt.Errorf("set admin totp: %w", err)
		}
	} else {
		if _, err := s.pool.Exec(ctx,
			`UPDATE users SET totp_secret = NULL WHERE username = 'admin'`); err != nil {
			return fmt.Errorf("clear admin totp: %w", err)
		}
	}

	// ssh_port column back-compat (older databases may lack it).
	var col string
	err := s.pool.QueryRow(ctx,
		`SELECT column_name FROM information_schema.columns
		 WHERE table_name = 'firewalls' AND column_name = 'ssh_port'`).Scan(&col)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.pool.Exec(ctx,
			`ALTER TABLE firewalls ADD COLUMN ssh_port INTEGER DEFAULT 9422`); err != nil {
			return fmt.Errorf("add ssh_port: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check ssh_port: %w", err)
	}

	if _, err := s.pool.Exec(ctx,
		`UPDATE firewalls SET interval_minutes = 180
		 WHERE interval_minutes IS NULL OR interval_minutes <= 0`); err != nil {
		return fmt.Errorf("normalize interval: %w", err)
	}

	if _, err := s.pool.Exec(ctx,
		`DELETE FROM backups WHERE id NOT IN (
			SELECT MIN(id) FROM backups GROUP BY fw_id, filename)`); err != nil {
		return fmt.Errorf("dedupe backups: %w", err)
	}
	return nil
}

// LogActivity records a user action. Fire-and-forget: failures are logged, not
// returned, matching the original best-effort behavior.
func (s *Store) LogActivity(username, action, details string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ts := s.Now().Format(ActivityTimeLayout)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO activity_logs (username, action, details, timestamp) VALUES ($1, $2, $3, $4)`,
		username, action, details, ts); err != nil {
		s.logger.Error("failed to log activity", "user", username, "action", action, "err", err)
	}
}

// GetUserForLogin returns the user row or (nil, nil) if the username is unknown.
func (s *Store) GetUserForLogin(ctx context.Context, username string) (*models.User, error) {
	var (
		u          models.User
		totpSecret *string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT password, first_login, totp_secret, is_radius_user FROM users WHERE username = $1`, username).
		Scan(&u.Password, &u.FirstLogin, &totpSecret, &u.IsRadiusUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Username = username
	if totpSecret != nil {
		u.TOTPSecret = *totpSecret
	}
	return &u, nil
}

// UpsertRadiusUser creates or flags a RADIUS-authenticated user, mirroring the
// Python login flow (first_login forced to 0, is_radius_user true).
func (s *Store) UpsertRadiusUser(ctx context.Context, username string) error {
	var id int
	err := s.pool.QueryRow(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = s.pool.Exec(ctx,
			`INSERT INTO users (username, password, first_login, is_radius_user) VALUES ($1, '', 0, TRUE)`,
			username)
		return err
	}
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE users SET is_radius_user = TRUE, first_login = 0 WHERE username = $1`, username)
	return err
}

// GetFirstLogin returns the stored first_login flag for a user.
func (s *Store) GetFirstLogin(ctx context.Context, username string) (firstLogin int, found bool, err error) {
	err = s.pool.QueryRow(ctx, `SELECT first_login FROM users WHERE username = $1`, username).Scan(&firstLogin)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return firstLogin, true, nil
}

// ChangePassword verifies the current password and sets a new one, clearing the
// first_login flag. Returns false when the current password does not match.
func (s *Store) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET password = $1, first_login = 0 WHERE username = $2 AND password = $3`,
		newPassword, username, oldPassword)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ListFirewalls returns all firewalls ordered by id.
func (s *Store) ListFirewalls(ctx context.Context) ([]models.Firewall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port
		 FROM firewalls ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFirewalls(rows)
}

// GetFirewall returns a single firewall or ErrNotFound.
func (s *Store) GetFirewall(ctx context.Context, id int) (*models.Firewall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port
		 FROM firewalls WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fws, err := scanFirewalls(rows)
	if err != nil {
		return nil, err
	}
	if len(fws) == 0 {
		return nil, ErrNotFound
	}
	return &fws[0], nil
}

// AddFirewall inserts a firewall and returns its new id.
func (s *Store) AddFirewall(ctx context.Context, fw models.Firewall) (int, error) {
	var id int
	err := s.pool.QueryRow(ctx,
		`INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port)
		 VALUES ($1, $2, $3, $4, $5, NULL, $6, $7) RETURNING id`,
		fw.FQDN, fw.Username, fw.Password, fw.IntervalMin, fw.RetentionCount, fw.Status, fw.SSHPort).Scan(&id)
	return id, err
}

// DeleteFirewall removes a firewall and its backup rows, returning its FQDN.
func (s *Store) DeleteFirewall(ctx context.Context, id int) (string, error) {
	var fqdn string
	err := s.pool.QueryRow(ctx, `SELECT fqdn FROM firewalls WHERE id = $1`, id).Scan(&fqdn)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM backups WHERE fw_id = $1`, id); err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM firewalls WHERE id = $1`, id); err != nil {
		return "", err
	}
	return fqdn, nil
}

// ListBackups returns the distinct backups for a firewall, newest first.
func (s *Store) ListBackups(ctx context.Context, fwID int) ([]models.Backup, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT id, fw_id, timestamp, filename FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC`, fwID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBackups(rows)
}

// ListErrors returns firewalls whose status marks a failed backup.
func (s *Store) ListErrors(ctx context.Context) ([]models.Firewall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, fqdn, last_backup, status FROM firewalls WHERE status LIKE 'Failed:%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Firewall
	for rows.Next() {
		var fw models.Firewall
		var lastBackup *string
		if err := rows.Scan(&fw.ID, &fw.FQDN, &lastBackup, &fw.Status); err != nil {
			return nil, err
		}
		if lastBackup != nil {
			fw.LastBackup = *lastBackup
		}
		out = append(out, fw)
	}
	return out, rows.Err()
}

// ListActivityLogs returns all activity, newest first.
func (s *Store) ListActivityLogs(ctx context.Context) ([]models.ActivityLog, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ActivityLog
	for rows.Next() {
		var l models.ActivityLog
		if err := rows.Scan(&l.Username, &l.Action, &l.Details, &l.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListFirewallRefs returns id/fqdn pairs for config search.
func (s *Store) ListFirewallRefs(ctx context.Context) ([]models.FirewallRef, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, fqdn FROM firewalls`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.FirewallRef
	for rows.Next() {
		var r models.FirewallRef
		if err := rows.Scan(&r.ID, &r.FQDN); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListSchedules returns id/interval pairs used to (re)build backup jobs.
func (s *Store) ListSchedules(ctx context.Context) ([]models.FirewallSchedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, interval_minutes FROM firewalls`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.FirewallSchedule
	for rows.Next() {
		var sc models.FirewallSchedule
		var interval *int
		if err := rows.Scan(&sc.ID, &interval); err != nil {
			return nil, err
		}
		if interval != nil {
			sc.IntervalMin = *interval
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ---- backup engine helpers ----

// LastBackupTimestamp returns the newest backup timestamp for a firewall.
func (s *Store) LastBackupTimestamp(ctx context.Context, fwID int) (string, bool, error) {
	var ts string
	err := s.pool.QueryRow(ctx,
		`SELECT timestamp FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC LIMIT 1`, fwID).Scan(&ts)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return ts, true, nil
}

// InsertBackup records a new backup file (idempotent on the unique constraint).
func (s *Store) InsertBackup(ctx context.Context, fwID int, timestamp, filename string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO backups (fw_id, timestamp, filename) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		fwID, timestamp, filename)
	return err
}

// ListBackupFilenames returns all backup filenames for a firewall, newest first.
func (s *Store) ListBackupFilenames(ctx context.Context, fwID int) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT filename FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC`, fwID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// DeleteBackupByFilename removes a backup row by filename.
func (s *Store) DeleteBackupByFilename(ctx context.Context, filename string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM backups WHERE filename = $1`, filename)
	return err
}

// ListBackupIDFilenames returns up to limit id/filename pairs for cleanup.
func (s *Store) ListBackupIDFilenames(ctx context.Context, fwID, limit int) ([]models.Backup, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, filename FROM backups WHERE fw_id = $1 LIMIT $2`, fwID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Backup
	for rows.Next() {
		var b models.Backup
		if err := rows.Scan(&b.ID, &b.Filename); err != nil {
			return nil, err
		}
		b.FwID = fwID
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBackupByID removes a backup row by id.
func (s *Store) DeleteBackupByID(ctx context.Context, id int) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM backups WHERE id = $1`, id)
	return err
}

// UpdateFirewallSuccess records a successful backup time and status.
func (s *Store) UpdateFirewallSuccess(ctx context.Context, id int, lastBackup, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE firewalls SET last_backup = $1, status = $2 WHERE id = $3`, lastBackup, status, id)
	return err
}

// UpdateFirewallStatus records only a status change (used for failures).
func (s *Store) UpdateFirewallStatus(ctx context.Context, id int, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE firewalls SET status = $1 WHERE id = $2`, status, id)
	return err
}

func scanFirewalls(rows pgx.Rows) ([]models.Firewall, error) {
	var out []models.Firewall
	for rows.Next() {
		var (
			fw         models.Firewall
			lastBackup *string
			status     *string
			sshPort    *int
			interval   *int
			retention  *int
		)
		if err := rows.Scan(&fw.ID, &fw.FQDN, &fw.Username, &fw.Password,
			&interval, &retention, &lastBackup, &status, &sshPort); err != nil {
			return nil, err
		}
		if interval != nil {
			fw.IntervalMin = *interval
		}
		if retention != nil {
			fw.RetentionCount = *retention
		}
		if lastBackup != nil {
			fw.LastBackup = *lastBackup
		}
		if status != nil {
			fw.Status = *status
		}
		if sshPort != nil {
			fw.SSHPort = *sshPort
		}
		out = append(out, fw)
	}
	return out, rows.Err()
}

func scanBackups(rows pgx.Rows) ([]models.Backup, error) {
	var out []models.Backup
	for rows.Next() {
		var b models.Backup
		if err := rows.Scan(&b.ID, &b.FwID, &b.Timestamp, &b.Filename); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
