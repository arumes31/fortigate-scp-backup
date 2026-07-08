// Package database provides the shared PostgreSQL store. Its schema and the
// exact TEXT timestamp formats match the original Python application so an
// existing database keeps working unchanged.
package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/security"
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
	cipher *crypto.Cipher
	logger *slog.Logger
}

// NewStore opens a pooled connection to PostgreSQL. The connection parameters
// are set field-by-field (not concatenated into a DSN), so passwords containing
// URL-special characters are handled correctly. It retries the initial
// connection with a fixed backoff so a briefly-unavailable database at startup
// does not crash the process.
func NewStore(ctx context.Context, cfg *config.Config, cipher *crypto.Cipher, logger *slog.Logger) (*Store, error) {
	// Build a libpq keyword/value DSN with each value quoted and escaped, so a
	// password containing spaces or special characters is handled correctly and
	// pgx computes the right connection fallbacks (which enable sslmode=prefer).
	dsn := keywordDSN(map[string]string{
		"host":     cfg.PGHost,
		"port":     cfg.PGPort,
		"user":     cfg.PGUser,
		"password": cfg.PGPassword,
		"dbname":   cfg.PGDatabase,
		"sslmode":  cfg.PGSSLMode,
	})
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Guard the int32 cast with an explicit range check (config validation
	// already floors PGMaxConns at 1): a nonsensical value from the
	// environment must not overflow into a negative pool size. Out of range,
	// pgx's parsed default MaxConns is kept.
	if cfg.PGMaxConns >= 1 && cfg.PGMaxConns <= math.MaxInt32 {
		poolCfg.MaxConns = int32(cfg.PGMaxConns)
	}

	var pool *pgxpool.Pool
	attempts := cfg.PGConnectRetries
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; ; attempt++ {
		pool, err = pgxpool.NewWithConfig(ctx, poolCfg)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = pool.Ping(pingCtx)
			cancel()
			if err == nil {
				break
			}
			pool.Close()
		}
		if attempt >= attempts {
			return nil, fmt.Errorf("connect after %d attempts: %w", attempt, err)
		}
		logger.Warn("database not ready, retrying", "attempt", attempt, "max", attempts, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(cfg.PGConnectBackoff):
		}
	}
	return &Store{pool: pool, tz: cfg.TZ, cipher: cipher, logger: logger}, nil
}

// keywordDSN builds a libpq keyword/value connection string with every value
// single-quoted and backslash/quote escaped, so special characters (including
// URL-reserved ones) in the password are handled correctly.
func keywordDSN(params map[string]string) string {
	esc := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	// Deterministic ordering keeps logs/tests stable.
	order := []string{"host", "port", "user", "password", "dbname", "sslmode"}
	var b strings.Builder
	for _, k := range order {
		v, ok := params[k]
		if !ok {
			continue
		}
		b.WriteString(k)
		b.WriteString("='")
		b.WriteString(esc.Replace(v))
		b.WriteString("' ")
	}
	return strings.TrimSpace(b.String())
}

// Pool exposes the underlying pool (used by extensions that share the store).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

// Ping verifies the database is reachable (used by the readiness probe).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

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

	adminHash, err := security.HashPassword("changeme")
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO users (username, password, first_login, is_radius_user)
		 VALUES ('admin', $1, 1, FALSE) ON CONFLICT DO NOTHING`, adminHash); err != nil {
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
	err = s.pool.QueryRow(ctx,
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
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO activity_logs (username, action, details, timestamp) VALUES ($1, $2, $3, $4)`,
		username, action, details, s.Now()); err != nil {
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

// ChangePassword verifies the current password (accepting a legacy plaintext or
// a bcrypt hash) and stores a new bcrypt hash, clearing the first_login flag.
// Returns false when the current password does not match.
func (s *Store) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) (bool, error) {
	var stored string
	err := s.pool.QueryRow(ctx, `SELECT password FROM users WHERE username = $1`, username).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !security.VerifyPassword(stored, oldPassword) {
		return false, nil
	}
	hash, err := security.HashPassword(newPassword)
	if err != nil {
		return false, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET password = $1, first_login = 0 WHERE username = $2`, hash, username); err != nil {
		return false, err
	}
	return true, nil
}

// AuthenticateLocal verifies local credentials. On success it returns the user
// and, if the stored password was still legacy plaintext, transparently
// upgrades it to a bcrypt hash. Returns (user, false, nil) when the user exists
// but the password is wrong, and (nil, false, nil) when the user is unknown.
func (s *Store) AuthenticateLocal(ctx context.Context, username, password string) (*models.User, bool, error) {
	u, err := s.GetUserForLogin(ctx, username)
	if err != nil {
		return nil, false, err
	}
	if u == nil {
		return nil, false, nil
	}
	if !security.VerifyPassword(u.Password, password) {
		return u, false, nil
	}
	if security.NeedsUpgrade(u.Password) {
		if hash, herr := security.HashPassword(password); herr == nil {
			if _, uerr := s.pool.Exec(ctx,
				`UPDATE users SET password = $1 WHERE username = $2`, hash, username); uerr != nil {
				s.logger.Warn("failed to upgrade password hash", "user", username, "err", uerr)
			}
		}
	}
	return u, true, nil
}

// ListFirewalls returns all firewalls ordered by id.
func (s *Store) ListFirewalls(ctx context.Context) ([]models.Firewall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port, cron_expr
		 FROM firewalls ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanFirewalls(rows)
}

// GetFirewall returns a single firewall or ErrNotFound.
func (s *Store) GetFirewall(ctx context.Context, id int) (*models.Firewall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port, cron_expr
		 FROM firewalls WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fws, err := s.scanFirewalls(rows)
	if err != nil {
		return nil, err
	}
	if len(fws) == 0 {
		return nil, ErrNotFound
	}
	return &fws[0], nil
}

// AddFirewall inserts a firewall (encrypting the SSH password at rest when a key
// is configured) and returns its new id.
func (s *Store) AddFirewall(ctx context.Context, fw models.Firewall) (int, error) {
	pw, err := s.cipher.EncryptString(fw.Password)
	if err != nil {
		return 0, fmt.Errorf("encrypt password: %w", err)
	}
	var cron *string
	if fw.CronExpr != "" {
		cron = &fw.CronExpr
	}
	// Store a non-positive interval as NULL: the firewalls table has a
	// CHECK (interval_minutes > 0), so a 0 would be rejected. NULL passes the
	// check and is treated as "use the cron expression / default interval" by the
	// scheduler, which is what a cron-only firewall needs.
	var interval *int
	if fw.IntervalMin > 0 {
		interval = &fw.IntervalMin
	}
	// An unset (<=0) SSH port would otherwise be stored as 0; coerce it to the
	// same default the column uses so backups target the right port.
	sshPort := fw.SSHPort
	if sshPort <= 0 {
		sshPort = 9422
	}
	var id int
	err = s.pool.QueryRow(ctx,
		`INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port, cron_expr)
		 VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8) RETURNING id`,
		fw.FQDN, fw.Username, pw, interval, fw.RetentionCount, fw.Status, sshPort, cron).Scan(&id)
	return id, err
}

// DeleteFirewall removes a firewall and its backup rows in a single
// transaction, returning its FQDN.
func (s *Store) DeleteFirewall(ctx context.Context, id int) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var fqdn string
	err = tx.QueryRow(ctx, `SELECT fqdn FROM firewalls WHERE id = $1`, id).Scan(&fqdn)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM backups WHERE fw_id = $1`, id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM firewalls WHERE id = $1`, id); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return fqdn, nil
}

// ListBackups returns the distinct backups for a firewall, newest first.
func (s *Store) ListBackups(ctx context.Context, fwID int) ([]models.Backup, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT id, fw_id, timestamp, filename, size_bytes, checksum
		 FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC`, fwID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Backup
	for rows.Next() {
		var (
			b    models.Backup
			size *int64
			sum  *string
		)
		if err := rows.Scan(&b.ID, &b.FwID, &b.Timestamp, &b.Filename, &size, &sum); err != nil {
			return nil, err
		}
		if size != nil {
			b.SizeBytes = *size
		}
		if sum != nil {
			b.Checksum = *sum
		}
		out = append(out, b)
	}
	return out, rows.Err()
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
		var lastBackup *time.Time
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

// ListActivityLogs returns a page of activity, newest first.
func (s *Store) ListActivityLogs(ctx context.Context, limit, offset int) ([]models.ActivityLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT username, action, details, timestamp FROM activity_logs
		 ORDER BY timestamp DESC LIMIT $1 OFFSET $2`, limit, offset)
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

// CountActivityLogs returns the total number of activity rows.
func (s *Store) CountActivityLogs(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM activity_logs`).Scan(&n)
	return n, err
}

// PruneActivityLogs deletes activity rows older than the retention window.
// A retention of 0 keeps everything.
func (s *Store) PruneActivityLogs(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := s.Now().AddDate(0, 0, -days)
	tag, err := s.pool.Exec(ctx, `DELETE FROM activity_logs WHERE timestamp < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DashboardStats returns aggregate counts for the overview page.
func (s *Store) DashboardStats(ctx context.Context) (models.DashboardStats, error) {
	var st models.DashboardStats
	err := s.pool.QueryRow(ctx, `
		SELECT
			count(*),
			count(*) FILTER (WHERE status = 'Success'),
			count(*) FILTER (WHERE status LIKE 'Failed:%'),
			count(*) FILTER (WHERE status = 'New')
		FROM firewalls`).Scan(&st.TotalFirewalls, &st.Healthy, &st.Failed, &st.New)
	if err != nil {
		return st, err
	}
	cutoff := s.Now().Add(-24 * time.Hour)
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM backups WHERE timestamp >= $1`, cutoff).Scan(&st.BackupsLast24h); err != nil {
		return st, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM backups`).Scan(&st.TotalBackups); err != nil {
		return st, err
	}
	return st, nil
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

// ListSchedules returns id/interval/cron rows used to (re)build backup jobs.
func (s *Store) ListSchedules(ctx context.Context) ([]models.FirewallSchedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, interval_minutes, cron_expr FROM firewalls`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.FirewallSchedule
	for rows.Next() {
		var sc models.FirewallSchedule
		var interval *int
		var cron *string
		if err := rows.Scan(&sc.ID, &interval, &cron); err != nil {
			return nil, err
		}
		if interval != nil {
			sc.IntervalMin = *interval
		}
		if cron != nil {
			sc.CronExpr = *cron
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ---- backup engine helpers ----

// LastBackupTime returns the newest backup time for a firewall.
func (s *Store) LastBackupTime(ctx context.Context, fwID int) (time.Time, bool, error) {
	var ts time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT timestamp FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC LIMIT 1`, fwID).Scan(&ts)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return ts, true, nil
}

// InsertBackup records a new backup file, its size and checksum (idempotent on
// the unique constraint).
func (s *Store) InsertBackup(ctx context.Context, fwID int, ts time.Time, filename string, size int64, checksum string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO backups (fw_id, timestamp, filename, size_bytes, checksum)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
		fwID, ts, filename, size, checksum)
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

// ListBackupIDFilenames returns id/filename pairs for cleanup, newest first. A
// limit <= 0 returns every row: callers that use this for orphan detection must
// see the complete set, otherwise valid files whose rows fall outside the page
// would be misclassified as orphans and deleted.
func (s *Store) ListBackupIDFilenames(ctx context.Context, fwID, limit int) ([]models.Backup, error) {
	query := `SELECT id, filename FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC`
	args := []any{fwID}
	if limit > 0 {
		query += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, query, args...)
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
func (s *Store) UpdateFirewallSuccess(ctx context.Context, id int, lastBackup time.Time, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE firewalls SET last_backup = $1, status = $2, updated_at = now() WHERE id = $3`,
		lastBackup, status, id)
	return err
}

// UpdateFirewallStatus records only a status change (used for failures / in-progress).
func (s *Store) UpdateFirewallStatus(ctx context.Context, id int, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE firewalls SET status = $1, updated_at = now() WHERE id = $2`, status, id)
	return err
}

func (s *Store) scanFirewalls(rows pgx.Rows) ([]models.Firewall, error) {
	var out []models.Firewall
	for rows.Next() {
		var (
			fw         models.Firewall
			lastBackup *time.Time
			status     *string
			sshPort    *int
			interval   *int
			retention  *int
			cronExpr   *string
		)
		if err := rows.Scan(&fw.ID, &fw.FQDN, &fw.Username, &fw.Password,
			&interval, &retention, &lastBackup, &status, &sshPort, &cronExpr); err != nil {
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
		if cronExpr != nil {
			fw.CronExpr = *cronExpr
		}
		if pw, err := s.cipher.DecryptString(fw.Password); err == nil {
			fw.Password = pw
		} else {
			// Do not return the still-encrypted value: an SSH auth with ciphertext
			// as the password is worse (and more confusing) than an empty one.
			s.logger.Error("failed to decrypt firewall password", "fw_id", fw.ID, "err", err)
			fw.Password = ""
		}
		out = append(out, fw)
	}
	return out, rows.Err()
}

// GetAuditFindings returns the cached audit findings for a firewall.
func (s *Store) GetAuditFindings(ctx context.Context, fwID int) ([]models.AuditFinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT fw_id, backup_filename, severity, finding_text, remediation
		 FROM audit_findings
		 WHERE fw_id = $1`, fwID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.AuditFinding
	for rows.Next() {
		var f models.AuditFinding
		if err := rows.Scan(&f.FwID, &f.BackupFilename, &f.Severity, &f.Text, &f.Remediation); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SaveAuditFindings clears old findings and inserts new ones in a transaction.
func (s *Store) SaveAuditFindings(ctx context.Context, fwID int, findings []models.AuditFinding) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM audit_findings WHERE fw_id = $1`, fwID); err != nil {
		return err
	}

	for _, f := range findings {
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_findings (fw_id, backup_filename, severity, finding_text, remediation)
			 VALUES ($1, $2, $3, $4, $5)`,
			fwID, f.BackupFilename, f.Severity, f.Text, f.Remediation); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
