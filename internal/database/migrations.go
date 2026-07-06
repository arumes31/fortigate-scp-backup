package database

import (
	"context"
	"fmt"
)

// migration is a single, ordered, idempotent schema change recorded in the
// schema_migrations table so it runs at most once per database.
type migration struct {
	version int
	name    string
	run     func(ctx context.Context, s *Store) error
}

// migrations are applied in version order after InitSchema has created the
// baseline tables. Every step is safe to run against a database created by the
// original Python app.
var migrations = []migration{
	{1, "indexes", func(ctx context.Context, s *Store) error {
		return s.execAll(ctx,
			`CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs (timestamp DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_backups_fw_timestamp ON backups (fw_id, timestamp DESC)`,
		)
	}},
	{2, "firewall_cron", func(ctx context.Context, s *Store) error {
		return s.execAll(ctx,
			`ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS cron_expr TEXT`,
		)
	}},
	{3, "firewall_timestamps", func(ctx context.Context, s *Store) error {
		return s.execAll(ctx,
			`ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now()`,
			`ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now()`,
		)
	}},
	{4, "backup_size_checksum", func(ctx context.Context, s *Store) error {
		return s.execAll(ctx,
			`ALTER TABLE backups ADD COLUMN IF NOT EXISTS size_bytes BIGINT`,
			`ALTER TABLE backups ADD COLUMN IF NOT EXISTS checksum TEXT`,
		)
	}},
	{5, "timestamps_to_timestamptz", migrateTimestampsToTZ},
}

// Migrate applies any pending migrations in order.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	rows.Close()

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		s.logger.Info("applying migration", "version", m.version, "name", m.name)
		if err := m.run(ctx, s); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
	}
	return nil
}

// execAll runs a series of statements, stopping on the first error.
func (s *Store) execAll(ctx context.Context, stmts ...string) error {
	for _, q := range stmts {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// migrateTimestampsToTZ converts the legacy TEXT timestamp columns to
// timestamptz. The original strings are naive local time in the configured
// timezone, so the conversion runs inside a transaction with the session
// timezone set accordingly. NULL/empty values become NULL.
//
// NOTE: this changes the physical schema; the columns are no longer the exact
// TEXT format the Python app wrote. It is a forward-only migration.
func migrateTimestampsToTZ(ctx context.Context, s *Store) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	// Idempotency guard: skip if already timestamptz (e.g. partial prior run).
	var dataType string
	if err := conn.QueryRow(ctx,
		`SELECT data_type FROM information_schema.columns
		 WHERE table_name='activity_logs' AND column_name='timestamp'`).Scan(&dataType); err == nil {
		if dataType == "timestamp with time zone" {
			return nil
		}
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL TIME ZONE %s", quoteLiteral(s.tz.String()))); err != nil {
		return err
	}
	stmts := []string{
		`ALTER TABLE activity_logs ALTER COLUMN timestamp TYPE timestamptz
		   USING (CASE WHEN timestamp IS NULL OR timestamp = '' THEN NULL
		               ELSE to_timestamp(timestamp, 'YYYY-MM-DD HH24:MI:SS') END)`,
		`ALTER TABLE firewalls ALTER COLUMN last_backup TYPE timestamptz
		   USING (CASE WHEN last_backup IS NULL OR last_backup = '' THEN NULL
		               ELSE to_timestamp(last_backup, 'YYYYMMDD_HH24MISS') END)`,
		`ALTER TABLE backups ALTER COLUMN timestamp TYPE timestamptz
		   USING (CASE WHEN timestamp IS NULL OR timestamp = '' THEN NULL
		               ELSE to_timestamp(timestamp, 'YYYYMMDD_HH24MISS') END)`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// quoteLiteral single-quotes a SQL string literal (for identifiers that cannot
// be parameterized, such as SET TIME ZONE).
func quoteLiteral(s string) string {
	out := "'"
	for _, r := range s {
		if r == '\'' {
			out += "''"
		} else {
			out += string(r)
		}
	}
	return out + "'"
}
