# Architecture

FortiSafe is a single Go binary that backs up FortiGate configurations over
SSH/SCP on a schedule, serves a web UI, and optionally mounts self-contained
feature extensions. It runs as **one process** — the scheduler and every
extension background worker are goroutines, so there is no multi-worker
coordination to manage.

## Package layout

```
cmd/fortisafe/        entrypoint: wires config, DB, cipher, scheduler, web, extensions
internal/
  config/             environment parsing (all *_ENV vars, defaults, key decoding)
  models/             plain row structs shared by the store
  crypto/             AES-256-GCM encryption at rest (no-op passthrough when no key)
  security/           bcrypt password hashing + legacy-plaintext verification
  database/           PostgreSQL store (postgres.go) + versioned migrations (migrations.go)
  session/            signed-cookie sessions + login_required middleware (idle timeout, IP pinning)
  auth/               RADIUS (PAP) + TOTP verification
  scheduler/          per-firewall interval/cron jobs (last/next run tracking)
  backup/             SSH/SCP engine (engine.go, scp.go) + bounded worker pool (backup.go)
  mailer/             SMTP STARTTLS failure notifications
  extension/          the Extension interface + registry
  web/                chi router, embedded templates/static, handlers, middleware,
                      rate limiter, SSE hub, styled error pages
extensions/
  fgt_adm_vpn_conf/   the ADM VPN config module (own SQLite DB + Graylog/HookWise worker)
```

## Request & data flow

- `cmd/fortisafe` builds the shared services and calls `web.Server.Routes()` to
  get the chi router, then mounts each enabled extension under its prefix.
- The web layer depends on a `web.Store` **interface** (not the concrete
  `*database.Store`), which keeps handlers testable with a fake.
- Middleware order: request id → access log → panic recovery → security headers.
  Authenticated routes additionally run the session `LoginRequired` guard.
- The backup engine writes `BACKUP_DIR/<fw_id>/<timestamp>.conf`. When an
  `ENCRYPTION_KEY` is configured the file is encrypted at rest; the download and
  search paths transparently decrypt it. Firewall SSH passwords are likewise
  encrypted in the `firewalls.password` column.

## Database

- **PostgreSQL** is the shared store. `InitSchema` creates the baseline tables
  (compatible with a database created by the original Python app), then
  `Migrate` applies ordered, idempotent migrations recorded in
  `schema_migrations` (indexes, cron column, created/updated, backup
  size/checksum, and a forward-only conversion of the TEXT timestamp columns to
  `timestamptz`).
- The scheduler is rebuilt from the `firewalls` table at startup; the old
  APScheduler `apscheduler_jobs` table is neither used nor touched.
- **SQLite** (`DATA_DIR/fgt-adm-vpn-conf-db.db`) is private to the VPN
  extension, opened in WAL mode with a busy timeout.

## Concurrency model

- `scheduler` runs one goroutine per job; a job never overlaps itself.
- `backup.Service` gates concurrent backups with a semaphore
  (`MAX_CONCURRENT_BACKUPS`). Manual "Backup Now" is asynchronous.
- The SSE hub fans out status changes to connected browsers.

See [EXTENSIONS.md](EXTENSIONS.md) for how to add a feature module.
