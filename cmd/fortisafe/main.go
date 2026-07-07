// Command fortisafe is the FortiGate SCP backup service. It backs up FortiGate
// configurations over SSH/SCP on a schedule, exposes a web UI, and optionally
// loads self-contained extensions (e.g. the ADM VPN config module).
//
// It runs as a single process: the scheduler and any extension background
// workers are goroutines, which is why the old "gunicorn --workers 1"
// constraint no longer applies.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "time/tzdata" // embed the timezone database (no OS tzdata needed)

	"github.com/arumes31/fortigate-scp-backup/internal/auth"
	"github.com/arumes31/fortigate-scp-backup/internal/backup"
	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
	"github.com/arumes31/fortigate-scp-backup/internal/scheduler"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
	"github.com/arumes31/fortigate-scp-backup/internal/web"

	fgtadmvpnconf "github.com/arumes31/fortigate-scp-backup/extensions/fgt_adm_vpn_conf"
)

func main() {
	bootstrap := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Load(bootstrap)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	slog.SetDefault(logger)
	logger.Info("starting FortiSafe",
		"totp_enabled", cfg.TOTPEnabled,
		"radius_enabled", cfg.RadiusEnabled,
		"ext_adm_vpn_conf", cfg.ExtAdmVpnConf,
		"scp_timeout", cfg.SCPTimeout,
		"port", cfg.Port)

	ctx := context.Background()

	// Bound all startup database work (connect+retry, schema init, migrations,
	// schedule load) so a slow or unreachable database cannot block boot forever.
	// The window comfortably exceeds the default connect retry/backoff budget.
	startupCtx, startupCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer startupCancel()

	cipher, err := crypto.New(cfg.EncryptionKey)
	if err != nil {
		logger.Error("failed to initialize cipher", "err", err)
		os.Exit(1)
	}
	if cipher.Enabled() {
		logger.Info("encryption at rest enabled (credentials + backup files)")
	}

	// Shared PostgreSQL store + schema init/migrations.
	store, err := database.NewStore(startupCtx, cfg, cipher, logger)
	if err != nil {
		logger.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := store.InitSchema(startupCtx, cfg.TOTPEnabled, cfg.TOTPSecret); err != nil {
		logger.Error("failed to initialize database schema", "err", err)
		os.Exit(1)
	}
	if err := store.Migrate(startupCtx); err != nil {
		logger.Error("failed to run database migrations", "err", err)
		os.Exit(1)
	}
	if cfg.ActivityLogRetentionDays > 0 {
		go pruneActivityLogs(store, cfg.ActivityLogRetentionDays, logger)
	}

	// Backup storage directory. 0o750 keeps the FortiGate configs (potentially
	// plaintext when encryption at rest is disabled) off world-readable paths.
	if err := os.MkdirAll(cfg.BackupDir, 0o750); err != nil {
		logger.Error("failed to create backup directory", "dir", cfg.BackupDir, "err", err)
		os.Exit(1)
	}

	// Core services.
	mail := mailer.New(cfg, logger)
	authn := auth.New(cfg, logger)
	sess := session.New(cfg.SessionKey, cfg.CookieSecure)
	sched := scheduler.New(logger, cfg.TZ)
	backupSvc := backup.New(store, mail, cfg, cipher, logger)

	// Rebuild recurring backup jobs from the firewalls table (replaces the
	// APScheduler job store). Stagger startup by 10s per firewall. A cron
	// expression, when present, takes precedence over the interval.
	schedules, err := store.ListSchedules(startupCtx)
	if err != nil {
		logger.Error("failed to load firewall schedules", "err", err)
		os.Exit(1)
	}
	for i, sc := range schedules {
		id := sc.ID
		jobID := web.BackupJobID(id)
		if sc.CronExpr != "" {
			if err := sched.ScheduleCron(jobID, sc.CronExpr, func() { backupSvc.Backup(id) }); err == nil {
				continue
			} else {
				logger.Warn("invalid cron, falling back to interval", "fw_id", id, "cron", sc.CronExpr, "err", err)
			}
		}
		if sc.IntervalMin <= 0 {
			logger.Warn("invalid interval, skipping job", "fw_id", id, "interval", sc.IntervalMin)
			continue
		}
		sched.Schedule(jobID,
			time.Duration(sc.IntervalMin)*time.Minute,
			time.Duration(i)*10*time.Second,
			func() { backupSvc.Backup(id) })
	}
	logger.Info("scheduled backup jobs", "count", len(sched.IDs()))

	// Web server.
	srv, err := web.New(cfg, store, sched, backupSvc, sess, authn, cipher, logger)
	if err != nil {
		logger.Error("failed to build web server", "err", err)
		os.Exit(1)
	}
	// Live status updates: the engine notifies the web SSE hub on every change.
	backupSvc.SetStatusHook(srv.BroadcastStatus)
	router := srv.Routes()

	// Extensions: register, then mount the enabled ones.
	registry := extension.NewRegistry()
	registry.Register(fgtadmvpnconf.New(cfg, logger))
	if err := registry.MountEnabled(router, extension.Deps{
		DB:            store.Pool(),
		LogActivity:   store.LogActivity,
		LoginRequired: sess.LoginRequired,
		CurrentUser:   func(r *http.Request) string { return sess.User(r).Username },
		Logger:        logger,
		TZ:            cfg.TZ,
		DataDir:       cfg.DataDir,
	}); err != nil {
		logger.Error("failed to mount extensions", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Graceful shutdown.
	go func() {
		logger.Info("listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	sched.Stop()
	logger.Info("shutdown complete")
}

// pruneActivityLogs periodically deletes activity rows older than the retention
// window (runs at startup and daily thereafter).
func pruneActivityLogs(store *database.Store, days int, logger *slog.Logger) {
	prune := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if n, err := store.PruneActivityLogs(ctx, days); err != nil {
			logger.Error("activity log prune failed", "err", err)
		} else if n > 0 {
			logger.Info("pruned old activity logs", "deleted", n, "retention_days", days)
		}
	}
	prune()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for range t.C {
		prune()
	}
}

// parseLevel maps a LOG_LEVEL string to an slog.Level (default info).
func parseLevel(s string) slog.Level {
	switch s {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN", "warning":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
