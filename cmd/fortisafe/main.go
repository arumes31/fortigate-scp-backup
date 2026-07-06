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
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
	"github.com/arumes31/fortigate-scp-backup/internal/scheduler"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
	"github.com/arumes31/fortigate-scp-backup/internal/web"

	fgtadmvpnconf "github.com/arumes31/fortigate-scp-backup/extensions/fgt_adm_vpn_conf"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := config.Load(logger)
	logger.Info("starting FortiSafe",
		"totp_enabled", cfg.TOTPEnabled,
		"radius_enabled", cfg.RadiusEnabled,
		"ext_adm_vpn_conf", cfg.ExtAdmVpnConf,
		"scp_timeout", cfg.SCPTimeout,
		"port", cfg.Port)

	ctx := context.Background()

	// Shared PostgreSQL store + schema init/migrations.
	store, err := database.NewStore(ctx, cfg.PostgresDSN(), cfg.TZ, logger)
	if err != nil {
		logger.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := store.InitSchema(ctx, cfg.TOTPEnabled, cfg.TOTPSecret); err != nil {
		logger.Error("failed to initialize database schema", "err", err)
		os.Exit(1)
	}

	// Backup storage directory.
	if err := os.MkdirAll(cfg.BackupDir, 0o777); err != nil {
		logger.Error("failed to create backup directory", "dir", cfg.BackupDir, "err", err)
		os.Exit(1)
	}

	// Core services.
	mail := mailer.New(cfg, logger)
	authn := auth.New(cfg, logger)
	sess := session.New()
	sched := scheduler.New(logger)
	backupSvc := backup.New(store, mail, cfg, logger)

	// Rebuild recurring backup jobs from the firewalls table (replaces the
	// APScheduler job store). Stagger startup by 10s per firewall.
	schedules, err := store.ListSchedules(ctx)
	if err != nil {
		logger.Error("failed to load firewall schedules", "err", err)
		os.Exit(1)
	}
	for i, sc := range schedules {
		if sc.IntervalMin <= 0 {
			logger.Warn("invalid interval, skipping job", "fw_id", sc.ID, "interval", sc.IntervalMin)
			continue
		}
		id := sc.ID
		jobID := web.BackupJobID(id)
		sched.Schedule(jobID,
			time.Duration(sc.IntervalMin)*time.Minute,
			time.Duration(i)*10*time.Second,
			func() { backupSvc.Backup(id) })
	}
	logger.Info("scheduled backup jobs", "count", len(sched.IDs()))

	// Web server.
	srv, err := web.New(cfg, store, sched, backupSvc, sess, authn, logger)
	if err != nil {
		logger.Error("failed to build web server", "err", err)
		os.Exit(1)
	}
	router := srv.Routes()

	// Extensions: register, then mount the enabled ones.
	registry := extension.NewRegistry()
	registry.Register(fgtadmvpnconf.New(cfg, logger))
	registry.MountEnabled(router, extension.Deps{
		DB:            store.Pool(),
		LogActivity:   store.LogActivity,
		LoginRequired: sess.LoginRequired,
		CurrentUser:   func(r *http.Request) string { return sess.User(r).Username },
		Logger:        logger,
		TZ:            cfg.TZ,
		DataDir:       cfg.DataDir,
	})

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
