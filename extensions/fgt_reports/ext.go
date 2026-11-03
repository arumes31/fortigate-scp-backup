// Package fgt_reports automatically publishes the latest configuration and
// Graylog-derived reports for each registered firewall.
package fgt_reports

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	_ "modernc.org/sqlite"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Extension struct {
	cfg          *config.Config
	dataDir      string
	logger       *slog.Logger
	db           *sql.DB
	cipher       *crypto.Cipher
	ctx          context.Context
	wake         chan struct{}
	done         chan struct{}
	page         *webui.Renderer
	detailPage   *webui.Renderer
	profilePage  *webui.Renderer
	catalogPage  *webui.Renderer
	calendarPage *webui.Renderer
	pageBase     extension.PageBaseProvider
	listSources  func(context.Context) ([]reportmodel.Source, error)
	readSource   func(context.Context, int, int) (reportmodel.Source, []byte, error)
	canRead      func(*http.Request) bool
	currentUser  func(*http.Request) string
	logActivity  func(string, string, string)
	broadcast    func(string, int, string)
	// Dependency seams keep lifecycle/atomicity tests independent of PDF layout.
	analyze          func(context.Context, []byte) (reportmodel.Assessment, error)
	render           func(context.Context, reportmodel.Source, reportmodel.Assessment, string, string) ([]byte, error)
	renderProfile    func(context.Context, reportmodel.Source, reportmodel.Assessment, string, reportmodel.Profile) ([]byte, error)
	collectTelemetry func(context.Context, reportmodel.Source, reportmodel.Assessment, reportmodel.Profile, time.Time) reportmodel.Telemetry
}

func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}
func (e *Extension) Name() string   { return "fgt_reports" }
func (e *Extension) Prefix() string { return "/reports" }
func (e *Extension) Enabled() bool  { return e.cfg.ExtFgtReports }

func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	if d.Context == nil || d.PageBase == nil || d.LoginRequired == nil || d.CanReadReports == nil ||
		d.ListReportSources == nil || d.ReadReportSource == nil || d.SubscribeBackup == nil {
		return errors.New("fgt_reports: authenticated source and lifecycle services are required")
	}
	if d.Cipher == nil || !d.Cipher.Enabled() {
		return errors.New("fgt_reports: encrypted storage is required")
	}
	e.ctx, e.cipher = d.Context, d.Cipher
	e.dataDir = d.DataDir
	e.pageBase, e.canRead = d.PageBase, d.CanReadReports
	e.listSources, e.readSource = d.ListReportSources, d.ReadReportSource
	e.currentUser, e.logActivity, e.broadcast = d.CurrentUser, d.LogActivity, d.BroadcastOp
	if e.logger == nil {
		e.logger = slog.Default()
	}
	if e.cfg.ReportsLanguage != "de" {
		e.cfg.ReportsLanguage = "en"
	}
	var err error
	funcs := template.FuncMap{"R": reportText}
	e.page, err = webui.ParsePage(assets, "templates/index.html", funcs)
	if err != nil {
		return err
	}
	e.detailPage, err = webui.ParsePage(assets, "templates/detail.html", funcs)
	if err != nil {
		return err
	}
	e.profilePage, err = webui.ParsePage(assets, "templates/profile.html", funcs)
	if err != nil {
		return err
	}
	e.catalogPage, err = webui.ParsePage(assets, "templates/catalog.html", funcs)
	if err != nil {
		return err
	}
	e.calendarPage, err = webui.ParsePage(assets, "templates/calendar.html", funcs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.DataDir, 0o700); err != nil {
		return err
	}
	dbPath := filepath.Join(d.DataDir, "fgt-reports.db")
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		if err := file.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("fgt_reports: report store must be a regular file")
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return err
	}
	e.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	e.db.SetMaxOpenConns(1)
	if err := initDB(d.Context, e.db); err != nil {
		_ = e.db.Close()
		return err
	}
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		_ = e.db.Close()
		return err
	}
	r.Group(func(pr chi.Router) {
		pr.Use(d.LoginRequired, e.authorized)
		pr.Get("/", e.index)
		pr.Get("/catalog", e.catalog)
		pr.Get("/calendar", e.calendar)
		pr.Get("/{firewallID}", e.detail)
		pr.Get("/{firewallID}/data", e.data)
		pr.Get("/{firewallID}/{kind}.pdf", e.download)
		pr.Get("/{firewallID}/{kind}.html", e.exportHTML)
		pr.Get("/{firewallID}/{kind}.csv", e.exportCSV)
		pr.Get("/{firewallID}/{kind}.json", e.exportJSON)
		pr.Get("/{firewallID}/{kind}.xml", e.exportXML)
		pr.Get("/{firewallID}/profile", e.profile)
		pr.Post("/{firewallID}/profile", e.updateProfile)
		pr.Get("/{firewallID}/profile.json", e.exportProfile)
		pr.Post("/{firewallID}/profile/import", e.importProfile)
		pr.Post("/{firewallID}/profile/copy", e.copyProfile)
		pr.Post("/{firewallID}/profile/reset", e.resetProfile)
		pr.Post("/{firewallID}/regenerate", e.regenerate)
		pr.Handle("/static/*", http.StripPrefix("/reports/static/", http.FileServer(http.FS(staticFS))))
	})
	e.wake, e.done = make(chan struct{}, 1), make(chan struct{})
	d.SubscribeBackup(func(_ models.Backup) { e.signal() })
	if d.RegisterHealth != nil {
		d.RegisterHealth("reports", func(ctx context.Context) string {
			if e.db.PingContext(ctx) != nil {
				return "error"
			}
			return "ok"
		})
	}
	go e.run()
	return nil
}

func (e *Extension) authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.canRead == nil || !e.canRead(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (e *Extension) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Extension) generation() string {
	return profileGeneration(reportmodel.DefaultProfile(e.cfg.ReportsLanguage))
}

func (e *Extension) run() {
	defer close(e.done)
	defer func() { _ = e.db.Close() }()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	e.signal() // Backfill newest backups on first enable; repair missed events on restart.
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.wake:
		case <-ticker.C:
		}
		if err := e.refresh(e.ctx); err != nil {
			e.logger.Warn("report source reconciliation failed")
			continue
		}
		if err := e.enqueueScheduled(e.ctx, time.Now()); err != nil {
			e.logger.Warn("report schedule reconciliation failed")
		}
		for e.ctx.Err() == nil {
			t, err := nextTarget(e.ctx, e.db, time.Now())
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				e.logger.Warn("report queue read failed")
				break
			}
			e.generate(t)
		}
		// Reclaim replaced/deleted encrypted blobs without retaining historical sets.
		if _, err := e.db.ExecContext(e.ctx, "PRAGMA incremental_vacuum(128)"); err != nil && e.ctx.Err() == nil {
			e.logger.Warn("report store compaction failed")
		}
	}
}

func (e *Extension) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sources, err := e.listSources(ctx)
	if err != nil {
		return err
	}
	return reconcileGenerations(ctx, e.db, sources, func(tx *sql.Tx, id int) (string, error) {
		// Read the profile in the same transaction as the queue update. An
		// earlier snapshot could otherwise undo a concurrent profile edit.
		saved, err := e.readProfile(ctx, tx, id)
		if err != nil {
			return "", err
		}
		return profileGeneration(saved.Profile), nil
	})
}

var _ extension.Extension = (*Extension)(nil)
