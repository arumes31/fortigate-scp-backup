// Package fgtadmvpnconf is the self-contained "ADM VPN config" extension. It
// owns a private SQLite database, generates FortiGate config bundles, exposes a
// public Graylog DSV endpoint and runs a background Graylog/HookWise status
// worker. It is mounted at /fgt-adm-vpn-conf only when EXT_ADM_VPN_CONF=true.
package fgtadmvpnconf

import (
	"database/sql"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
)

// Extension implements extension.Extension.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	db   *sql.DB
	tmpl *template.Template
	tz   *time.Location

	logActivity func(username, action, details string)
	currentUser func(*http.Request) string

	migrateOnce sync.Once
	migrateErr  error
}

// New constructs the extension (not yet enabled/mounted).
func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}

// Name identifies the extension in logs.
func (e *Extension) Name() string { return "fgt_adm_vpn_conf" }

// Prefix is the URL mount point.
func (e *Extension) Prefix() string { return "/fgt-adm-vpn-conf" }

// Enabled reports whether EXT_ADM_VPN_CONF is set.
func (e *Extension) Enabled() bool { return e.cfg.ExtAdmVpnConf }

// Mount opens the private database, runs migrations, parses templates, registers
// routes and starts the Graylog background worker.
func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	e.logActivity = d.LogActivity
	e.currentUser = d.CurrentUser
	e.tz = d.TZ
	if e.tz == nil {
		e.tz = time.UTC
	}

	if err := os.MkdirAll(d.DataDir, 0o777); err != nil {
		return err
	}
	db, err := openDB(filepath.Join(d.DataDir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		return err
	}
	e.db = db

	if _, err := db.Exec(createTableSQL); err != nil {
		return err
	}
	if err := e.ensureMigrations(); err != nil {
		return err
	}
	if err := e.parseTemplates(); err != nil {
		return err
	}

	// Authenticated routes.
	r.Group(func(pr chi.Router) {
		pr.Use(d.LoginRequired)
		pr.Get("/", e.index)
		pr.Post("/add", e.add)
		pr.Post("/import", e.importCSV)
		pr.Get("/edit/{id}", e.editForm)
		pr.Post("/edit/{id}", e.editSubmit)
		pr.Get("/delete/{id}", e.delete)
		pr.Get("/generate_single/{id}", e.generateSingle)
		pr.Get("/export", e.exportCSV)
		pr.Get("/export_bookmarks", e.exportBookmarks)
	})

	// Public status feed (no auth) consumed by external monitoring.
	r.Get("/graylog_dsv", e.graylogDSV)

	go e.graylogWorker()
	return nil
}

// logAction records an activity-log entry from a background context (no request).
func (e *Extension) logAction(action, details string) {
	if e.logActivity != nil {
		e.logActivity("System", action, details)
	}
}

// log records an activity-log entry attributed to the current request's user.
func (e *Extension) log(r *http.Request, action, details string) {
	if e.logActivity == nil {
		return
	}
	user := ""
	if e.currentUser != nil {
		user = e.currentUser(r)
	}
	e.logActivity(user, action, details)
}

var _ extension.Extension = (*Extension)(nil)
