package fgt_confgen

import (
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

//go:embed templates/* static/*
var extensionFS embed.FS

type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	db     *sql.DB
	pgPool *pgxpool.Pool
	page   *webui.Renderer
	tz     *time.Location
	cipher *crypto.Cipher

	logActivity func(username, action, details string)
	currentUser func(*http.Request) string
	pageBase    extension.PageBaseProvider
}

func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}

func (e *Extension) Name() string { return "fgt_confgen" }

func (e *Extension) Prefix() string { return "/fgt-confgen" }

func (e *Extension) Enabled() bool { return e.cfg.ExtFgtConfGen }

func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	if d.PageBase == nil {
		return errors.New("fgt_confgen: shared page context is required")
	}
	e.logActivity = d.LogActivity
	e.currentUser = d.CurrentUser
	e.pageBase = d.PageBase
	e.tz = d.TZ
	e.pgPool = d.DB
	e.cipher = d.Cipher
	if e.tz == nil {
		e.tz = time.UTC
	}

	if err := os.MkdirAll(d.DataDir, 0o700); err != nil {
		return err
	}
	dbFile := filepath.Join(d.DataDir, "fgt-confgen-db.db")
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return err
	}
	e.db = db
	db.SetMaxOpenConns(1)

	// Initialize private SQLite schema
	if err := InitDB(db); err != nil {
		return err
	}

	if err := e.parseTemplates(); err != nil {
		return err
	}

	// Routes
	r.Group(func(pr chi.Router) {
		pr.Use(d.LoginRequired)
		pr.Get("/", e.index)
		pr.Get("/list_firewalls", e.listFirewalls)
		pr.Get("/load_firewall_config", e.loadFirewallConfig)
		pr.Post("/parse_config", e.parseConfig)
		pr.Get("/load_templates", e.loadTemplatesEndpoint)
		pr.Get("/get_template/{templateName}", e.getTemplate)
		pr.Post("/save_template", e.saveTemplate)
		pr.Delete("/delete_template/{templateName}", e.deleteTemplate)
		pr.Post("/rename_template", e.renameTemplate)
		pr.Post("/clone_template/{templateName}", e.cloneTemplate)
		pr.Post("/clone_policy", e.clonePolicy)
		pr.Post("/generate_policy", e.generatePolicy)
		pr.Post("/import_template", e.importTemplate)
		pr.Get("/export_template/{templateName}", e.exportTemplate)
		pr.Post("/shorten_url", e.shortenURL)
		pr.Post("/log", e.logFrontend)
	})

	// Public short URL redirect
	r.Get("/s/{shortCode}", e.redirectShortURL)

	// Serve static files
	staticSub, err := fs.Sub(extensionFS, "static")
	if err != nil {
		return err
	}
	r.Handle("/static/*", http.StripPrefix("/fgt-confgen/static/", http.FileServer(http.FS(staticSub))))

	return nil
}

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
