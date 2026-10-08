// Package fgt_confconv implements the Configuration Conversions extension:
// pick a firewall, select one or more structural migration recipes (e.g.
// interfaces -> FortiLink, WAN interfaces -> SD-WAN), and get back a
// reviewable CLI script. See docs/plans/2026-07-22-fgt-confconv-design.md.
package fgt_confconv

import (
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

//go:embed templates/* static/*
var extensionFS embed.FS

// Extension is the configuration conversion tool. Stateless, like
// fgt_polsplit: firewalls/backups come from the shared PostgreSQL database;
// only the shared activity log is written.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

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

func (e *Extension) Name() string { return "fgt_confconv" }

func (e *Extension) Prefix() string { return "/fgt-confconv" }

func (e *Extension) Enabled() bool { return e.cfg.ExtFgtConfConv }

func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	if d.PageBase == nil {
		return errors.New("fgt_confconv: shared page context is required")
	}
	if d.Cipher == nil {
		return errors.New("fgt_confconv: shared cipher is required")
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

	if err := e.parseTemplates(); err != nil {
		return err
	}

	r.Group(func(pr chi.Router) {
		pr.Use(d.LoginRequired)
		pr.Get("/", e.index)
		pr.Get("/list_firewalls", e.listFirewalls)
		pr.Get("/config_summary", e.configSummary)
		pr.Post("/convert", e.convert)
	})

	staticSub, err := fs.Sub(extensionFS, "static")
	if err != nil {
		return err
	}
	r.Handle("/static/*", http.StripPrefix("/fgt-confconv/static/", http.FileServer(http.FS(staticSub))))

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

func (e *Extension) parseTemplates() error {
	page, err := webui.ParsePage(extensionFS, "templates/fgt_confconv_index.html", nil)
	if err != nil {
		return err
	}
	e.page = page
	return nil
}

var _ extension.Extension = (*Extension)(nil)
