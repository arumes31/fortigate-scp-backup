// Package fgt_confconv implements the Configuration Conversions extension:
// pick a firewall, select one or more structural migration recipes (e.g.
// interfaces -> FortiLink, WAN interfaces -> SD-WAN), and get back a
// reviewable CLI script. See docs/plans/2026-07-22-fgt-confconv-design.md.
package fgt_confconv

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
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
	tmpl   *template.Template
	tz     *time.Location

	logActivity func(username, action, details string)
	currentUser func(*http.Request) string
}

func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}

func (e *Extension) Name() string { return "fgt_confconv" }

func (e *Extension) Prefix() string { return "/fgt-confconv" }

func (e *Extension) Enabled() bool { return e.cfg.ExtFgtConfConv }

func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	e.logActivity = d.LogActivity
	e.currentUser = d.CurrentUser
	e.tz = d.TZ
	e.pgPool = d.DB
	if e.tz == nil {
		e.tz = time.UTC
	}

	t, err := template.New("").ParseFS(extensionFS, "templates/*.html")
	if err != nil {
		return err
	}
	e.tmpl = t

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

// baseData carries the fields the shared topbar nav needs — every known
// extension's enablement flag, the same shape read via .Base in the sibling
// extension templates.
type baseData struct {
	Title               string
	Username            string
	ExtEnabled          bool
	ExtConfigGenEnabled bool
	ExtPolSplitEnabled  bool
	ExtConfConvEnabled  bool
	Active              string
}

func (e *Extension) baseData(r *http.Request, title, active string) baseData {
	username := ""
	if e.currentUser != nil {
		username = e.currentUser(r)
	}
	return baseData{
		Title:               title,
		Username:            username,
		ExtEnabled:          e.cfg.ExtAdmVpnConf,
		ExtConfigGenEnabled: e.cfg.ExtFgtConfGen,
		ExtPolSplitEnabled:  e.cfg.ExtFgtPolSplit,
		ExtConfConvEnabled:  e.cfg.ExtFgtConfConv,
		Active:              active,
	}
}

var _ extension.Extension = (*Extension)(nil)
