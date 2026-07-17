package fgt_polsplit

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
)

//go:embed templates/* static/*
var extensionFS embed.FS

// Extension is the policy split advisor. It is stateless: firewalls/backups
// come from the shared PostgreSQL database, traffic data from Graylog; only
// the shared activity log is written.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	pgPool  *pgxpool.Pool
	tmpl    *template.Template
	tz      *time.Location
	dataDir string

	logActivity func(username, action, details string)
	currentUser func(*http.Request) string

	// Live progress of running analyses, polled by the UI (see progress.go).
	progressMu   sync.Mutex
	progressByID map[string]*progressState
}

func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}

func (e *Extension) Name() string { return "fgt_polsplit" }

func (e *Extension) Prefix() string { return "/fgt-polsplit" }

func (e *Extension) Enabled() bool { return e.cfg.ExtFgtPolSplit }

func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	e.logActivity = d.LogActivity
	e.currentUser = d.CurrentUser
	e.tz = d.TZ
	e.pgPool = d.DB
	e.dataDir = d.DataDir
	if e.tz == nil {
		e.tz = time.UTC
	}

	t, err := template.New("").ParseFS(extensionFS, "templates/*.html")
	if err != nil {
		return err
	}
	e.tmpl = t

	e.progressByID = map[string]*progressState{}

	r.Group(func(pr chi.Router) {
		pr.Use(d.LoginRequired)
		pr.Get("/", e.index)
		pr.Get("/list_firewalls", e.listFirewalls)
		pr.Get("/policy_info", e.policyInfo)
		pr.Post("/analyze", e.analyze)
		pr.Get("/progress", e.progressHandler)
	})

	staticSub, err := fs.Sub(extensionFS, "static")
	if err != nil {
		return err
	}
	r.Handle("/static/*", http.StripPrefix("/fgt-polsplit/static/", http.FileServer(http.FS(staticSub))))

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

type baseData struct {
	Title               string
	Username            string
	ExtEnabled          bool
	ExtConfigGenEnabled bool
	ExtPolSplitEnabled  bool
	Lang                string
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
		Lang:                "en",
		Active:              active,
	}
}

var _ extension.Extension = (*Extension)(nil)
