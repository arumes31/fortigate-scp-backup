package fgt_polsplit

import (
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
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

// Extension is the policy split advisor. It is stateless: firewalls/backups
// come from the shared PostgreSQL database, traffic data from Graylog; only
// the shared activity log is written.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	pgPool  *pgxpool.Pool
	page    *webui.Renderer
	tz      *time.Location
	dataDir string
	cipher  *crypto.Cipher

	logActivity func(username, action, details string)
	currentUser func(*http.Request) string
	broadcastOp func(kind string, fwID int, status string)
	pageBase    extension.PageBaseProvider

	// Live progress of running analyses, polled by the UI (see progress.go).
	progressMu   sync.Mutex
	progressByID map[string]*progressState
}

// broadcast publishes an operation lifecycle event to the core SSE stream
// (no-op when the host did not wire the hook).
func (e *Extension) broadcast(kind string, fwID int, status string) {
	if e.broadcastOp != nil {
		e.broadcastOp(kind, fwID, status)
	}
}

func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}

func (e *Extension) Name() string { return "fgt_polsplit" }

func (e *Extension) Prefix() string { return "/fgt-polsplit" }

func (e *Extension) Enabled() bool { return e.cfg.ExtFgtPolSplit }

func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	if d.PageBase == nil {
		return errors.New("fgt_polsplit: shared page context is required")
	}
	if d.Cipher == nil {
		return errors.New("fgt_polsplit: shared cipher is required")
	}
	e.logActivity = d.LogActivity
	e.currentUser = d.CurrentUser
	e.broadcastOp = d.BroadcastOp
	e.pageBase = d.PageBase
	e.tz = d.TZ
	e.pgPool = d.DB
	e.dataDir = d.DataDir
	e.cipher = d.Cipher
	if e.tz == nil {
		e.tz = time.UTC
	}

	if err := e.parseTemplates(); err != nil {
		return err
	}

	e.progressByID = map[string]*progressState{}
	liveExt.Store(e) // publish for the core dashboard's running-queries card

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

func (e *Extension) parseTemplates() error {
	page, err := webui.ParsePage(extensionFS, "templates/fgt_polsplit_index.html", nil)
	if err != nil {
		return err
	}
	e.page = page
	return nil
}

var _ extension.Extension = (*Extension)(nil)
