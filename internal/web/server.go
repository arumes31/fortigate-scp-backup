// Package web wires the HTTP layer for the main application: the chi router,
// the embedded template engine (one shared design system) and static assets.
// Handlers live in handlers.go.
package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/arumes31/fortigate-scp-backup/internal/backup"
	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/scheduler"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Authenticator is the subset of internal/auth used by the login handler.
type Authenticator interface {
	VerifyRadius(username, password string) bool
	VerifyTOTP(secret, code string) bool
}

// BaseData carries the shared layout fields every page embeds as `.Base`.
type BaseData struct {
	Title      string
	Username   string
	ExtEnabled bool
	Active     string // nav key: firewalls|search|activity|admvpn|password
}

// Server holds the dependencies shared by every handler.
type Server struct {
	cfg    *config.Config
	store  *database.Store
	sched  *scheduler.Scheduler
	backup *backup.Service
	sess   *session.Manager
	auth   Authenticator
	logger *slog.Logger

	pages map[string]pageTmpl
}

type pageTmpl struct {
	t    *template.Template
	exec string // template name to execute ("base" for content pages)
}

// BackupJobID is the scheduler job id for a firewall. main.go and the handlers
// both use this so add/remove/rebuild stay consistent.
func BackupJobID(fwID int) string { return fmt.Sprintf("backup_firewall_%d", fwID) }

// New builds the Server and parses all templates.
func New(cfg *config.Config, store *database.Store, sched *scheduler.Scheduler,
	backupSvc *backup.Service, sess *session.Manager, auth Authenticator, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg: cfg, store: store, sched: sched, backup: backupSvc,
		sess: sess, auth: auth, logger: logger,
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

var funcMap = template.FuncMap{
	"hasPrefix": strings.HasPrefix,
	"hasSuffix": strings.HasSuffix,
	"contains":  strings.Contains,
	"lower":     strings.ToLower,
	"upper":     strings.ToUpper,
	"trim":      strings.TrimSpace,
	"add":       func(a, b int) int { return a + b },
	"sub":       func(a, b int) int { return a - b },
}

func (s *Server) parseTemplates() error {
	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		return err
	}
	base, err := templatesFS.ReadFile("templates/base.html")
	if err != nil {
		return err
	}
	pages := make(map[string]pageTmpl)
	for _, e := range entries {
		name := e.Name()
		if name == "base.html" {
			continue
		}
		content, err := templatesFS.ReadFile("templates/" + name)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), `{{define "content"}}`) {
			t := template.New("layout").Funcs(funcMap)
			if _, err := t.Parse(string(base)); err != nil {
				return err
			}
			if _, err := t.Parse(string(content)); err != nil {
				return err
			}
			pages[name] = pageTmpl{t: t, exec: "base"}
		} else {
			t := template.New(name).Funcs(funcMap)
			if _, err := t.Parse(string(content)); err != nil {
				return err
			}
			pages[name] = pageTmpl{t: t, exec: name}
		}
	}
	s.pages = pages
	return nil
}

// render executes a named page template into a buffer, then flushes it.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	p, ok := s.pages[name]
	if !ok {
		s.logger.Error("template not found", "name", name)
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := p.t.ExecuteTemplate(&buf, p.exec, data); err != nil {
		s.logger.Error("template render failed", "name", name, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// base builds the shared layout data for the current request.
func (s *Server) base(r *http.Request, title, active string) BaseData {
	d := s.sess.User(r)
	return BaseData{
		Title:      title,
		Username:   d.Username,
		ExtEnabled: s.cfg.ExtAdmVpnConf,
		Active:     active,
	}
}

// Routes builds the main router. Extensions are mounted by the caller.
func (s *Server) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// Static assets.
	staticSub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Public.
	r.HandleFunc("/login", s.handleLogin)

	// Authenticated.
	r.Group(func(pr chi.Router) {
		pr.Use(s.sess.LoginRequired)
		pr.Get("/logout", s.handleLogout)
		pr.HandleFunc("/", s.handleIndex)
		pr.Get("/backups/{fwID}", s.handleListBackups)
		pr.Get("/download/*", s.handleDownload)
		pr.Get("/delete/{fwID}", s.handleDeleteFirewall)
		pr.Get("/errors", s.handleErrors)
		pr.Get("/backup_now/{fwID}", s.handleBackupNow)
		pr.HandleFunc("/change_password", s.handleChangePassword)
		pr.HandleFunc("/search", s.handleSearch)
		pr.Get("/activity_log", s.handleActivityLog)
	})

	return r
}
