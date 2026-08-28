// Package web wires the HTTP layer for the main application: the chi router,
// the embedded template engine (one shared design system) and static assets.
// Handlers live in handlers.go.
package web

import (
	"bytes"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/arumes31/fortigate-scp-backup/internal/backup"
	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/scheduler"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
	"golang.org/x/crypto/ssh"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

func init() {
	// The embedded static FileServer picks Content-Type by extension. Register
	// the self-hosted font types explicitly so they are served correctly on every
	// platform (Go's built-in table / the OS registry may not include them).
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".woff", "font/woff")
}

// Authenticator is the subset of internal/auth used by the login handler.
type Authenticator interface {
	VerifyRadius(username, password string) bool
	VerifyTOTP(secret, code string) bool
}

// BaseData carries the shared layout fields every page embeds as `.Base`.
type BaseData struct {
	Title                 string
	Username              string
	ExtEnabled            bool
	ExtFgtConfGenEnabled  bool
	ExtFgtPolSplitEnabled bool
	ExtFgtConfConvEnabled bool
	IsRadius              bool   // RADIUS users cannot change their password locally
	Lang                  string // UI language: "en" (default) or "de"
	Active                string // nav key: firewalls|search|activity|admvpn|password
}

// Server holds the dependencies shared by every handler.
type Server struct {
	cfg     *config.Config
	store   Store
	sched   *scheduler.Scheduler
	backup  *backup.Service
	sess    *session.Manager
	auth    Authenticator
	cipher  *crypto.Cipher
	limiter *loginLimiter
	// ipLimiter is a per-source-IP aggregate guard so a password-spray across
	// many usernames from one host is throttled even though each (IP,username)
	// bucket in limiter never reaches its own threshold.
	ipLimiter       *loginLimiter
	hub             *sseHub
	logger          *slog.Logger
	hostKeyCallback ssh.HostKeyCallback

	pages map[string]pageTmpl

	// Insights SQLite handle (audit cache, custom rules, exemptions,
	// topology shares), opened lazily per Server. See insightsDB().
	insightsMu sync.Mutex
	insights   *sql.DB

	// warmSem bounds concurrent audit-cache warms (full config parses) so a
	// fleet-wide backup burst cannot pile up dozens of parses at once.
	warmSem chan struct{}

	// auditRuns tracks in-flight audit recomputations (full config parses)
	// for the dashboard's "currently running" card.
	auditRuns runningTracker

	// licenseInFlight coalesces concurrent license fetches per firewall
	// (daily sweep vs manual refresh), keyed by firewall ID.
	licenseInFlight sync.Map

	// Fleet-sweep progress for the Licenses and IPAM pages (polled by their
	// JS); begin() on each also coalesces concurrent sweeps.
	licenseProgress sweepProgress
	ipamProgress    sweepProgress
}

// SetHostKeyCallback configures the verified host-key policy used by live SSH
// collectors. It must be called before a collection is started.
func (s *Server) SetHostKeyCallback(callback ssh.HostKeyCallback) {
	s.hostKeyCallback = callback
}

type pageTmpl struct {
	t    *template.Template
	exec string // template name to execute ("base" for content pages)
}

// BackupJobID is the scheduler job id for a firewall. main.go and the handlers
// both use this so add/remove/rebuild stay consistent.
func BackupJobID(fwID int) string { return fmt.Sprintf("backup_firewall_%d", fwID) }

// New builds the Server and parses all templates.
func New(cfg *config.Config, store Store, sched *scheduler.Scheduler,
	backupSvc *backup.Service, sess *session.Manager, auth Authenticator, cipher *crypto.Cipher, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg: cfg, store: store, sched: sched, backup: backupSvc,
		sess: sess, auth: auth, cipher: cipher, logger: logger,
		limiter:   newLoginLimiter(cfg.LoginMaxAttempts, time.Duration(cfg.LoginLockoutMinutes)*time.Minute),
		ipLimiter: newLoginLimiter(cfg.LoginMaxAttempts*4, time.Duration(cfg.LoginLockoutMinutes)*time.Minute),
		hub:       newSSEHub(),
		warmSem:   make(chan struct{}, 2),
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	if cfg.CVEAutoUpdate {
		interval := time.Duration(cfg.CVERefreshHours) * time.Hour
		if interval <= 0 {
			interval = 24 * time.Hour
		}
		sched.Schedule("cve-refresh", interval, 30*time.Second, s.refreshCVECacheJob)
	}
	// License/entitlement data changes rarely; one fleet sweep per day keeps
	// the inventory and the dashboard expiry card fresh without SSH churn.
	sched.Schedule("license-refresh", 24*time.Hour, 2*time.Minute, s.refreshLicensesJob)
	// IPAM aggregates from cached audit parses; the daily recompute (plus the
	// on-demand button) keeps the stored snapshot at most a day old without
	// ever parsing configs inside a page request.
	sched.Schedule("ipam-refresh", 24*time.Hour, 5*time.Minute, s.refreshIPAM)
	return s, nil
}

// BroadcastStatus pushes a firewall status change to any connected SSE clients.
// On a successful backup it also pre-warms the audit cache in the background so
// the audit and topology pages stay instant.
func (s *Server) BroadcastStatus(fwID int, status string) {
	s.hub.broadcast("backup", fwID, status)
	if status == "Success" {
		go s.WarmAuditCache(fwID)
	}
}

// BroadcastOp pushes an operation lifecycle event (kind: "analysis",
// "devicedata", "sshdiag", "audit", "live"; status: "started"/"finished") to
// connected SSE clients. The dashboard prints these to the SYS_STDOUT panel
// and refreshes the currently-running card; extensions publish through the
// extension.Deps.BroadcastOp hook.
func (s *Server) BroadcastOp(kind string, fwID int, status string) {
	s.hub.broadcast(kind, fwID, status)
}

// Shutdown releases resources that would otherwise keep the process alive
// during a graceful stop. It signals SSE streams to end so http.Server.Shutdown
// (which does not cancel their request contexts) can complete promptly.
func (s *Server) Shutdown() {
	s.hub.shutdown()
	s.limiter.Close()
	s.ipLimiter.Close()
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
	"fmtTime":   fmtTime,
	"fmtBytes":  fmtBytes,
	"T":         tr,
	"i18nJSON":  i18nJSON,
	"isZero":    func(t time.Time) bool { return t.IsZero() },
}

// fmtTime renders a timestamp for display, or "—" when zero.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// fmtBytes renders a byte count in human units.
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
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
		Title:                 title,
		Username:              d.Username,
		ExtEnabled:            s.cfg.ExtAdmVpnConf,
		ExtFgtConfGenEnabled:  s.cfg.ExtFgtConfGen,
		ExtFgtPolSplitEnabled: s.cfg.ExtFgtPolSplit,
		ExtFgtConfConvEnabled: s.cfg.ExtFgtConfConv,
		IsRadius:              d.IsRadiusUser,
		Lang:                  langFromRequest(r),
		Active:                active,
	}
}

// Routes builds the main router. Extensions are mounted by the caller.
func (s *Server) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.accessLog)
	r.Use(middleware.Recoverer)
	// gzip/deflate for HTML/JSON/JS/CSS: the fleet-sized JSON payloads (IPAM
	// snapshot, topology data) compress ~10×. SSE is unaffected — chi only
	// compresses its default content types, which exclude text/event-stream.
	r.Use(middleware.Compress(5))
	r.Use(securityHeaders(s.cfg.EnableHSTS))

	r.NotFound(s.handleNotFound)
	r.MethodNotAllowed(s.handleMethodNotAllowed)

	// Static assets.
	staticSub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Public / unauthenticated.
	r.HandleFunc("/login", s.handleLogin)
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	// Shared topology views: access is granted by an unguessable token.
	r.Get("/topology/shared/{token}", s.handleTopologyShared)
	r.Get("/topology/shared/{token}/data", s.handleTopologySharedData)
	r.Get("/topology/shared/{token}/devices", s.handleTopologySharedDevices)

	// Authenticated.
	r.Group(func(pr chi.Router) {
		pr.Use(s.sess.LoginRequired)
		// State-changing actions are POST-only so they cannot be triggered by a
		// plain GET navigation/prefetch/<img> (SameSite=Lax then blocks the
		// cross-site POST). The templates submit these via forms.
		pr.Post("/logout", s.handleLogout)
		pr.Post("/lang", s.handleSetLang)
		pr.HandleFunc("/", s.handleIndex)
		pr.Get("/dashboard", s.handleDashboard)
		pr.Get("/dashboard/stats", s.handleDashboardStats)
		pr.Post("/backup_now_all_failed", s.handleRetryAllFailed)
		pr.Get("/audit", s.handleAudit)
		pr.Get("/audit/results/{fwID}", s.handleAuditResults)
		pr.HandleFunc("/audit/exemption", s.handleAuditExemption)
		pr.HandleFunc("/audit/custom_rule", s.handleAuditCustomRule)
		pr.HandleFunc("/audit/cve_refresh", s.handleAuditCVERefresh)
		pr.HandleFunc("/audit/ticket", s.handleAuditTicket)
		pr.Get("/licenses", s.handleLicenses)
		pr.Get("/licenses/status", s.handleLicenseStatus)
		pr.Post("/licenses/refresh/{fwID}", s.handleLicenseRefresh)
		pr.Post("/licenses/refresh_all", s.handleLicenseRefreshAll)
		pr.Get("/ipam", s.handleIPAM)
		pr.Get("/ipam/data", s.handleIPAMData)
		pr.Post("/ipam/refresh", s.handleIPAMRefresh)
		pr.Get("/topology", s.handleTopology)
		pr.Get("/topology/data/{fwID}", s.handleTopologyData)
		pr.Post("/topology/share", s.handleTopologyShareCreate)
		pr.Get("/topology/shares", s.handleTopologyShareList)
		pr.Post("/topology/share/revoke", s.handleTopologyShareRevoke)
		pr.Get("/download_bundle", s.handleDownloadBundle)
		pr.Get("/backups/{fwID}", s.handleListBackups)
		pr.Get("/download/*", s.handleDownload)
		pr.Post("/delete/{fwID}", s.handleDeleteFirewall)
		pr.Get("/errors", s.handleErrors)
		pr.Post("/backup_now/{fwID}", s.handleBackupNow)
		pr.Get("/test_connection/{fwID}", s.handleTestConnection)
		pr.HandleFunc("/change_password", s.handleChangePassword)
		pr.HandleFunc("/search", s.handleSearch)
		pr.Get("/activity_log", s.handleActivityLog)
		pr.Get("/events", s.handleEvents)
	})

	return r
}
