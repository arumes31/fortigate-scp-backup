// Package extension defines the contract every optional module implements and a
// tiny registry to mount the enabled ones. This keeps features like the VPN
// config module self-contained and conditionally loaded, exactly like the old
// Flask blueprints.
package extension

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Deps is the set of shared services an extension may use. Extensions get the
// shared activity logger and auth middleware but own any private storage.
type Deps struct {
	// DB is the shared PostgreSQL pool (rarely needed; most extensions only log).
	DB *pgxpool.Pool
	// LogActivity writes to the shared activity_logs table.
	LogActivity func(username, action, details string)
	// LoginRequired guards authenticated routes with the same session rules.
	LoginRequired func(http.Handler) http.Handler
	// CurrentUser returns the logged-in username for a request (empty if none).
	CurrentUser func(*http.Request) string
	// Logger is the process logger.
	Logger *slog.Logger
	// TZ is the configured timezone.
	TZ *time.Location
	// DataDir is where an extension may keep its private database/files.
	DataDir string
}

// Extension is a self-contained, conditionally-loaded feature module.
type Extension interface {
	// Name is a short identifier used in logs.
	Name() string
	// Prefix is the URL mount point, e.g. "/fgt-adm-vpn-conf".
	Prefix() string
	// Enabled reports whether this extension should be mounted.
	Enabled() bool
	// Mount registers routes on r and starts any background workers.
	Mount(r chi.Router, d Deps) error
}

// Registry holds the known extensions.
type Registry struct {
	exts []Extension
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds an extension (mounted later only if Enabled reports true).
func (reg *Registry) Register(e Extension) { reg.exts = append(reg.exts, e) }

// MountEnabled mounts every enabled extension under its prefix.
func (reg *Registry) MountEnabled(r chi.Router, d Deps) {
	for _, e := range reg.exts {
		if !e.Enabled() {
			d.Logger.Info("extension disabled, not mounting", "name", e.Name())
			continue
		}
		sub := chi.NewRouter()
		if err := e.Mount(sub, d); err != nil {
			d.Logger.Error("failed to mount extension", "name", e.Name(), "err", err)
			continue
		}
		r.Mount(e.Prefix(), sub)
		d.Logger.Info("extension mounted", "name", e.Name(), "prefix", e.Prefix())
	}
}
