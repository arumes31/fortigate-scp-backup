// Package extension defines the contract every optional module implements and a
// tiny registry to mount the enabled ones. This keeps features like the VPN
// config module self-contained and conditionally loaded, exactly like the old
// Flask blueprints.
package extension

import (
	"context"
	"fmt"
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
	// FirewallCreds returns a firewall's SSH connection details with the password
	// decrypted, for extensions that reach the device directly (e.g. live CLI
	// diagnostics). nil when the host did not wire it.
	FirewallCreds func(ctx context.Context, fwID int) (host, user, pass string, port int, err error)
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

// MountEnabled mounts every enabled extension under its prefix. It returns an
// error if any enabled extension fails to mount, so startup can fail loudly
// rather than silently running without a feature the operator turned on.
func (reg *Registry) MountEnabled(r chi.Router, d Deps) error {
	for _, e := range reg.exts {
		if !e.Enabled() {
			d.Logger.Info("extension disabled, not mounting", "name", e.Name())
			continue
		}
		sub := chi.NewRouter()
		if err := e.Mount(sub, d); err != nil {
			return fmt.Errorf("mount extension %q: %w", e.Name(), err)
		}
		r.Mount(e.Prefix(), sub)
		d.Logger.Info("extension mounted", "name", e.Name(), "prefix", e.Prefix())
	}
	return nil
}
