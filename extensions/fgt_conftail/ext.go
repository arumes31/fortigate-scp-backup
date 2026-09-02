// Package fgtconftail groups FortiGate configuration-change events into
// per-firewall, per-administrator sessions and queues create-only Hookwise
// tickets after a session has been quiet for the configured idle period.
package fgtconftail

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
)

const (
	conftailPollJobID       = "fgt_conftail.poll"
	conftailDeliveryJobID   = "fgt_conftail.delivery"
	conftailCatalogJobID    = "fgt_conftail.catalog"
	conftailDatabaseName    = "fgt-conftail.db"
	conftailPollFirstDelay  = 10 * time.Second
	conftailSendFirstDelay  = 20 * time.Second
	conftailDeliveryCadence = time.Minute
	conftailCatalogCadence  = 30 * time.Second
	conftailCatalogDelay    = 5 * time.Second
	conftailPollTimeout     = 5 * time.Minute
	conftailDeliveryTimeout = 2 * time.Minute
	missingUserWindow       = 5 * time.Minute
)

// Extension owns the private ConfTail ledger, polling worker and dashboard.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	pgPool        *pgxpool.Pool
	ctx           context.Context
	store         *store
	graylog       *graylogClient
	hookwise      *hookwiseClient
	poller        *pollWorker
	tmpl          *template.Template
	currentUser   func(*http.Request) string
	catalogLoader func(context.Context) (sourceCatalog, error)

	catalogMu            sync.RWMutex
	catalog              sourceCatalog
	catalogFingerprint   string
	catalogLoadedAt      time.Time
	catalogLastFailureAt time.Time
	catalogLastError     string
	catalogRefreshMu     sync.Mutex
	pollMu               sync.Mutex
	deliveryMu           sync.Mutex
}

// New creates an unmounted ConfTail extension.
func New(cfg *config.Config, logger *slog.Logger) *Extension {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Extension{cfg: cfg, logger: logger}
}

func (e *Extension) Name() string { return "fgt_conftail" }

func (e *Extension) Prefix() string { return "/fgt-conftail" }

func (e *Extension) Enabled() bool { return e.cfg.ExtFgtConfTail }

// Mount initializes private storage, registers authenticated read-only routes,
// and schedules non-overlapping poll and delivery jobs on the host scheduler.
func (e *Extension) Mount(r chi.Router, deps extension.Deps) error {
	if deps.DB == nil {
		return errors.New("shared database is required")
	}
	if deps.LoginRequired == nil {
		return errors.New("login middleware is required")
	}
	if deps.Schedule == nil {
		return errors.New("scheduler is required")
	}
	if strings.TrimSpace(deps.DataDir) == "" {
		return errors.New("extension data directory is required")
	}

	tmpl, err := parseDashboardTemplate()
	if err != nil {
		return fmt.Errorf("parse conftail dashboard template: %w", err)
	}
	staticFS, err := dashboardStaticFS()
	if err != nil {
		return fmt.Errorf("open conftail dashboard assets: %w", err)
	}
	graylog, err := newGraylogClient(
		e.cfg.GraylogURL,
		e.cfg.GraylogToken,
		&http.Client{Timeout: 45 * time.Second},
	)
	if err != nil {
		return fmt.Errorf("initialize conftail Graylog client: %w", err)
	}
	hookwise, err := newHookwiseClient(
		e.cfg.FgtConfTailHookwiseURL,
		e.cfg.FgtConfTailHookwiseToken,
		&http.Client{Timeout: 30 * time.Second},
	)
	if err != nil {
		return fmt.Errorf("initialize conftail Hookwise client: %w", err)
	}

	activation := time.Now().UTC()
	storePath := filepath.Join(deps.DataDir, conftailDatabaseName)
	store, err := openStore(context.Background(), storePath, activation)
	if err != nil {
		return err
	}

	e.pgPool = deps.DB
	e.ctx = deps.Context
	if e.ctx == nil {
		e.ctx = context.Background()
	}
	e.store = store
	e.graylog = graylog
	e.hookwise = hookwise
	e.tmpl = tmpl
	e.currentUser = deps.CurrentUser
	e.catalogLoader = func(ctx context.Context) (sourceCatalog, error) {
		return loadSourceCatalog(ctx, deps.DB, deps.DataDir)
	}
	e.poller = &pollWorker{
		store:               store,
		logger:              e.logger,
		graylog:             graylog,
		loadCatalog:         e.catalogLoader,
		publishCatalog:      e.publishCatalog,
		query:               e.cfg.FgtConfTailGraylogQuery,
		overlap:             time.Duration(e.cfg.FgtConfTailOverlapSeconds) * time.Second,
		idle:                time.Duration(e.cfg.FgtConfTailIdleSeconds) * time.Second,
		maxDescriptionBytes: e.cfg.FgtConfTailTicketMaxBytes,
		missingUserWindow:   missingUserWindow,
	}

	r.Group(func(protected chi.Router) {
		protected.Use(deps.LoginRequired)
		protected.Get("/", e.dashboard)
		protected.Get("/chain/{chainID}", e.dashboardChain)
		protected.Get(
			"/static/*",
			http.StripPrefix("/fgt-conftail/static/", http.FileServer(http.FS(staticFS))).ServeHTTP,
		)
	})

	deps.Schedule(
		conftailPollJobID,
		time.Duration(e.cfg.FgtConfTailPollSeconds)*time.Second,
		conftailPollFirstDelay,
		e.runPoll,
	)
	deps.Schedule(
		conftailDeliveryJobID,
		conftailDeliveryCadence,
		conftailSendFirstDelay,
		e.runDeliveries,
	)
	if e.cfg.ExtAdmVpnConf {
		deps.Schedule(
			conftailCatalogJobID,
			conftailCatalogCadence,
			conftailCatalogDelay,
			e.runCatalogRefresh,
		)
	}
	if deps.RegisterHealth != nil {
		deps.RegisterHealth("conftail.graylog", e.graylogHealth)
		deps.RegisterHealth("conftail.catalog", e.catalogHealth)
		deps.RegisterHealth("conftail.store", e.storeHealth)
		deps.RegisterHealth("conftail.hookwise", e.hookwiseHealth)
	}
	return nil
}

func (e *Extension) graylogHealth(ctx context.Context) string {
	if e.store == nil {
		return "failed"
	}
	state, err := e.store.pollState(ctx)
	if err != nil {
		return "failed"
	}
	return dashboardPollHealth(
		state,
		time.Now().UTC(),
		e.dashboardPollInterval(),
	).State
}

func (e *Extension) catalogHealth(context.Context) string {
	e.catalogMu.RLock()
	defer e.catalogMu.RUnlock()
	if e.catalogLastError != "" &&
		(e.catalogLoadedAt.IsZero() || !e.catalogLastFailureAt.Before(e.catalogLoadedAt)) {
		return "failed"
	}
	if e.catalogLoadedAt.IsZero() {
		return "waiting"
	}
	if len(e.catalog.aliases) == 0 {
		return "degraded"
	}
	return "healthy"
}

func (e *Extension) storeHealth(ctx context.Context) string {
	if e.store == nil || e.store.db == nil || e.store.db.PingContext(ctx) != nil {
		return "failed"
	}
	return "healthy"
}

func (e *Extension) hookwiseHealth(ctx context.Context) string {
	if e.store == nil {
		return "failed"
	}
	counts, err := e.store.dashboardCounts(ctx)
	if err != nil {
		return "failed"
	}
	return dashboardDeliveryHealth(counts).State
}

func (e *Extension) publishCatalog(catalog sourceCatalog) {
	e.catalogMu.Lock()
	e.catalog = catalog
	e.catalogFingerprint = catalog.fingerprint()
	e.catalogLoadedAt = time.Now().UTC()
	e.catalogLastError = ""
	e.catalogMu.Unlock()
}

func (e *Extension) runCatalogRefresh() {
	e.catalogRefreshMu.Lock()
	defer e.catalogRefreshMu.Unlock()
	if e.catalogLoader == nil {
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	catalog, err := e.catalogLoader(ctx)
	if err != nil {
		now := time.Now().UTC()
		e.catalogMu.Lock()
		e.catalogLastFailureAt = now
		e.catalogLastError = sanitizeDeliveryError(err)
		e.catalogMu.Unlock()
		e.logger.Warn("conftail source catalog refresh failed", "err", sanitizeDeliveryError(err))
		return
	}
	newFingerprint := catalog.fingerprint()
	e.catalogMu.RLock()
	changed := newFingerprint != e.catalogFingerprint
	e.catalogMu.RUnlock()
	e.publishCatalog(catalog)
	if changed {
		e.logger.Info(
			"conftail source catalog refreshed",
			"firewalls", len(catalog.coverage()),
			"aliases", len(catalog.aliases),
			"warnings", len(catalog.warnings()),
		)
	}
}

func (e *Extension) runPoll() {
	e.pollMu.Lock()
	defer e.pollMu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, conftailPollTimeout)
	defer cancel()
	stats, err := e.poller.poll(ctx, time.Now().UTC())
	if err != nil {
		e.logger.Error("conftail poll failed", "err", sanitizeDeliveryError(err))
		return
	}
	e.logger.Info(
		"conftail poll completed",
		"pages", stats.Pages,
		"fetched", stats.Fetched,
		"quarantined", stats.Quarantined,
		"graylog_retries", stats.Retries,
		"skipped", stats.Skipped,
		"inserted", stats.Inserted,
		"duplicates", stats.Duplicates,
		"sealed", stats.Sealed,
	)

	pruneCtx, pruneCancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer pruneCancel()
	if deleted, pruneErr := e.store.prune(
		pruneCtx,
		time.Now().UTC(),
		e.cfg.FgtConfTailRetentionDays,
	); pruneErr != nil {
		e.logger.Error("conftail history prune failed", "err", pruneErr)
	} else if deleted > 0 {
		e.logger.Info("conftail history pruned", "deleted", deleted)
	}
	e.runDeliveries()
}

func (e *Extension) runDeliveries() {
	e.deliveryMu.Lock()
	defer e.deliveryMu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, conftailDeliveryTimeout)
	defer cancel()
	stats, err := dispatchDeliveries(ctx, e.store, e.hookwise, nil, nil)
	if err != nil {
		e.logger.Error("conftail delivery failed", "err", sanitizeDeliveryError(err))
		return
	}
	if stats.Accepted > 0 || stats.Failed > 0 {
		e.logger.Info(
			"conftail delivery completed",
			"accepted", stats.Accepted,
			"failed", stats.Failed,
		)
	}
}

var _ extension.Extension = (*Extension)(nil)
