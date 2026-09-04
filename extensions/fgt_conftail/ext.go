// Package fgtconftail groups FortiGate configuration-change events into
// per-firewall, per-administrator sessions and queues create-only Hookwise
// tickets after a session has been quiet for the configured idle period.
package fgtconftail

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

const (
	conftailPollJobID          = "fgt_conftail.poll"
	conftailDeliveryJobID      = "fgt_conftail.delivery"
	conftailCatalogJobID       = "fgt_conftail.catalog"
	conftailMaintenanceJobID   = "fgt_conftail.maintenance"
	conftailDatabaseName       = "fgt-conftail.db"
	conftailPollFirstDelay     = 10 * time.Second
	conftailSendFirstDelay     = 20 * time.Second
	conftailDeliveryCadence    = time.Minute
	conftailCatalogCadence     = 30 * time.Second
	conftailCatalogDelay       = 5 * time.Second
	conftailMaintenanceCadence = 24 * time.Hour
	conftailMaintenanceDelay   = time.Hour
	conftailMaintenanceCron    = "30 3 * * *"
	conftailPollTimeout        = 5 * time.Minute
	conftailDeliveryTimeout    = 2 * time.Minute
	missingUserWindow          = 5 * time.Minute
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
	indexPage     *webui.Renderer
	chainPage     *webui.Renderer
	currentUser   func(*http.Request) string
	logActivity   func(username, action, details string)
	pageBase      extension.PageBaseProvider
	catalogLoader func(context.Context) (sourceCatalog, error)
	exportLimits  sessionExportLimits

	catalogMu            sync.RWMutex
	catalog              sourceCatalog
	catalogFingerprint   string
	catalogLoadedAt      time.Time
	catalogLastFailureAt time.Time
	catalogLastError     string
	catalogRefreshMu     sync.Mutex
	pollMu               sync.Mutex
	deliveryMu           sync.Mutex
	operationMu          sync.RWMutex
	tz                   *time.Location
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

// Mount initializes private storage, registers authenticated dashboard and
// global-ignore routes, and schedules non-overlapping poll and delivery jobs.
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
	if deps.PageBase == nil {
		return errors.New("shared page context is required")
	}

	indexPage, chainPage, err := parseDashboardPages()
	if err != nil {
		return fmt.Errorf("parse conftail dashboard pages: %w", err)
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
	e.indexPage = indexPage
	e.chainPage = chainPage
	e.currentUser = deps.CurrentUser
	e.logActivity = deps.LogActivity
	e.pageBase = deps.PageBase
	e.tz = deps.TZ
	if e.tz == nil {
		e.tz = time.UTC
	}
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
		protected.Post("/", e.dashboard)
		protected.Get("/status", e.dashboardStatus)
		protected.Get("/chain/{chainID}", e.dashboardChain)
		protected.Get("/chain/{chainID}/export/{format}", e.exportSession)
		protected.Post("/ignore-rules", e.createGlobalIgnoreRule)
		protected.Post("/ignore-rules/{ruleID}/toggle", e.toggleGlobalIgnoreRule)
		protected.Post("/ignore-rules/{ruleID}/delete", e.deleteGlobalIgnoreRule)
		protected.Get(
			"/static/*",
			http.StripPrefix("/fgt-conftail/static/", http.FileServer(http.FS(staticFS))).ServeHTTP,
		)
	})

	deps.Schedule(
		conftailPollJobID,
		adaptivePollActiveInterval,
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
	if deps.ScheduleCron != nil {
		if err := deps.ScheduleCron(conftailMaintenanceJobID, conftailMaintenanceCron, e.runMaintenance); err != nil {
			return fmt.Errorf("schedule conftail maintenance: %w", err)
		}
	} else {
		deps.Schedule(
			conftailMaintenanceJobID,
			conftailMaintenanceCadence,
			conftailMaintenanceDelay,
			e.runMaintenance,
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
	now := time.Now().UTC()
	return dashboardPollHealth(state, now, adaptivePollInterval(state, state.LastIngestedAt, now)).State
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
	return dashboardDeliveryHealth(counts, time.Now().UTC()).State
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
	if !e.operationMu.TryRLock() {
		e.logger.Debug("conftail catalog refresh deferred for maintenance", "code", codeMaintenanceSkipped)
		return
	}
	defer e.operationMu.RUnlock()
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
		e.logger.Warn("conftail source catalog refresh failed", "code", codeCatalogRefreshFailed, "err", sanitizeDeliveryError(err))
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
	if !e.operationMu.TryRLock() {
		e.logger.Debug("conftail poll deferred for maintenance", "code", codeMaintenanceSkipped)
		return
	}
	defer e.operationMu.RUnlock()
	e.pollMu.Lock()
	defer e.pollMu.Unlock()
	now := time.Now().UTC()
	state, lastIngestedAt, err := e.store.pollScheduleState(e.ctx)
	if err != nil {
		e.logger.Error(
			"conftail adaptive poll state failed",
			"code", codeAdaptivePollStateFailed,
			"err", sanitizeDeliveryError(err),
		)
		return
	}
	if !adaptivePollDue(state, lastIngestedAt, now) {
		e.logger.Debug(
			"conftail poll deferred",
			"code", codeGraylogPollDeferred,
			"next_poll_at", state.LastStartedAt.Add(adaptivePollInterval(state, lastIngestedAt, now)),
		)
		return
	}
	ctx, cancel := context.WithTimeout(e.ctx, conftailPollTimeout)
	defer cancel()
	stats, err := e.poller.poll(ctx, now)
	if err != nil {
		e.logger.Error(
			"conftail poll failed",
			"code", codeGraylogPollFailed,
			"err", sanitizeDeliveryError(err),
		)
		return
	}
	e.logger.Info(
		"conftail poll completed",
		"code", codeGraylogPollCompleted,
		"pages", stats.Pages,
		"fetched", stats.Fetched,
		"quarantined", stats.Quarantined,
		"graylog_retries", stats.Retries,
		"skipped", stats.Skipped,
		"inserted", stats.Inserted,
		"duplicates", stats.Duplicates,
		"ignored", stats.Ignored,
		"sealed", stats.Sealed,
	)

	pruneCtx, pruneCancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer pruneCancel()
	if deleted, pruneErr := e.store.prune(
		pruneCtx,
		time.Now().UTC(),
		e.cfg.FgtConfTailRetentionDays,
	); pruneErr != nil {
		e.logger.Error("conftail history prune failed", "code", codeMaintenanceFailed, "err", pruneErr)
	} else if deleted > 0 {
		e.logger.Info("conftail history pruned", "deleted", deleted)
	}
	e.runDeliveries()
}

func (e *Extension) runDeliveries() {
	if !e.operationMu.TryRLock() {
		e.logger.Debug("conftail delivery deferred for maintenance", "code", codeMaintenanceSkipped)
		return
	}
	defer e.operationMu.RUnlock()
	e.deliveryMu.Lock()
	defer e.deliveryMu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, conftailDeliveryTimeout)
	defer cancel()
	stats, err := dispatchDeliveries(ctx, e.store, e.hookwise, nil, nil)
	if err != nil {
		e.logger.Error("conftail delivery failed", "code", codeHookwiseDeliveryFailed, "err", sanitizeDeliveryError(err))
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

func (e *Extension) runMaintenance() {
	if e.store == nil || !e.operationMu.TryLock() {
		e.logger.Debug("conftail database maintenance skipped while work is active", "code", codeMaintenanceSkipped)
		return
	}
	defer e.operationMu.Unlock()
	baseContext := e.ctx
	if baseContext == nil {
		baseContext = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseContext, conftailPollTimeout)
	defer cancel()
	tz := e.tz
	if tz == nil {
		tz = time.UTC
	}
	now := time.Now().In(tz)
	stats, err := e.store.maintenanceStats(ctx)
	if err != nil {
		e.logger.Error("conftail database maintenance stats failed", "code", codeMaintenanceFailed, "err", err)
		return
	}
	retired, err := e.store.retireManagedIndexes(ctx, now)
	if err != nil {
		e.logger.Error("conftail managed index retirement failed", "code", codeIndexMaintenanceFailed, "err", err)
		return
	}
	mode := "none"
	if shouldRunFullVacuum(now, stats) {
		if err := e.store.fullVacuum(ctx); err != nil {
			e.logger.Error("conftail full vacuum failed", "code", codeMaintenanceFailed, "err", err)
			return
		}
		mode = "full"
	} else if stats.AutoVacuum == 2 && stats.FreelistCount > 0 {
		if err := e.store.incrementalVacuum(ctx); err != nil {
			e.logger.Error("conftail incremental vacuum failed", "code", codeMaintenanceFailed, "err", err)
			return
		}
		mode = "incremental"
	}
	e.logger.Info(
		"conftail database maintenance completed",
		"code", codeMaintenanceCompleted,
		"vacuum", mode,
		"managed_indexes_retired", retired,
		"page_count", stats.PageCount,
		"freelist_count", stats.FreelistCount,
	)
}

var _ extension.Extension = (*Extension)(nil)
