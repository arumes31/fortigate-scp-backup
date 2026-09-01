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
	conftailDatabaseName    = "fgt-conftail.db"
	conftailPollFirstDelay  = 10 * time.Second
	conftailSendFirstDelay  = 20 * time.Second
	conftailDeliveryCadence = time.Minute
	conftailPollTimeout     = 5 * time.Minute
	conftailDeliveryTimeout = 2 * time.Minute
	missingUserWindow       = 5 * time.Minute
)

// Extension owns the private ConfTail ledger, polling worker and dashboard.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	pgPool      *pgxpool.Pool
	ctx         context.Context
	store       *store
	graylog     *graylogClient
	hookwise    *hookwiseClient
	poller      *pollWorker
	tmpl        *template.Template
	currentUser func(*http.Request) string

	catalogMu  sync.RWMutex
	catalog    sourceCatalog
	pollMu     sync.Mutex
	deliveryMu sync.Mutex
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
	e.poller = &pollWorker{
		store:   store,
		graylog: graylog,
		loadCatalog: func(ctx context.Context) (sourceCatalog, error) {
			return loadSourceCatalog(ctx, deps.DB, deps.DataDir)
		},
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
	return nil
}

func (e *Extension) publishCatalog(catalog sourceCatalog) {
	e.catalogMu.Lock()
	e.catalog = catalog
	e.catalogMu.Unlock()
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
