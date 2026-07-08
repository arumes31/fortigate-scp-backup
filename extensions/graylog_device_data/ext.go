// Package graylogdevicedata is the self-contained "Graylog device data"
// extension. For every firewall whose latest audited configuration manages
// FortiSwitches, it fetches the client devices seen in the firewall's Graylog
// logs (MAC, IP, VLAN, switch port), stores them in a private SQLite database
// and serves them to the topology page, which renders the devices under their
// switch and highlights MAC/IP sharing. A background worker refreshes the
// inventory on an interval (default hourly); the topology page can also
// trigger an immediate fetch for the firewall being viewed.
//
// Mounted at /graylog-devices when EXT_GRAYLOG_DEVICE_DATA=true.
package graylogdevicedata

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
)

// Extension implements extension.Extension.
type Extension struct {
	cfg    *config.Config
	logger *slog.Logger

	db      *sql.DB       // private device inventory
	pool    *pgxpool.Pool // shared store: firewall list (read-only)
	dataDir string        // to read the core insights DB (audit cache)

	logActivity func(username, action, details string)
	currentUser func(r *http.Request) string
}

// New constructs the extension (not yet enabled/mounted).
func New(cfg *config.Config, logger *slog.Logger) *Extension {
	return &Extension{cfg: cfg, logger: logger}
}

// Name identifies the extension in logs.
func (e *Extension) Name() string { return "graylog_device_data" }

// Prefix is the URL mount point.
func (e *Extension) Prefix() string { return "/graylog-devices" }

// Enabled reports whether EXT_GRAYLOG_DEVICE_DATA is set.
func (e *Extension) Enabled() bool { return e.cfg.ExtGraylogDeviceData }

// Mount opens the private database, registers routes and starts the
// background refresh worker.
func (e *Extension) Mount(r chi.Router, d extension.Deps) error {
	e.logActivity = d.LogActivity
	e.currentUser = d.CurrentUser
	e.pool = d.DB
	e.dataDir = d.DataDir

	if err := os.MkdirAll(d.DataDir, 0o700); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", filepath.Join(d.DataDir, "graylog-device-data.db"))
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		createTableSQL,
	} {
		if _, execErr := db.Exec(q); execErr != nil {
			_ = db.Close()
			return execErr
		}
	}
	e.db = db

	// Authenticated JSON API consumed by the topology page.
	r.Group(func(pr chi.Router) {
		pr.Use(d.LoginRequired)
		pr.Get("/data/{fwID}", e.handleData)
		pr.Post("/refresh/{fwID}", e.handleRefresh)
	})

	go e.worker()
	return nil
}

const createTableSQL = `CREATE TABLE IF NOT EXISTS devices (
	fw_id     INTEGER NOT NULL,
	mac       TEXT NOT NULL,
	ip        TEXT NOT NULL DEFAULT '',
	vlan      TEXT NOT NULL DEFAULT '',
	port      TEXT NOT NULL DEFAULT '',
	switch_id TEXT NOT NULL DEFAULT '',
	hostname  TEXT NOT NULL DEFAULT '',
	last_seen TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY (fw_id, mac, ip)
)`

// worker refreshes the device inventory for every switch-managing firewall on
// the configured interval, staggering firewalls across the sweep.
func (e *Extension) worker() {
	time.Sleep(15 * time.Second) // let the app finish booting
	interval := time.Duration(e.cfg.GraylogDeviceInterval) * time.Second
	if interval < time.Minute {
		interval = time.Hour
	}
	for {
		fws, err := e.switchFirewalls()
		if err != nil {
			e.logger.Error("graylog device worker: listing firewalls failed", "err", err)
			time.Sleep(time.Minute)
			continue
		}
		if len(fws) == 0 {
			time.Sleep(interval)
			continue
		}
		// Stagger fetches across the interval so Graylog is not hit in a burst.
		delay := interval / time.Duration(len(fws)+1)
		for _, fw := range fws {
			if n, ferr := e.refreshFirewall(fw.ID, fw.FQDN); ferr != nil {
				e.logger.Warn("graylog device fetch failed", "fw_id", fw.ID, "fqdn", fw.FQDN, "err", ferr)
			} else {
				e.logger.Debug("graylog devices refreshed", "fw_id", fw.ID, "devices", n)
			}
			time.Sleep(delay)
		}
	}
}

var _ extension.Extension = (*Extension)(nil)
