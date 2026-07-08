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
	"strings"
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
		"PRAGMA synchronous=NORMAL",
		createTableSQL,
		createStpTableSQL,
		createStpEventsSQL,
		createMacPortsSQL,
		createWifiSQL,
		createVpnStatusSQL,
		createHaStatusSQL,
	} {
		if _, execErr := db.Exec(q); execErr != nil {
			_ = db.Close()
			return execErr
		}
	}
	// Migrations (ignore the duplicate-column error on re-runs): guard column
	// for BPDU/loop/root-guard blocks, link column for live port status,
	// first_seen for the retained device inventory, plus the endpoint
	// fingerprint columns (device-identification: type/OS/vendor).
	for _, alter := range []string{
		`ALTER TABLE stp_ports ADD COLUMN guard TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN link TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN first_seen TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN devtype TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN osname TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN osversion TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN vendor TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(alter); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			_ = db.Close()
			return err
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
	devtype   TEXT NOT NULL DEFAULT '',
	osname    TEXT NOT NULL DEFAULT '',
	osversion TEXT NOT NULL DEFAULT '',
	vendor    TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL DEFAULT '',
	last_seen TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY (fw_id, mac, ip)
)`

// stp_events keeps the raw port event history (role/state/guard/link
// transitions) for the port-detail timeline; rows age out after 48h.
const createStpEventsSQL = `CREATE TABLE IF NOT EXISTS stp_events (
	fw_id       INTEGER NOT NULL,
	switch_name TEXT NOT NULL DEFAULT '',
	serial      TEXT NOT NULL DEFAULT '',
	port        TEXT NOT NULL,
	kind        TEXT NOT NULL,
	from_val    TEXT NOT NULL DEFAULT '',
	to_val      TEXT NOT NULL DEFAULT '',
	event_time  TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_name, port, kind, event_time)
)`

// stp_ports holds the latest spanning-tree role/state per switch port,
// derived from the FortiGate's switch-controller STP event logs.
const createStpTableSQL = `CREATE TABLE IF NOT EXISTS stp_ports (
	fw_id       INTEGER NOT NULL,
	switch_name TEXT NOT NULL DEFAULT '',
	serial      TEXT NOT NULL DEFAULT '',
	port        TEXT NOT NULL,
	role        TEXT NOT NULL DEFAULT '',
	state       TEXT NOT NULL DEFAULT '',
	guard       TEXT NOT NULL DEFAULT '',
	last_change TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_name, port)
)`

// mac_ports holds the latest wired switch + physical port per client MAC,
// derived from FortiSwitch MAC add/move events (the piece traffic logs lack).
// listDevices joins this over the inventory so devices pin to real ports.
const createMacPortsSQL = `CREATE TABLE IF NOT EXISTS mac_ports (
	fw_id       INTEGER NOT NULL,
	mac         TEXT NOT NULL,
	switch_name TEXT NOT NULL DEFAULT '',
	port        TEXT NOT NULL DEFAULT '',
	vlan        TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, mac)
)`

// wifi_clients holds the latest wireless association per client MAC
// (client↔AP↔SSID + signal); joined onto the inventory by MAC.
const createWifiSQL = `CREATE TABLE IF NOT EXISTS wifi_clients (
	fw_id      INTEGER NOT NULL,
	mac        TEXT NOT NULL,
	ap         TEXT NOT NULL DEFAULT '',
	ssid       TEXT NOT NULL DEFAULT '',
	signal     TEXT NOT NULL DEFAULT '',
	channel    TEXT NOT NULL DEFAULT '',
	vlan       TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY (fw_id, mac)
)`

// vpn_status holds the latest up/down state per IPsec/SSL tunnel.
const createVpnStatusSQL = `CREATE TABLE IF NOT EXISTS vpn_status (
	fw_id      INTEGER NOT NULL,
	name       TEXT NOT NULL,
	remip      TEXT NOT NULL DEFAULT '',
	type       TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY (fw_id, name)
)`

// ha_status holds the newest HA event summary per firewall (liveness hint for
// the HA cluster node, which is otherwise config-derived).
const createHaStatusSQL = `CREATE TABLE IF NOT EXISTS ha_status (
	fw_id      INTEGER NOT NULL PRIMARY KEY,
	detail     TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL
)`

// worker refreshes the device inventory for every switch-managing firewall on
// the configured interval, staggering firewalls across the sweep.
func (e *Extension) worker() {
	time.Sleep(15 * time.Second) // let the app finish booting
	interval := time.Duration(e.cfg.GraylogDeviceInterval) * time.Second
	if interval < time.Minute {
		interval = time.Hour
	}
	e.logger.Info("graylog device worker started",
		"interval", interval.String(), "range_seconds", e.cfg.GraylogDeviceRange,
		"graylog_configured", e.cfg.GraylogURL != "" && e.cfg.GraylogToken != "",
		"device_query", e.cfg.GraylogDeviceQuery, "stp_query", e.cfg.GraylogStpQuery)
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
			if n, ferr := e.refreshFirewall(fw.ID, fw.FQDN, ""); ferr != nil {
				e.logger.Warn("graylog device fetch failed", "fw_id", fw.ID, "fqdn", fw.FQDN, "err", ferr)
			} else {
				e.logger.Info("graylog devices refreshed", "fw_id", fw.ID, "fqdn", fw.FQDN, "devices", n)
			}
			time.Sleep(delay)
		}
	}
}

var _ extension.Extension = (*Extension)(nil)
