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
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	// Live SSH diagnostics (optional): resolve a firewall's decrypted SSH
	// credentials, and a per-device serial executor that rate-limits CLI queries
	// (never more than one in flight per firewall; extra requests are queued).
	firewallCreds func(ctx context.Context, fwID int) (host, user, pass string, port int, err error)
	diagMu        sync.Mutex
	diagState     map[int]*diagRunState // fw_id → serial-execution state

	// In-flight fetches and active live views, listed on the core dashboard
	// (see running.go).
	runningMu  sync.Mutex
	runningSeq int
	running    map[int]runningEntry
	liveByFw   map[int]*liveState
}

// diagRunState is one firewall's SSH-collection state: a single-flight guard, a
// coalesced pending slot (at most one queued request, keeping the shortest
// requested interval), the last run's start time (for the cadence gate) and the
// last full-static-refresh time (for the static/live cadence split).
type diagRunState struct {
	busy         bool
	pending      bool
	pendMin      time.Duration
	last         time.Time // last background-sweep start (drives the sweep rate floor)
	lastStatic   time.Time
	lastPortDiag time.Time // last on-demand port query start (its own cooldown clock)
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
	e.firewallCreds = d.FirewallCreds
	e.diagState = map[int]*diagRunState{}
	liveExt.Store(e) // publish for the core dashboard's running-operations card

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
		createMacSightingsSQL,
		createSwitchEdgesSQL,
		createWifiSQL,
		createVpnStatusSQL,
		createHaStatusSQL,
		createMacEnrichSQL,
		createSwitchHealthSQL,
		createLiveRoutesSQL,
		createSdwanHealthSQL,
		createIfaceStatsSQL,
		createDiagStatusSQL,
		createApLocationSQL,
		createPortCountersSQL,
		createMacViolationsSQL,
		// Legacy single-row-per-MAC binding table, superseded by mac_sightings
		// (per-switch rows preserve the transit signal). Cache data only —
		// repopulated by the next refresh.
		`DROP TABLE IF EXISTS mac_ports`,
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
		`ALTER TABLE stp_ports ADD COLUMN dot1x TEXT NOT NULL DEFAULT ''`,
		// Live SSH-diagnostics port enrichment.
		`ALTER TABLE stp_ports ADD COLUMN media TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN speed TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN admin TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN poe TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN optic TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN health TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE stp_ports ADD COLUMN neighbor TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE switch_edges ADD COLUMN state TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE switch_edges ADD COLUMN note TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ha_status ADD COLUMN health TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE switch_health ADD COLUMN tcn INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE switch_health ADD COLUMN poe_used REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE switch_health ADD COLUMN poe_total REAL NOT NULL DEFAULT 0`,
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
		pr.Post("/port-diag/{fwID}", e.handlePortDiag)
	})

	go e.worker()
	if e.cfg.FgtDiagSSHEnabled && e.firewallCreds != nil {
		go e.diagWorker()
	}
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
	link        TEXT NOT NULL DEFAULT '',
	dot1x       TEXT NOT NULL DEFAULT '',
	media       TEXT NOT NULL DEFAULT '',
	speed       TEXT NOT NULL DEFAULT '',
	admin       TEXT NOT NULL DEFAULT '',
	poe         TEXT NOT NULL DEFAULT '',
	optic       TEXT NOT NULL DEFAULT '',
	health      TEXT NOT NULL DEFAULT '',
	neighbor    TEXT NOT NULL DEFAULT '',
	last_change TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_name, port)
)`

// mac_enrich holds per-MAC enrichment joined into the device inventory: the
// ARP-resolved IP and the 802.1X RADIUS identity (AD user/machine, group) and
// dynamic VLAN — all keyed by client MAC, pulled live over SSH.
const createMacEnrichSQL = `CREATE TABLE IF NOT EXISTS mac_enrich (
	fw_id       INTEGER NOT NULL,
	mac         TEXT NOT NULL,
	ip          TEXT NOT NULL DEFAULT '',
	iface       TEXT NOT NULL DEFAULT '',
	dot1x_user  TEXT NOT NULL DEFAULT '',
	dot1x_group TEXT NOT NULL DEFAULT '',
	dot1x_vlan  TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, mac)
)`

// mac_sightings holds the latest port per (client MAC, switch), derived from
// FortiSwitch MAC add/move/delete and NAC device events. One row per switch:
// every switch a frame transits learns the MAC, and that per-switch spread is
// exactly the signal that separates access ports (few MACs) from uplinks
// (many MACs) — bestMacPins picks the access port, listMultiMacPorts ranks
// the trunks.
const createMacSightingsSQL = `CREATE TABLE IF NOT EXISTS mac_sightings (
	fw_id       INTEGER NOT NULL,
	mac         TEXT NOT NULL,
	switch_name TEXT NOT NULL DEFAULT '',
	port        TEXT NOT NULL DEFAULT '',
	vlan        TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, mac, switch_name)
)`

// switch_edges holds the switch-side trunk observations from STP/link events:
// the trunk NAME identifies the peer (auto-ISL trunks carry the peer serial
// fragment; FortiLink MLAG/ICL trunks their role), the STP role orients the
// edge (root = uplink), and ports are the physical LAG legs from
// trunk-membership events — the data that resolves dual-homed uplinks.
const createSwitchEdgesSQL = `CREATE TABLE IF NOT EXISTS switch_edges (
	fw_id       INTEGER NOT NULL,
	switch_sn   TEXT NOT NULL,
	switch_name TEXT NOT NULL DEFAULT '',
	trunk       TEXT NOT NULL,
	role        TEXT NOT NULL DEFAULT '',
	state       TEXT NOT NULL DEFAULT '',
	ports       TEXT NOT NULL DEFAULT '',
	note        TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_sn, trunk)
)`

// switch_health holds one managed switch's live environmental/congestion state
// (fan status + cumulative QoS drops) for the per-switch health rollup.
const createSwitchHealthSQL = `CREATE TABLE IF NOT EXISTS switch_health (
	fw_id       INTEGER NOT NULL,
	switch_name TEXT NOT NULL,
	fan         TEXT NOT NULL DEFAULT '',
	congestion  INTEGER NOT NULL DEFAULT 0,
	tcn         INTEGER NOT NULL DEFAULT 0,
	poe_used    REAL NOT NULL DEFAULT 0,
	poe_total   REAL NOT NULL DEFAULT 0,
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_name)
)`

// sdwan_health holds the live per-member SD-WAN SLA (loss/latency/jitter/state).
const createSdwanHealthSQL = `CREATE TABLE IF NOT EXISTS sdwan_health (
	fw_id      INTEGER NOT NULL,
	member     TEXT NOT NULL,
	state      TEXT NOT NULL DEFAULT '',
	loss       REAL NOT NULL DEFAULT 0,
	latency    REAL NOT NULL DEFAULT 0,
	jitter     REAL NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (fw_id, member)
)`

// iface_stats holds the previous byte counters + derived throughput (Mbps) per
// FortiGate interface — the two-sample delta that turns counters into a rate.
const createIfaceStatsSQL = `CREATE TABLE IF NOT EXISTS iface_stats (
	fw_id      INTEGER NOT NULL,
	iface      TEXT NOT NULL,
	rxb        INTEGER NOT NULL DEFAULT 0,
	txb        INTEGER NOT NULL DEFAULT 0,
	ts         TEXT NOT NULL DEFAULT '',
	rx_mbps    REAL NOT NULL DEFAULT 0,
	tx_mbps    REAL NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (fw_id, iface)
)`

// diag_status records the last SSH sweep outcome for the collection-status UI.
const createDiagStatusSQL = `CREATE TABLE IF NOT EXISTS diag_status (
	fw_id       INTEGER NOT NULL PRIMARY KEY,
	last_run    TEXT NOT NULL DEFAULT '',
	switches    INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	static      INTEGER NOT NULL DEFAULT 0,
	updated_at  TEXT NOT NULL
)`

// live_routes holds the firewall's live routing egress summary: per interface/
// tunnel, the number of installed routes and whether it carries the default.
const createLiveRoutesSQL = `CREATE TABLE IF NOT EXISTS live_routes (
	fw_id       INTEGER NOT NULL,
	device      TEXT NOT NULL,
	routes      INTEGER NOT NULL DEFAULT 0,
	is_default  INTEGER NOT NULL DEFAULT 0,
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, device)
)`

// ap_location maps each managed FortiAP to the FortiSwitch port it is wired to,
// from the AP's own LLDP view (get wireless-controller wtp-status): the AP
// reports its upstream switch (sys name) and port (port id) — the authoritative
// AP↔port pin the wired MAC/device inventory cannot supply (an AP has no device
// row of its own). Serves the "📶 <AP> · N clients" line on the switch faceplate.
const createApLocationSQL = `CREATE TABLE IF NOT EXISTS ap_location (
	fw_id       INTEGER NOT NULL,
	ap_serial   TEXT NOT NULL,
	ap_name     TEXT NOT NULL DEFAULT '',
	board_mac   TEXT NOT NULL DEFAULT '',
	ip          TEXT NOT NULL DEFAULT '',
	switch_name TEXT NOT NULL DEFAULT '',
	switch_port TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, ap_serial)
)`

// port_counters holds the previous per-port error/discard counters + sample
// time, so a two-sample delta turns the cumulative counters into an active
// error-*rate* (a port gaining CRC errors between polls = a failing cable/SFP,
// distinct from old damage that is no longer growing).
const createPortCountersSQL = `CREATE TABLE IF NOT EXISTS port_counters (
	fw_id       INTEGER NOT NULL,
	switch_name TEXT NOT NULL,
	port        TEXT NOT NULL,
	errors      INTEGER NOT NULL DEFAULT 0,
	discards    INTEGER NOT NULL DEFAULT 0,
	ts          TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_name, port)
)`

// mac_violations holds the current port-security (MAC-limit) violations from
// `mac-limit-violations all` — a port exceeding its MAC limit means an
// unauthorized device, rogue mini-switch, or a loop. Snapshot per sweep.
const createMacViolationsSQL = `CREATE TABLE IF NOT EXISTS mac_violations (
	fw_id       INTEGER NOT NULL,
	switch_name TEXT NOT NULL,
	port        TEXT NOT NULL,
	vlan        TEXT NOT NULL DEFAULT '',
	mac         TEXT NOT NULL DEFAULT '',
	action      TEXT NOT NULL DEFAULT '',
	seen_at     TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (fw_id, switch_name, port, mac)
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
	health     TEXT NOT NULL DEFAULT '',
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
		// Anchor one full sweep per interval: stagger fetches across the
		// interval, then sleep whatever time remains. Staggering alone (a delay
		// after every firewall with no remainder) would make the effective
		// period interval*n/(n+1), polling Graylog faster than configured.
		sweepStart := time.Now()
		delay := interval / time.Duration(len(fws)+1)
		for _, fw := range fws {
			if n, ferr := e.refreshFirewall(fw.ID, fw.FQDN, ""); ferr != nil {
				e.logger.Warn("graylog device fetch failed", "fw_id", fw.ID, "fqdn", fw.FQDN, "err", ferr)
			} else {
				e.logger.Info("graylog devices refreshed", "fw_id", fw.ID, "fqdn", fw.FQDN, "devices", n)
			}
			time.Sleep(delay)
		}
		if rem := interval - time.Since(sweepStart); rem > 0 {
			time.Sleep(rem)
		}
	}
}

var _ extension.Extension = (*Extension)(nil)
