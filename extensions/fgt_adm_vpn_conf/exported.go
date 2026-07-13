package fgtadmvpnconf

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"
)

// GraylogIssue is one VPN device whose Graylog logging status is not healthy,
// exported for the core dashboard's issue card. The extension's background
// worker keeps vpn_config.last_graylog_status current (online / offline /
// error / config_missing); this is a read-only projection of the unhealthy
// rows so the core can surface them without reaching into this schema.
type GraylogIssue struct {
	Firewall  string // firewallname
	Site      string // standort, or kundenname when standort is blank
	Cluster   string // cluster_hostnames (comma-separated), when set
	Status    string // offline | error | config_missing
	LastCheck string // last_graylog_check timestamp text ("" if never checked)
}

// graylogIssueMinAge is how long a device must have been continuously unhealthy
// before it is surfaced on the dashboard, matching the external alert threshold
// (only sustained issues are worth flagging, not transient blips).
const graylogIssueMinAge = 24 * time.Hour

// ListGraylogIssues opens the extension's database read-only and returns every
// Graylog-enabled device whose status has been unhealthy (offline, error or
// config_missing) for at least graylogIssueMinAge — mirroring the alert mail so
// the card lists only sustained issues, not momentary blips. Devices whose
// unhealthy streak start is unknown (e.g. not yet re-checked after upgrade) are
// omitted until the streak is old enough. A missing database — the extension
// disabled or not yet initialised — yields (nil, nil), so the dashboard simply
// renders no card.
func ListGraylogIssues(dataDir string) ([]GraylogIssue, error) {
	dbFile := filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db")
	if _, err := os.Stat(dbFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil // extension disabled or not yet initialised: no card
		}
		return nil, err // permission / I/O error: surface it, don't hide as "no issues"
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	// Only devices unhealthy for at least graylogIssueMinAge. graylog_unhealthy_since
	// is written by the worker in the same fixed-width UTC layout as the cutoff
	// (formatDBTime), so a lexical string comparison is chronological; NULL
	// (streak start unknown) is excluded.
	cutoff := formatDBTime(time.Now().Add(-graylogIssueMinAge))
	rows, err := db.Query(`SELECT COALESCE(firewallname,''), COALESCE(standort,''),
		COALESCE(kundenname,''), COALESCE(cluster_hostnames,''),
		COALESCE(last_graylog_status,''), COALESCE(last_graylog_check,'')
		FROM vpn_config
		WHERE graylog_enabled = 1
		  AND last_graylog_status IN ('offline', 'error', 'config_missing')
		  AND graylog_unhealthy_since IS NOT NULL
		  AND graylog_unhealthy_since <= ?
		ORDER BY last_graylog_status, firewallname`, cutoff)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []GraylogIssue
	for rows.Next() {
		var g GraylogIssue
		var site, customer string
		if scanErr := rows.Scan(&g.Firewall, &site, &customer, &g.Cluster, &g.Status, &g.LastCheck); scanErr != nil {
			return nil, scanErr
		}
		g.Site = site
		if g.Site == "" {
			g.Site = customer
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
