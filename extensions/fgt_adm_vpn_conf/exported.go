package fgtadmvpnconf

import (
	"database/sql"
	"os"
	"path/filepath"
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

// ListGraylogIssues opens the extension's database read-only and returns every
// Graylog-enabled device whose last checked status is not healthy (offline,
// error or config_missing). A missing database — the extension disabled or not
// yet initialised — yields (nil, nil), so the dashboard simply renders no card.
func ListGraylogIssues(dataDir string) ([]GraylogIssue, error) {
	dbFile := filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db")
	if _, err := os.Stat(dbFile); err != nil {
		return nil, nil
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	rows, err := db.Query(`SELECT COALESCE(firewallname,''), COALESCE(standort,''),
		COALESCE(kundenname,''), COALESCE(cluster_hostnames,''),
		COALESCE(last_graylog_status,''), COALESCE(last_graylog_check,'')
		FROM vpn_config
		WHERE graylog_enabled = 1
		  AND last_graylog_status IN ('offline', 'error', 'config_missing')
		ORDER BY last_graylog_status, firewallname`)
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
