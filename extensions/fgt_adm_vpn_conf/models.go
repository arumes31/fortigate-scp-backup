package fgtadmvpnconf

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	// Pure-Go SQLite driver, registered under the name "sqlite".
	_ "modernc.org/sqlite"
)

const (
	// graylogCheckCycleSeconds is how long after a device's last check the worker
	// is expected to check it again (one ~15-minute sweep).
	graylogCheckCycleSeconds = 900

	// hookwiseDisabledCID is the sentinel CID that disables HookWise up/down
	// alerts for a device while still tracking its Graylog status normally.
	hookwiseDisabledCID = "000000"
)

// VpnConfig mirrors a row of the vpn_config table.
type VpnConfig struct {
	ID                int64
	Kundenname        string
	Standort          string
	RemoteipFull      string
	RemoteipFull1st   string
	Ike2Username      string
	WanInterface      string
	LanInterface      string
	DnsName           string
	Firewallname      string
	Cid               string
	IpsecPskRo        string
	IpsecPskHci       string
	Radiusmgt         string
	DnsNameFull       string
	GraylogEnabled    bool
	ClusterHostnames  string
	LastGraylogStatus string
	LastGraylogCheck  *time.Time
	// LastGraylogUnhealthySince marks when the current unhealthy streak began
	// (nil while healthy). Used to surface only devices failing long enough to
	// match the alert threshold. See graylogStatusUnhealthy.
	LastGraylogUnhealthySince *time.Time
}

// NextGraylogCheck is the approximate UTC time of this device's next Graylog
// check, or nil if it has not been checked yet.
func (c *VpnConfig) NextGraylogCheck() *time.Time {
	if c.LastGraylogCheck == nil {
		return nil
	}
	t := c.LastGraylogCheck.Add(graylogCheckCycleSeconds * time.Second)
	return &t
}

// createTableSQL creates the table with the full, current schema. For legacy
// databases the table already exists (this is a no-op) and runMigrations adds
// any missing columns.
const createTableSQL = `CREATE TABLE IF NOT EXISTS vpn_config (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	kundenname VARCHAR(100),
	standort VARCHAR(100),
	remoteip_full VARCHAR(100) UNIQUE,
	remoteip_full_1st VARCHAR(100),
	ike2_username VARCHAR(100),
	wan_interface VARCHAR(100),
	lan_interface VARCHAR(100),
	dns_name VARCHAR(100),
	firewallname VARCHAR(100) UNIQUE,
	cid VARCHAR(100) NOT NULL,
	ipsec_psk_ro VARCHAR(100),
	ipsec_psk_hci VARCHAR(100),
	radiusmgt VARCHAR(10),
	dns_name_full VARCHAR(100),
	graylog_enabled BOOLEAN DEFAULT 1,
	cluster_hostnames VARCHAR(255),
	last_graylog_status VARCHAR(20) DEFAULT 'unknown',
	last_graylog_check DATETIME,
	graylog_unhealthy_since DATETIME
)`

// migrations is the same idempotent list the Python run_migrations() applied, in
// the same order and with identical ALTER statements.
var migrations = []struct {
	col string
	sql string
}{
	{"graylog_enabled", "ALTER TABLE vpn_config ADD COLUMN graylog_enabled BOOLEAN DEFAULT 1"},
	{"cluster_hostnames", "ALTER TABLE vpn_config ADD COLUMN cluster_hostnames VARCHAR(255)"},
	{"last_graylog_status", "ALTER TABLE vpn_config ADD COLUMN last_graylog_status VARCHAR(20) DEFAULT 'unknown'"},
	{"cid", "ALTER TABLE vpn_config ADD COLUMN cid VARCHAR(100)"},
	{"last_graylog_check", "ALTER TABLE vpn_config ADD COLUMN last_graylog_check DATETIME"},
	{"graylog_unhealthy_since", "ALTER TABLE vpn_config ADD COLUMN graylog_unhealthy_since DATETIME"},
}

// openDB opens the private SQLite database. A single connection serialises
// access between the request handlers and the background worker, which avoids
// "database is locked" errors on the file-backed store.
func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// WAL improves read/write concurrency between the web handlers and the
	// background Graylog worker; busy_timeout avoids "database is locked" errors
	// under contention (#50).
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

// columnExists reports whether a column can be selected, mirroring the Python
// existence probe (SELECT <col> FROM vpn_config LIMIT 1).
func columnExists(db *sql.DB, col string) bool {
	rows, err := db.Query("SELECT " + col + " FROM vpn_config LIMIT 1")
	if err != nil {
		return false
	}
	_ = rows.Close()
	return true
}

// runMigrations applies the idempotent schema migrations and backfills cid.
func (e *Extension) runMigrations() error {
	for _, m := range migrations {
		if columnExists(e.db, m.col) {
			continue
		}
		if _, err := e.db.Exec(m.sql); err != nil {
			// Another writer may have added it concurrently; treat as success if
			// it now exists, else propagate the error.
			if !columnExists(e.db, m.col) {
				return err
			}
			continue
		}
		e.logAction("Database Migration", "Added "+m.col+" column to vpn_config table")
	}
	// Backfill missing cid (NOT NULL now) with the HookWise "disabled" sentinel
	// rather than inventing one from firewallname/UNKNOWN: a fabricated cid would
	// make sendHookwiseEvent fire real alerts with a wrong CID. The sentinel keeps
	// alerts off until an operator sets a genuine cid.
	_, err := e.db.Exec(
		"UPDATE vpn_config SET cid = ? WHERE cid IS NULL OR cid = ''", hookwiseDisabledCID)
	return err
}

// ensureMigrations runs the migrations at most once per process.
func (e *Extension) ensureMigrations() error {
	e.migrateOnce.Do(func() {
		e.migrateErr = e.runMigrations()
	})
	return e.migrateErr
}

// selectCols is the column projection used everywhere a VpnConfig is read.
// COALESCE keeps NULLs from legacy rows out of the string scans.
const selectCols = `id,
	COALESCE(kundenname,''), COALESCE(standort,''), COALESCE(remoteip_full,''),
	COALESCE(remoteip_full_1st,''), COALESCE(ike2_username,''), COALESCE(wan_interface,''),
	COALESCE(lan_interface,''), COALESCE(dns_name,''), COALESCE(firewallname,''),
	COALESCE(cid,''), COALESCE(ipsec_psk_ro,''), COALESCE(ipsec_psk_hci,''),
	COALESCE(radiusmgt,''), COALESCE(dns_name_full,''), COALESCE(graylog_enabled,1),
	COALESCE(cluster_hostnames,''), COALESCE(last_graylog_status,'unknown'),
	last_graylog_check, graylog_unhealthy_since`

type rowScanner interface {
	Scan(dest ...any) error
}

// scanConfig reads one row (from *sql.Row or *sql.Rows) into a VpnConfig.
func scanConfig(s rowScanner) (*VpnConfig, error) {
	var c VpnConfig
	var glEnabled int64
	var lastCheck, unhealthySince any
	err := s.Scan(
		&c.ID, &c.Kundenname, &c.Standort, &c.RemoteipFull, &c.RemoteipFull1st,
		&c.Ike2Username, &c.WanInterface, &c.LanInterface, &c.DnsName, &c.Firewallname,
		&c.Cid, &c.IpsecPskRo, &c.IpsecPskHci, &c.Radiusmgt, &c.DnsNameFull,
		&glEnabled, &c.ClusterHostnames, &c.LastGraylogStatus, &lastCheck, &unhealthySince,
	)
	if err != nil {
		return nil, err
	}
	c.GraylogEnabled = glEnabled != 0
	if t, ok := parseDBTime(lastCheck); ok {
		c.LastGraylogCheck = &t
	}
	if t, ok := parseDBTime(unhealthySince); ok {
		c.LastGraylogUnhealthySince = &t
	}
	return &c, nil
}

// parseDBTime tolerantly decodes whatever the driver returns for a DATETIME
// column (time.Time, string, []byte or nil) into a UTC time.
func parseDBTime(v any) (time.Time, bool) {
	var s string
	switch t := v.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return t.UTC(), true
	case string:
		s = t
	case []byte:
		s = string(t)
	default:
		return time.Time{}, false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, l := range layouts {
		if tt, err := time.Parse(l, s); err == nil {
			return tt.UTC(), true
		}
	}
	return time.Time{}, false
}

// formatDBTime renders a time the same way Python's datetime.utcnow() serialised
// through SQLAlchemy: a UTC string with six fractional digits.
func formatDBTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05.000000")
}

// ---- IP pool helpers (10.105.1.0/24) ----------------------------------------

// poolFirstHost/poolLastHost bound the usable host range, matching Python's
// ipaddress hosts() which excludes the network (.0) and broadcast (.255).
const (
	poolPrefix    = "10.105.1."
	poolFirstHost = 1
	poolLastHost  = 254
	poolTotal     = 254 // num_addresses - 2
)

// usedIPSet returns the set of normalised remoteip_full values in use.
func (e *Extension) usedIPSet() (map[string]bool, error) {
	rows, err := e.db.Query("SELECT remoteip_full FROM vpn_config WHERE remoteip_full IS NOT NULL AND remoteip_full != ''")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	used := map[string]bool{}
	for rows.Next() {
		var ip sql.NullString
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		if ip.Valid {
			if parsed := net.ParseIP(strings.TrimSpace(ip.String)); parsed != nil {
				used[parsed.String()] = true
			}
		}
	}
	return used, rows.Err()
}

// nextAvailableIP returns the first free host address, or "" if the pool is full.
func (e *Extension) nextAvailableIP() (string, error) {
	used, err := e.usedIPSet()
	if err != nil {
		return "", err
	}
	for i := poolFirstHost; i <= poolLastHost; i++ {
		cand := fmt.Sprintf("%s%d", poolPrefix, i)
		if !used[cand] {
			return cand, nil
		}
	}
	return "", nil
}

// availableIPs returns every free host address and the pool size (host count).
func (e *Extension) availableIPs() (available []string, total int, err error) {
	used, err := e.usedIPSet()
	if err != nil {
		return nil, 0, err
	}
	for i := poolFirstHost; i <= poolLastHost; i++ {
		cand := fmt.Sprintf("%s%d", poolPrefix, i)
		if !used[cand] {
			available = append(available, cand)
		}
	}
	return available, poolTotal, nil
}

// ---- CRUD -------------------------------------------------------------------

func (e *Extension) getConfig(id int64) (*VpnConfig, error) {
	row := e.db.QueryRow("SELECT "+selectCols+" FROM vpn_config WHERE id = ?", id)
	return scanConfig(row)
}

func (e *Extension) queryConfigs(where string) ([]*VpnConfig, error) {
	q := "SELECT " + selectCols + " FROM vpn_config"
	if where != "" {
		q += " " + where
	}
	q += " ORDER BY id"
	rows, err := e.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*VpnConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (e *Extension) allConfigs() ([]*VpnConfig, error) {
	return e.queryConfigs("")
}

func (e *Extension) enabledConfigs() ([]*VpnConfig, error) {
	return e.queryConfigs("WHERE graylog_enabled = 1")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// insertConfig inserts a new row. last_graylog_status/last_graylog_check take
// their column defaults (unknown / NULL), matching the Python insert path.
func (e *Extension) insertConfig(c *VpnConfig) error {
	_, err := e.db.Exec(`INSERT INTO vpn_config
		(kundenname, standort, remoteip_full, remoteip_full_1st, ike2_username,
		 wan_interface, lan_interface, dns_name, firewallname, cid,
		 ipsec_psk_ro, ipsec_psk_hci, radiusmgt, dns_name_full,
		 graylog_enabled, cluster_hostnames)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.Kundenname, c.Standort, c.RemoteipFull, c.RemoteipFull1st, c.Ike2Username,
		c.WanInterface, c.LanInterface, c.DnsName, c.Firewallname, c.Cid,
		c.IpsecPskRo, c.IpsecPskHci, c.Radiusmgt, c.DnsNameFull,
		boolToInt(c.GraylogEnabled), c.ClusterHostnames)
	return err
}

// updateConfigFull writes every editable field (used by the edit handler).
func (e *Extension) updateConfigFull(c *VpnConfig) error {
	_, err := e.db.Exec(`UPDATE vpn_config SET
		kundenname=?, standort=?, remoteip_full=?, remoteip_full_1st=?, ike2_username=?,
		wan_interface=?, lan_interface=?, dns_name=?, firewallname=?, cid=?,
		ipsec_psk_ro=?, ipsec_psk_hci=?, radiusmgt=?, dns_name_full=?,
		graylog_enabled=?, cluster_hostnames=?
		WHERE id=?`,
		c.Kundenname, c.Standort, c.RemoteipFull, c.RemoteipFull1st, c.Ike2Username,
		c.WanInterface, c.LanInterface, c.DnsName, c.Firewallname, c.Cid,
		c.IpsecPskRo, c.IpsecPskHci, c.Radiusmgt, c.DnsNameFull,
		boolToInt(c.GraylogEnabled), c.ClusterHostnames, c.ID)
	return err
}

// updateConfigImport mirrors the CSV upsert path, which updates every field of
// the matched row EXCEPT firewallname (the match key).
func (e *Extension) updateConfigImport(id int64, c *VpnConfig) error {
	_, err := e.db.Exec(`UPDATE vpn_config SET
		kundenname=?, standort=?, remoteip_full=?, remoteip_full_1st=?, ike2_username=?,
		wan_interface=?, lan_interface=?, dns_name=?, ipsec_psk_ro=?, ipsec_psk_hci=?,
		radiusmgt=?, dns_name_full=?, graylog_enabled=?, cluster_hostnames=?, cid=?
		WHERE id=?`,
		c.Kundenname, c.Standort, c.RemoteipFull, c.RemoteipFull1st, c.Ike2Username,
		c.WanInterface, c.LanInterface, c.DnsName, c.IpsecPskRo, c.IpsecPskHci,
		c.Radiusmgt, c.DnsNameFull, boolToInt(c.GraylogEnabled), c.ClusterHostnames, c.Cid, id)
	return err
}

func (e *Extension) deleteConfig(id int64) error {
	_, err := e.db.Exec("DELETE FROM vpn_config WHERE id = ?", id)
	return err
}

// remoteIPTaken reports whether another row (id != excludeID) already uses ip.
func (e *Extension) remoteIPTaken(ip string, excludeID int64) (bool, error) {
	var n int
	err := e.db.QueryRow("SELECT COUNT(*) FROM vpn_config WHERE remoteip_full = ? AND id != ?", ip, excludeID).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (e *Extension) findIDByFirewallname(name string) (int64, bool, error) {
	var id int64
	err := e.db.QueryRow("SELECT id FROM vpn_config WHERE firewallname = ? LIMIT 1", name).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (e *Extension) findIDByRemoteip(ip string) (int64, bool, error) {
	var id int64
	err := e.db.QueryRow("SELECT id FROM vpn_config WHERE remoteip_full = ? LIMIT 1", ip).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// updateGraylogStatus persists a worker check result. unhealthySince is the
// start of the current unhealthy streak (nil while healthy), stored as NULL so
// the dashboard can filter on how long a device has been failing.
func (e *Extension) updateGraylogStatus(id int64, checkedAt time.Time, status string, unhealthySince *time.Time) error {
	var since any
	if unhealthySince != nil {
		since = formatDBTime(*unhealthySince)
	}
	_, err := e.db.Exec(
		"UPDATE vpn_config SET last_graylog_check = ?, last_graylog_status = ?, graylog_unhealthy_since = ? WHERE id = ?",
		formatDBTime(checkedAt), status, since, id)
	return err
}

// ---- password generator (parity with Python get_random_password) ------------

// cryptoIntn returns a uniformly distributed int in [0, n) from a cryptographic
// source. These values seed IPsec pre-shared keys and RADIUS secrets, so a
// predictable (math/rand) generator would let an observer of a few generated
// secrets reconstruct future ones.
func cryptoIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("fgt_adm_vpn_conf: crypto/rand unavailable: " + err.Error())
	}
	return int(v.Int64())
}

func getRandomPassword(length, upper, lower, numeric, special int) string {
	const (
		uSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lSet = "abcdefghijklmnopqrstuvwxyz"
		nSet = "0123456789"
		sSet = "!#"
	)
	pw := make([]byte, 0, length)
	for i := 0; i < upper; i++ {
		pw = append(pw, uSet[cryptoIntn(len(uSet))])
	}
	for i := 0; i < lower; i++ {
		pw = append(pw, lSet[cryptoIntn(len(lSet))])
	}
	for i := 0; i < numeric; i++ {
		pw = append(pw, nSet[cryptoIntn(len(nSet))])
	}
	for i := 0; i < special; i++ {
		pw = append(pw, sSet[cryptoIntn(len(sSet))])
	}
	remaining := length - (upper + lower + numeric + special)
	all := uSet + lSet + nSet + sSet
	for i := 0; i < remaining; i++ {
		pw = append(pw, all[cryptoIntn(len(all))])
	}
	// Fisher-Yates shuffle so the character classes are not grouped by position.
	for i := len(pw) - 1; i > 0; i-- {
		j := cryptoIntn(i + 1)
		pw[i], pw[j] = pw[j], pw[i]
	}
	return string(pw)
}

// isDigits reports whether s is a non-empty run of ASCII digits (str.isdigit).
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// splitHostnames splits a comma-separated cluster list, trimming and dropping
// empties (matching the Python comprehension).
func splitHostnames(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}
