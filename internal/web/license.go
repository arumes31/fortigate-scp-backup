// License & entitlement inventory: a background collector fetches each
// firewall's serial number and FortiGuard contract expiry dates over SSH
// (get system status + diagnose autoupdate versions) once per day, stores
// them in the insights DB and serves the /licenses page plus the dashboard's
// expiring-licenses card. The FortiCare hardware/support contract is not
// exposed by these commands, so the inventory covers FortiGuard service
// entitlements; on HA clusters the primary answers, so its serial is recorded.
package web

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/ssh"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// licenseWarnDays / licenseCritDays classify how soon an entitlement expiry
// becomes a warning (orange) or critical (red). Expired is always critical.
const (
	licenseWarnDays = 60
	licenseCritDays = 30
)

// licenseSSHTimeout bounds the whole per-device collection (dial + both
// commands), so one hung device cannot stall the daily sweep for long.
const licenseSSHTimeout = 45 * time.Second

// licenseStatus is the per-device summary parsed from `get system status`.
type licenseStatus struct {
	Serial       string
	Hostname     string
	Model        string
	Version      string
	Build        string
	Registration string
	HAMode       string
	OpMode       string
}

// licenseEntitlement is one FortiGuard service from
// `diagnose autoupdate versions`.
type licenseEntitlement struct {
	Service    string `json:"service"`
	Version    string `json:"version"`
	Expiry     string `json:"expiry"` // ISO yyyy-mm-dd, "" when unknown
	LastUpdate string `json:"last_update"`
	Result     string `json:"result"`
}

// ---- SSH collection ---------------------------------------------------------

// sshRunCommands opens one SSH connection to the firewall (same credentials
// the backup engine uses) and runs each command in its own session. A single
// deadline covers the whole exchange: on expiry the client is closed, which
// unblocks any in-flight session read.
func sshRunCommands(fw models.Firewall, cmds []string) (map[string]string, error) {
	cfg := &ssh.ClientConfig{
		User:            fw.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(fw.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // matches the backup engine's transfer()
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(fw.FQDN, strconv.Itoa(fw.SSHPort))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()
	// Hard deadline for the whole command exchange.
	killer := time.AfterFunc(licenseSSHTimeout, func() { _ = client.Close() })
	defer killer.Stop()

	out := make(map[string]string, len(cmds))
	for _, cmd := range cmds {
		sess, err := client.NewSession()
		if err != nil {
			return nil, fmt.Errorf("ssh session: %w", err)
		}
		b, err := sess.CombinedOutput(cmd)
		_ = sess.Close()
		if err != nil && len(b) == 0 {
			return nil, fmt.Errorf("%q: %w", cmd, err)
		}
		out[cmd] = string(b)
	}
	return out, nil
}

// ---- parsers ----------------------------------------------------------------

// reStatusVersion splits the `get system status` Version value, e.g.
// "FortiGate-90G v7.6.7,build3704,260601 (GA.M)".
var reStatusVersion = regexp.MustCompile(`^(\S+)\s+v?([0-9.]+),build(\d+)`)

// stripPrompt removes an echoed CLI prompt ("HOSTNAME (ctx) $ ") that FortiOS
// prefixes to the first output line of an exec-channel command.
func stripPrompt(line string) string {
	if i := strings.LastIndex(line, " $ "); i >= 0 {
		return line[i+3:]
	}
	return line
}

// parseSystemStatus extracts the device summary from `get system status`.
func parseSystemStatus(out string) licenseStatus {
	var st licenseStatus
	for _, line := range strings.Split(out, "\n") {
		line = stripPrompt(strings.TrimRight(line, "\r"))
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "Version":
			if m := reStatusVersion.FindStringSubmatch(val); m != nil {
				st.Model, st.Version, st.Build = m[1], m[2], m[3]
			} else {
				st.Version = val
			}
		case "Serial-Number":
			st.Serial = val
		case "Hostname":
			st.Hostname = val
		case "FortiCare Registration Level":
			st.Registration = val
		case "Current HA mode":
			st.HAMode = val
		case "Operation Mode":
			st.OpMode = val
		}
	}
	return st
}

// parseExpiryDate converts FortiOS's "Sat Apr 24 2027" (single-digit days are
// space-padded: "Mon Apr  9 2018") to ISO yyyy-mm-dd, or "" if unparseable.
func parseExpiryDate(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" || strings.EqualFold(s, "n/a") {
		return ""
	}
	t, err := time.Parse("Mon Jan 2 2006", s)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02")
}

// parseAutoupdateVersions extracts one entitlement per section of
// `diagnose autoupdate versions`. Sections look like:
//
//	AV Engine
//	---------
//	Version: 7.00054 signed
//	Contract Expiry Date: Sat Apr 24 2027
//	Last Updated using manual update on Tue Apr 14 22:14:00 2026
//	Last Update Attempt: n/a
//	Result: Updates Installed
func parseAutoupdateVersions(out string) []licenseEntitlement {
	lines := strings.Split(out, "\n")
	var ents []licenseEntitlement
	var cur *licenseEntitlement
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		// A dashed rule names the previous line as a new section header.
		if strings.HasPrefix(line, "---") && i > 0 {
			name := stripPrompt(strings.TrimSpace(lines[i-1]))
			name = strings.TrimRight(name, "\r")
			if name != "" {
				ents = append(ents, licenseEntitlement{Service: strings.TrimSpace(name)})
				cur = &ents[len(ents)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Version: "):
			cur.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		case strings.HasPrefix(line, "Contract Expiry Date: "):
			cur.Expiry = parseExpiryDate(strings.TrimPrefix(line, "Contract Expiry Date: "))
		case strings.HasPrefix(line, "Last Updated using "):
			cur.LastUpdate = strings.TrimSpace(strings.TrimPrefix(line, "Last Updated using "))
		case strings.HasPrefix(line, "Result: "):
			cur.Result = strings.TrimSpace(strings.TrimPrefix(line, "Result: "))
		}
	}
	// Drop non-service footer sections (e.g. "FDS Address", which lists only
	// the update server): every real service carries at least a version.
	kept := ents[:0]
	for _, e := range ents {
		if e.Version != "" || e.Expiry != "" {
			kept = append(kept, e)
		}
	}
	return kept
}

// ---- storage ----------------------------------------------------------------

// storeLicenseResult upserts one device's collection outcome. On success the
// entitlement rows are replaced atomically; on failure only the error and
// attempt time are recorded, so the last good data stays visible.
func storeLicenseResult(db *sql.DB, fwID int, st *licenseStatus, ents []licenseEntitlement, fetchErr string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if fetchErr != "" {
		_, err := db.Exec(`INSERT INTO license_status (fw_id, fetched_at, fetch_error)
			VALUES (?, ?, ?)
			ON CONFLICT(fw_id) DO UPDATE SET fetched_at=excluded.fetched_at, fetch_error=excluded.fetch_error`,
			fwID, now, fetchErr)
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO license_status
		(fw_id, serial, hostname, model, version, build, registration, ha_mode, op_mode, fetched_at, fetch_error)
		VALUES (?,?,?,?,?,?,?,?,?,?,'')
		ON CONFLICT(fw_id) DO UPDATE SET
			serial=excluded.serial, hostname=excluded.hostname, model=excluded.model,
			version=excluded.version, build=excluded.build, registration=excluded.registration,
			ha_mode=excluded.ha_mode, op_mode=excluded.op_mode,
			fetched_at=excluded.fetched_at, fetch_error=''`,
		fwID, st.Serial, st.Hostname, st.Model, st.Version, st.Build,
		st.Registration, st.HAMode, st.OpMode, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM license_entitlements WHERE fw_id = ?`, fwID); err != nil {
		return err
	}
	for _, e := range ents {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO license_entitlements
			(fw_id, service, version, expiry, last_update, result) VALUES (?,?,?,?,?,?)`,
			fwID, e.Service, e.Version, e.Expiry, e.LastUpdate, e.Result); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- collector --------------------------------------------------------------

// fetchLicense collects and stores one device's license data. Concurrent
// fetches for the same device are coalesced via licenseInFlight.
func (s *Server) fetchLicense(fw models.Firewall) {
	if _, busy := s.licenseInFlight.LoadOrStore(fw.ID, true); busy {
		return
	}
	defer s.licenseInFlight.Delete(fw.ID)

	db, err := s.insightsDB()
	if err != nil {
		s.logger.Error("license fetch: insights DB unavailable", "err", err)
		return
	}
	out, err := sshRunCommands(fw, []string{"get system status", "diagnose autoupdate versions"})
	if err != nil {
		s.logger.Warn("license fetch failed", "fqdn", fw.FQDN, "err", err)
		if serr := storeLicenseResult(db, fw.ID, nil, nil, err.Error()); serr != nil {
			s.logger.Error("license store failed", "fqdn", fw.FQDN, "err", serr)
		}
		return
	}
	st := parseSystemStatus(out["get system status"])
	ents := parseAutoupdateVersions(out["diagnose autoupdate versions"])
	if err := storeLicenseResult(db, fw.ID, &st, ents, ""); err != nil {
		s.logger.Error("license store failed", "fqdn", fw.FQDN, "err", err)
		return
	}
	s.logger.Info("license data refreshed", "fqdn", fw.FQDN, "serial", st.Serial, "entitlements", len(ents))
}

// refreshLicensesJob is the daily sweep over every firewall, run by the
// scheduler. Devices are collected sequentially with a small gap so the sweep
// never bursts SSH connections across the fleet.
func (s *Server) refreshLicensesJob() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	fws, err := s.store.ListFirewalls(ctx)
	cancel()
	if err != nil {
		s.logger.Error("license sweep: list firewalls failed", "err", err)
		return
	}
	for _, fw := range fws {
		s.fetchLicense(fw)
		time.Sleep(2 * time.Second)
	}
}

// ---- page -------------------------------------------------------------------

// licenseRow is one firewall on the /licenses page.
type licenseRow struct {
	FwID         int
	FQDN         string
	Serial       string
	Hostname     string
	Model        string
	Version      string
	Build        string
	Registration string
	HAMode       string
	FetchedAt    string
	FetchError   string
	Expiry       string // earliest entitlement expiry (ISO), "" unknown
	DaysLeft     int
	Level        string // ok | warn | crit | expired | unknown
	Entitlements []licenseEntitlement
}

// licenseLevel classifies days-until-expiry into a display level.
func licenseLevel(daysLeft int) string {
	switch {
	case daysLeft < 0:
		return "expired"
	case daysLeft <= licenseCritDays:
		return "crit"
	case daysLeft <= licenseWarnDays:
		return "warn"
	default:
		return "ok"
	}
}

// daysUntil returns whole days from today (UTC) to an ISO date; negative when
// past.
func daysUntil(iso string, now time.Time) int {
	t, err := time.Parse("2006-01-02", iso)
	if err != nil {
		return 0
	}
	return int(t.Sub(now.UTC().Truncate(24*time.Hour)).Hours() / 24)
}

// loadLicenseRows joins the firewall list with stored license data.
func (s *Server) loadLicenseRows(ctx context.Context) ([]licenseRow, error) {
	fws, err := s.store.ListFirewalls(ctx)
	if err != nil {
		return nil, err
	}
	db, err := s.insightsDB()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	rows := make([]licenseRow, 0, len(fws))
	for _, fw := range fws {
		row := licenseRow{FwID: fw.ID, FQDN: fw.FQDN, Level: "unknown"}
		err := db.QueryRow(`SELECT COALESCE(serial,''), COALESCE(hostname,''), COALESCE(model,''),
			COALESCE(version,''), COALESCE(build,''), COALESCE(registration,''), COALESCE(ha_mode,''),
			COALESCE(fetched_at,''), COALESCE(fetch_error,'')
			FROM license_status WHERE fw_id = ?`, fw.ID).Scan(
			&row.Serial, &row.Hostname, &row.Model, &row.Version, &row.Build,
			&row.Registration, &row.HAMode, &row.FetchedAt, &row.FetchError)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ents, err := db.Query(`SELECT COALESCE(service,''), COALESCE(version,''), COALESCE(expiry,''),
			COALESCE(last_update,''), COALESCE(result,'')
			FROM license_entitlements WHERE fw_id = ? ORDER BY service`, fw.ID)
		if err != nil {
			return nil, err
		}
		for ents.Next() {
			var e licenseEntitlement
			if err := ents.Scan(&e.Service, &e.Version, &e.Expiry, &e.LastUpdate, &e.Result); err != nil {
				_ = ents.Close()
				return nil, err
			}
			row.Entitlements = append(row.Entitlements, e)
			if e.Expiry != "" && (row.Expiry == "" || e.Expiry < row.Expiry) {
				row.Expiry = e.Expiry
			}
		}
		_ = ents.Close()
		if err := ents.Err(); err != nil {
			return nil, err
		}
		if row.Expiry != "" {
			row.DaysLeft = daysUntil(row.Expiry, now)
			row.Level = licenseLevel(row.DaysLeft)
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].FQDN < rows[j].FQDN })
	return rows, nil
}

type licensesData struct {
	Base     BaseData
	Rows     []licenseRow
	Expiring int // devices at warn/crit
	Expired  int
	Unknown  int // never fetched or fetch failed
	Error    string
}

func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request) {
	data := licensesData{Base: s.base(r, "Licenses", "licenses")}
	rows, err := s.loadLicenseRows(r.Context())
	if err != nil {
		s.logger.Error("licenses page failed", "err", err)
		data.Error = "Failed to load license data. Check logs for details."
	}
	data.Rows = rows
	for _, row := range rows {
		switch row.Level {
		case "warn", "crit":
			data.Expiring++
		case "expired":
			data.Expired++
		case "unknown":
			data.Unknown++
		}
	}
	s.render(w, "licenses.html", data)
}

// handleLicenseRefresh triggers a background re-collection for one firewall.
func (s *Server) handleLicenseRefresh(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fws, err := s.store.ListFirewalls(r.Context())
	if err != nil {
		s.logger.Error("license refresh: list firewalls failed", "err", err)
		http.Redirect(w, r, "/licenses", http.StatusSeeOther)
		return
	}
	for _, fw := range fws {
		if fw.ID == id {
			s.store.LogActivity(s.sess.User(r).Username, "License Refresh", "Triggered license fetch for "+fw.FQDN)
			go s.fetchLicense(fw)
			break
		}
	}
	http.Redirect(w, r, "/licenses", http.StatusSeeOther)
}

// handleLicenseRefreshAll triggers a background sweep over every firewall.
func (s *Server) handleLicenseRefreshAll(w http.ResponseWriter, r *http.Request) {
	s.store.LogActivity(s.sess.User(r).Username, "License Refresh", "Triggered license fetch for all firewalls")
	go s.refreshLicensesJob()
	http.Redirect(w, r, "/licenses", http.StatusSeeOther)
}

// ---- dashboard card ---------------------------------------------------------

// licenseIssue is one device with an entitlement expired or expiring within
// licenseWarnDays, surfaced on the dashboard.
type licenseIssue struct {
	FwID     int    `json:"fw_id"`
	FQDN     string `json:"fqdn"`
	Serial   string `json:"serial,omitempty"`
	Service  string `json:"service"`
	Expiry   string `json:"expiry"`
	DaysLeft int    `json:"days_left"`
	Level    string `json:"level"` // warn | crit | expired
}

// licenseIssues lists the soonest-expiring entitlement per affected device.
// Any error yields an empty list so the dashboard card simply does not appear.
func (s *Server) licenseIssues(fqdnByID map[int]string) []licenseIssue {
	db, err := s.insightsDB()
	if err != nil {
		s.logger.Warn("dashboard license lookup failed", "err", err)
		return nil
	}
	now := time.Now()
	cutoff := now.UTC().AddDate(0, 0, licenseWarnDays).Format("2006-01-02")
	// Soonest expiring entitlement per device, only when inside the window.
	rows, err := db.Query(`SELECT e.fw_id, COALESCE(s.serial,''), e.service, MIN(e.expiry)
		FROM license_entitlements e
		LEFT JOIN license_status s ON s.fw_id = e.fw_id
		WHERE e.expiry != '' AND e.expiry <= ?
		GROUP BY e.fw_id
		ORDER BY MIN(e.expiry)`, cutoff)
	if err != nil {
		s.logger.Warn("dashboard license lookup failed", "err", err)
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []licenseIssue
	for rows.Next() {
		var is licenseIssue
		if err := rows.Scan(&is.FwID, &is.Serial, &is.Service, &is.Expiry); err != nil {
			s.logger.Warn("dashboard license scan failed", "err", err)
			return out
		}
		is.FQDN = fqdnByID[is.FwID]
		is.DaysLeft = daysUntil(is.Expiry, now)
		is.Level = licenseLevel(is.DaysLeft)
		out = append(out, is)
	}
	if err := rows.Err(); err != nil {
		s.logger.Warn("dashboard license lookup failed", "err", err)
	}
	return out
}
