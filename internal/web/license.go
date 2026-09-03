// License & entitlement inventory: a background collector fetches each
// firewall's serial number and FortiGuard contract expiry dates over SSH
// (get system status + diagnose autoupdate versions) once per day, stores
// them in the insights DB and serves the /licenses page plus the dashboard's
// expiring-licenses card. The FortiCare hardware/support contract is not
// exposed by these commands, so the inventory covers FortiGuard service
// entitlements; on HA clusters the primary answers, so its serial is recorded.
//
// The same sweep also inventories each firewall's managed FortiSwitches
// (diagnose switch-controller switch-info status + get switch-controller
// managed-switch, the latter to flag configured-but-disconnected switches)
// and FortiAPs (show wireless-controller wtp). Their FortiCare contracts are
// not visible from the FortiGate at all — the child rows carry serial, model
// and firmware so the contract can be looked up in FortiCloud by serial.
// `execute …` commands (e.g. get-conn-status) are unavailable over the SSH
// exec channel, and failed commands still exit 0 with the error text as
// output — parsers must simply find nothing in such output.
package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	graylogdevicedata "github.com/arumes31/fortigate-scp-backup/extensions/graylog_device_data"
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

// licenseDevice is one managed child device (FortiSwitch or FortiAP) of a
// firewall. Version/Build are only known for connected switches; APs expose
// no firmware over the available commands. Status is online/offline for
// switches and "" (unknown) for APs, whose per-device state is not visible.
// Origin and IP are read-time only (never persisted): Origin "logs" marks data
// contributed by the graylog_device_data extension's observed inventory — a
// backfilled serial on an SSH row, or a whole row the SSH sweep never saw.
type licenseDevice struct {
	Kind    string // switch | ap
	Name    string
	Serial  string
	Model   string
	Version string
	Build   string
	Status  string // online | offline | ""
	Origin  string // "" (SSH) | "logs"
	IP      string // APs discovered from logs only
}

// ---- SSH collection ---------------------------------------------------------

// sshRunCommands opens one SSH connection to the firewall (same credentials
// the backup engine uses) and runs each command in its own session. A single
// deadline covers the whole exchange: on expiry the client is closed, which
// unblocks any in-flight session read.
func sshRunCommands(fw models.Firewall, hostKey ssh.HostKeyCallback, cmds []string) (map[string]string, error) {
	if hostKey == nil {
		return nil, errors.New("SSH host key verification is not configured")
	}
	cfg := &ssh.ClientConfig{
		User:            fw.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(fw.Password)},
		HostKeyCallback: hostKey,
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

// parseSwitchInfoStatus extracts connected managed switches from
// `diagnose switch-controller switch-info status`. Sections look like:
//
//	Managed Switch : EX-CORE01     0
//	Version: FortiSwitch-524D v7.6.6,build1137,251212 (GA)
//	Serial-Number: S524DN5020000043
//	Hostname: EX-CORE01
//
// The Version value has the same shape as `get system status`, so
// reStatusVersion splits model/version/build. Only switches currently talking
// to the controller appear here.
func parseSwitchInfoStatus(out string) []licenseDevice {
	var devs []licenseDevice
	var cur *licenseDevice
	for _, raw := range strings.Split(out, "\n") {
		line := stripPrompt(strings.TrimRight(raw, "\r"))
		if name, ok := strings.CutPrefix(line, "Managed Switch : "); ok {
			f := strings.Fields(name)
			if len(f) == 0 {
				cur = nil
				continue
			}
			devs = append(devs, licenseDevice{Kind: "switch", Name: f[0], Status: "online"})
			cur = &devs[len(devs)-1]
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "Version":
			if m := reStatusVersion.FindStringSubmatch(val); m != nil {
				cur.Model, cur.Version, cur.Build = m[1], m[2], m[3]
			} else {
				cur.Version = val
			}
		case "Serial-Number":
			cur.Serial = val
		case "Hostname":
			if cur.Name == "" {
				cur.Name = val
			}
		}
	}
	return devs
}

// parseManagedSwitchList extracts the CONFIGURED switch ids from
// `get switch-controller managed-switch` ("switch-id: EX-CORE01" lines; the
// id is the serial unless renamed). Together with parseSwitchInfoStatus this
// flags switches that are configured but not connected.
func parseManagedSwitchList(out string) []string {
	var ids []string
	for _, raw := range strings.Split(out, "\n") {
		line := stripPrompt(strings.TrimRight(raw, "\r"))
		if id, ok := strings.CutPrefix(line, "switch-id: "); ok {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// mergeSwitchDevices returns one row per configured switch id, enriched from
// the connected-switch details when present; a configured id with no
// connected section reads offline. Connected switches missing from the
// configured list (multi-vdom boxes where the global `get` fails) are kept.
func mergeSwitchDevices(configured []string, connected []licenseDevice) []licenseDevice {
	byName := map[string]int{}
	for i, d := range connected {
		byName[d.Name] = i
	}
	var out []licenseDevice
	seen := map[string]bool{}
	for _, id := range configured {
		if i, ok := byName[id]; ok {
			out = append(out, connected[i])
		} else {
			out = append(out, licenseDevice{Kind: "switch", Name: id, Status: "offline"})
		}
		seen[id] = true
	}
	for _, d := range connected {
		if !seen[d.Name] {
			out = append(out, d)
		}
	}
	return out
}

// mergeObservedDevices folds the graylog_device_data extension's observed
// switch/AP inventory into one firewall's SSH-collected child devices:
//   - serial backfill: an SSH switch row without a serial (the CLI reports no
//     serial for an offline switch) takes the observed serial matched by name
//     (case-insensitive). An ambiguous name — two observed serials claiming
//     it — stays empty rather than guessing.
//   - discovery: observed devices the SSH sweep did not report at all are
//     appended as extra rows with Origin "logs" and no fabricated status or
//     firmware. SSH stays authoritative when both sources know a device.
//
// The result keeps switches before APs, discovered rows after the SSH rows of
// their kind, sorted by name.
func mergeObservedDevices(devs []licenseDevice, obs []graylogdevicedata.ObservedDevice) []licenseDevice {
	if len(obs) == 0 {
		return devs
	}
	serialsByName := map[string]map[string]bool{} // lower(switch name) → observed serials
	for _, o := range obs {
		if o.Kind != "switch" || o.Name == "" || o.Serial == "" {
			continue
		}
		k := strings.ToLower(o.Name)
		if serialsByName[k] == nil {
			serialsByName[k] = map[string]bool{}
		}
		serialsByName[k][o.Serial] = true
	}
	out := make([]licenseDevice, len(devs))
	copy(out, devs)
	knownSerial := map[string]bool{} // kind + "|" + serial after SSH + backfill
	knownSwitchName := map[string]bool{}
	for i := range out {
		d := &out[i]
		if d.Kind == "switch" && d.Name != "" {
			if d.Serial == "" {
				if set := serialsByName[strings.ToLower(d.Name)]; len(set) == 1 {
					for s := range set {
						d.Serial = s
					}
					d.Origin = "logs"
				}
			}
			knownSwitchName[strings.ToLower(d.Name)] = true
		}
		if d.Serial != "" {
			knownSerial[d.Kind+"|"+d.Serial] = true
		}
	}
	var discovered []licenseDevice
	for _, o := range obs {
		if o.Serial == "" || knownSerial[o.Kind+"|"+o.Serial] {
			continue
		}
		// A name match on a serial-less (or ambiguous) SSH switch row means
		// this is the same configured switch, not an extra device.
		if o.Kind == "switch" && o.Name != "" && knownSwitchName[strings.ToLower(o.Name)] {
			continue
		}
		name := o.Name
		if name == "" {
			name = o.Serial
		}
		discovered = append(discovered, licenseDevice{
			Kind: o.Kind, Name: name, Serial: o.Serial, IP: o.IP, Origin: "logs",
		})
	}
	if len(discovered) == 0 {
		return out
	}
	sort.SliceStable(discovered, func(i, j int) bool { return discovered[i].Name < discovered[j].Name })
	var switches, aps []licenseDevice
	for _, list := range [][]licenseDevice{out, discovered} {
		for _, d := range list {
			if d.Kind == "switch" {
				switches = append(switches, d)
			} else {
				aps = append(aps, d)
			}
		}
	}
	return append(switches, aps...)
}

// reWTPEdit / reWTPSet pick AP entries out of `show wireless-controller wtp`.
var (
	reWTPEdit   = regexp.MustCompile(`^\s*edit "([^"]+)"`)
	reWTPSet    = regexp.MustCompile(`^\s*set (name|wtp-profile) "([^"]+)"`)
	reAPSerial  = regexp.MustCompile(`^FP([0-9A-Z]{4})`)
	reAPProfile = regexp.MustCompile(`^FAP([0-9A-Z]+)-`)
)

// apModel derives the FortiAP model from its serial prefix (FP231G… →
// FortiAP-231G), falling back to the profile name (FAP231G-default). The
// FortiGate exposes no other model or firmware detail for APs over the exec
// channel.
func apModel(serial, profile string) string {
	if m := reAPSerial.FindStringSubmatch(serial); m != nil {
		return "FortiAP-" + m[1]
	}
	if m := reAPProfile.FindStringSubmatch(profile); m != nil {
		return "FortiAP-" + m[1]
	}
	return ""
}

// parseWTPConfig extracts the configured FortiAPs from
// `show wireless-controller wtp`: the edit key is the AP serial, `set name`
// its display name and `set wtp-profile` hints the model when the serial
// prefix does not.
func parseWTPConfig(out string) []licenseDevice {
	var devs []licenseDevice
	var cur *licenseDevice
	var profile string
	flush := func() {
		if cur != nil {
			cur.Model = apModel(cur.Serial, profile)
			if cur.Name == "" {
				cur.Name = cur.Serial
			}
		}
		cur, profile = nil, ""
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if m := reWTPEdit.FindStringSubmatch(line); m != nil {
			flush()
			devs = append(devs, licenseDevice{Kind: "ap", Serial: m[1]})
			cur = &devs[len(devs)-1]
			continue
		}
		if cur == nil {
			continue
		}
		if m := reWTPSet.FindStringSubmatch(line); m != nil {
			if m[1] == "name" {
				cur.Name = m[2]
			} else {
				profile = m[2]
			}
		}
	}
	flush()
	return devs
}

// ---- storage ----------------------------------------------------------------

// storeLicenseResult upserts one device's collection outcome. On success the
// entitlement and child-device rows are replaced atomically; on failure only
// the error and attempt time are recorded, so the last good data stays
// visible.
func storeLicenseResult(db *sql.DB, fwID int, st *licenseStatus, ents []licenseEntitlement, devs []licenseDevice, fetchErr string) error {
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
	if _, err := tx.Exec(`DELETE FROM license_devices WHERE fw_id = ?`, fwID); err != nil {
		return err
	}
	for _, d := range devs {
		if _, err := tx.Exec(`INSERT INTO license_devices
			(fw_id, kind, name, serial, model, version, build, status) VALUES (?,?,?,?,?,?,?,?)`,
			fwID, d.Kind, d.Name, d.Serial, d.Model, d.Version, d.Build, d.Status); err != nil {
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
	out, err := sshRunCommands(fw, s.hostKeyCallbackForSSH(), []string{
		"get system status",
		"diagnose autoupdate versions",
		"diagnose switch-controller switch-info status",
		"get switch-controller managed-switch",
		"show wireless-controller wtp",
	})
	if err != nil {
		s.logger.Warn("license fetch failed", "fqdn", fw.FQDN, "err", err)
		if serr := storeLicenseResult(db, fw.ID, nil, nil, nil, err.Error()); serr != nil {
			s.logger.Error("license store failed", "fqdn", fw.FQDN, "err", serr)
		}
		return
	}
	st := parseSystemStatus(out["get system status"])
	ents := parseAutoupdateVersions(out["diagnose autoupdate versions"])
	devs := mergeSwitchDevices(
		parseManagedSwitchList(out["get switch-controller managed-switch"]),
		parseSwitchInfoStatus(out["diagnose switch-controller switch-info status"]))
	devs = append(devs, parseWTPConfig(out["show wireless-controller wtp"])...)
	if err := storeLicenseResult(db, fw.ID, &st, ents, devs, ""); err != nil {
		s.logger.Error("license store failed", "fqdn", fw.FQDN, "err", err)
		return
	}
	s.logger.Info("license data refreshed", "fqdn", fw.FQDN, "serial", st.Serial,
		"entitlements", len(ents), "children", len(devs))
}

// refreshLicensesJob is the daily sweep over every firewall, run by the
// scheduler. Devices are collected sequentially with a small gap so the sweep
// never bursts SSH connections across the fleet. Progress is published via
// licenseProgress for the page's poller; concurrent sweeps coalesce.
func (s *Server) refreshLicensesJob() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	fws, err := s.store.ListFirewalls(ctx)
	cancel()
	if err != nil {
		s.logger.Error("license sweep: list firewalls failed", "err", err)
		return
	}
	if !s.licenseProgress.begin(len(fws)) {
		return
	}
	defer s.licenseProgress.end()
	for i, fw := range fws {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		s.fetchLicense(fw)
		s.licenseProgress.step(fw.FQDN)
	}
}

// handleLicenseStatus reports the running sweep's progress for the page's
// poller.
func (s *Server) handleLicenseStatus(w http.ResponseWriter, r *http.Request) {
	running, done, total, current := s.licenseProgress.snapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"running": running, "done": done, "total": total, "current": current,
	})
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
	FetchedAt    time.Time
	FetchError   string
	Expiry       string // driving entitlement expiry (ISO), "" unknown
	DaysLeft     int
	Level        string // ok | warn | crit | expired | unknown
	Lapsed       int    // long-expired services not driving the status
	Entitlements []licenseEntitlement
	Devices      []licenseDevice // managed switches, then APs
	Switches     int
	APs          int
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

// licenseClass is the device-level rollup derived from all entitlements.
type licenseClass struct {
	Expiry   string // driving expiry date (ISO), "" when unknown
	Service  string // the service that drives Expiry
	DaysLeft int
	Level    string // ok | warn | crit | expired | unknown
	Lapsed   int    // already-expired services (informational unless all are)
}

// classifyLicense rolls per-service entitlements up to one device status.
// Real fleets carry long-lapsed entries for services that were never part of
// the current contract bundle (e.g. one item expired years ago while AV/IPS
// run to next year) — those must not mark the device expired. The device
// level therefore follows the earliest ACTIVE expiry; already-expired
// services are only counted, and the device reads "expired" solely when no
// active dated entitlement remains.
func classifyLicense(ents []licenseEntitlement, now time.Time) licenseClass {
	today := now.UTC().Format("2006-01-02")
	c := licenseClass{Level: "unknown"}
	var maxLapsed, maxLapsedSvc = "", ""
	for _, e := range ents {
		if e.Expiry == "" {
			continue
		}
		if e.Expiry < today { // lapsed
			c.Lapsed++
			if e.Expiry > maxLapsed {
				maxLapsed, maxLapsedSvc = e.Expiry, e.Service
			}
			continue
		}
		if c.Expiry == "" || e.Expiry < c.Expiry {
			c.Expiry, c.Service = e.Expiry, e.Service
		}
	}
	switch {
	case c.Expiry != "": // at least one active entitlement drives the status
		c.DaysLeft = daysUntil(c.Expiry, now)
		c.Level = licenseLevel(c.DaysLeft)
	case c.Lapsed > 0: // nothing active at all → genuinely expired
		c.Expiry, c.Service = maxLapsed, maxLapsedSvc
		c.DaysLeft = daysUntil(c.Expiry, now)
		c.Level = "expired"
	}
	return c
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
	// Observed switch/AP inventory from the graylog_device_data extension —
	// read-time enrichment only; any error just means "no observations".
	observed, obsErr := graylogdevicedata.ListObservedDevices(s.cfg.DataDir)
	if obsErr != nil {
		s.logger.Warn("licenses: observed-device lookup failed", "err", obsErr)
	}
	now := time.Now()
	rows := make([]licenseRow, 0, len(fws))
	for _, fw := range fws {
		row := licenseRow{FwID: fw.ID, FQDN: fw.FQDN, Level: "unknown"}
		var fetchedAt string
		err := db.QueryRow(`SELECT COALESCE(serial,''), COALESCE(hostname,''), COALESCE(model,''),
			COALESCE(version,''), COALESCE(build,''), COALESCE(registration,''), COALESCE(ha_mode,''),
			COALESCE(fetched_at,''), COALESCE(fetch_error,'')
			FROM license_status WHERE fw_id = ?`, fw.ID).Scan(
			&row.Serial, &row.Hostname, &row.Model, &row.Version, &row.Build,
			&row.Registration, &row.HAMode, &fetchedAt, &row.FetchError)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if parsed, parseErr := time.Parse(time.RFC3339, fetchedAt); parseErr == nil {
			row.FetchedAt = parsed
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
		}
		_ = ents.Close()
		if err := ents.Err(); err != nil {
			return nil, err
		}
		devs, err := db.Query(`SELECT kind, name, COALESCE(serial,''), COALESCE(model,''),
			COALESCE(version,''), COALESCE(build,''), COALESCE(status,'')
			FROM license_devices WHERE fw_id = ?
			ORDER BY CASE kind WHEN 'switch' THEN 0 ELSE 1 END, name`, fw.ID)
		if err != nil {
			return nil, err
		}
		for devs.Next() {
			var d licenseDevice
			if err := devs.Scan(&d.Kind, &d.Name, &d.Serial, &d.Model, &d.Version, &d.Build, &d.Status); err != nil {
				_ = devs.Close()
				return nil, err
			}
			row.Devices = append(row.Devices, d)
		}
		_ = devs.Close()
		if err := devs.Err(); err != nil {
			return nil, err
		}
		row.Devices = mergeObservedDevices(row.Devices, observed[fw.ID])
		for _, d := range row.Devices {
			if d.Kind == "switch" {
				row.Switches++
			} else {
				row.APs++
			}
		}
		cls := classifyLicense(row.Entitlements, now)
		row.Expiry, row.DaysLeft, row.Level, row.Lapsed = cls.Expiry, cls.DaysLeft, cls.Level, cls.Lapsed
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

// licenseIssues lists devices whose rolled-up license status is expiring or
// expired, using the same classification as the Licenses page — so a single
// long-lapsed service among otherwise-active entitlements never raises an
// alert. Any error yields an empty list so the card simply does not appear.
func (s *Server) licenseIssues(fqdnByID map[int]string) []licenseIssue {
	db, err := s.insightsDB()
	if err != nil {
		s.logger.Warn("dashboard license lookup failed", "err", err)
		return nil
	}
	rows, err := db.Query(`SELECT e.fw_id, COALESCE(s.serial,''), e.service, e.expiry
		FROM license_entitlements e
		LEFT JOIN license_status s ON s.fw_id = e.fw_id
		WHERE e.expiry != ''`)
	if err != nil {
		s.logger.Warn("dashboard license lookup failed", "err", err)
		return nil
	}
	defer func() { _ = rows.Close() }()
	type devEnts struct {
		serial string
		ents   []licenseEntitlement
	}
	byFw := map[int]*devEnts{}
	for rows.Next() {
		var fwID int
		var serial string
		var e licenseEntitlement
		if err := rows.Scan(&fwID, &serial, &e.Service, &e.Expiry); err != nil {
			s.logger.Warn("dashboard license scan failed", "err", err)
			return nil
		}
		d := byFw[fwID]
		if d == nil {
			d = &devEnts{serial: serial}
			byFw[fwID] = d
		}
		d.ents = append(d.ents, e)
	}
	if err := rows.Err(); err != nil {
		s.logger.Warn("dashboard license lookup failed", "err", err)
		return nil
	}
	now := time.Now()
	var out []licenseIssue
	for fwID, d := range byFw {
		cls := classifyLicense(d.ents, now)
		if cls.Level != "warn" && cls.Level != "crit" && cls.Level != "expired" {
			continue
		}
		out = append(out, licenseIssue{
			FwID: fwID, FQDN: fqdnByID[fwID], Serial: d.serial,
			Service: cls.Service, Expiry: cls.Expiry, DaysLeft: cls.DaysLeft, Level: cls.Level,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Expiry < out[j].Expiry })
	return out
}
