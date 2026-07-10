package graylogdevicedata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// firewallRef is the minimal firewall projection used by the worker.
type firewallRef struct {
	ID   int
	FQDN string
}

// switchFirewalls lists the firewalls whose latest audited configuration
// manages at least one FortiSwitch. The firewall list comes from the shared
// PostgreSQL store; the switch information from the core's insights cache
// (audit_cache.results_json) in DataDir.
func (e *Extension) switchFirewalls() ([]firewallRef, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rows, err := e.pool.Query(ctx, `SELECT id, fqdn FROM firewalls ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []firewallRef
	for rows.Next() {
		var fw firewallRef
		if scanErr := rows.Scan(&fw.ID, &fw.FQDN); scanErr != nil {
			return nil, scanErr
		}
		all = append(all, fw)
	}

	withSwitches, err := e.switchCapableIDs()
	if err != nil {
		// Without the audit cache we cannot tell which firewalls have
		// switches; fetch none rather than hammering Graylog for all — but
		// say so, otherwise an empty inventory is undiagnosable.
		e.logger.Warn("graylog device worker: audit cache unavailable, skipping sweep", "err", err)
		return nil, err
	}

	var out []firewallRef
	for _, fw := range all {
		if withSwitches[fw.ID] {
			out = append(out, fw)
		}
	}
	return out, nil
}

// vpnConfigSources resolves the Graylog `source` name(s) for a firewall from
// the fgt_adm_vpn_conf extension's database, where operators record each
// firewall's real log source — including both node hostnames of an HA cluster
// (cluster_hostnames). Graylog `source` is the FortiGate's devname/hostname,
// which frequently differs from the backup FQDN, so this mapping is what makes
// the device/STP queries match. The firewall is matched by FQDN (and its short
// host) against the unique firewallname / dns_name / dns_name_full columns,
// case-insensitively. Returns nil when that DB is absent or nothing matches, so
// the caller falls back to deriving the source from the FQDN.
func (e *Extension) vpnConfigSources(fqdn string) []string {
	dbFile := filepath.Join(e.dataDir, "fgt-adm-vpn-conf-db.db")
	if _, err := os.Stat(dbFile); err != nil {
		// Missing DB is normal (fall back to the FQDN); a permission/I/O error
		// is not — log it so a silent empty source resolution is diagnosable.
		if !os.IsNotExist(err) {
			e.logger.Warn("graylog devices: cannot stat adm-vpn-conf db", "path", dbFile, "err", err)
		}
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		e.logger.Debug("graylog devices: cannot open adm-vpn-conf db", "err", err)
		return nil
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	short := sourceHost(fqdn)
	var firewallname, clusters string
	err = db.QueryRow(`SELECT COALESCE(firewallname,''), COALESCE(cluster_hostnames,'')
		FROM vpn_config
		WHERE lower(firewallname) IN (lower(?), lower(?))
		   OR lower(dns_name)      IN (lower(?), lower(?))
		   OR lower(dns_name_full) IN (lower(?), lower(?))
		LIMIT 1`,
		fqdn, short, fqdn, short, fqdn, short).Scan(&firewallname, &clusters)
	if err != nil {
		if err != sql.ErrNoRows {
			e.logger.Debug("graylog devices: adm-vpn-conf lookup failed", "fqdn", fqdn, "err", err)
		}
		return nil
	}
	if hs := splitHostnames(clusters); len(hs) > 0 {
		return hs
	}
	if firewallname != "" {
		return []string{firewallname}
	}
	return nil
}

// splitHostnames splits a comma-separated cluster-hostname list, trimming
// blanks (mirrors the fgt_adm_vpn_conf helper of the same name).
func splitHostnames(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// switchCapableIDs returns the ids of every firewall whose cached audit
// result contains managed FortiSwitches, from one pass over the core's
// insights database. The core creates that database lazily, so a missing
// file is reported as an error (the caller logs it) instead of being
// mistaken for "no switches anywhere".
func (e *Extension) switchCapableIDs() (map[int]bool, error) {
	dbFile := filepath.Join(e.dataDir, "forti-insights.db")
	if _, err := os.Stat(dbFile); err != nil {
		return nil, fmt.Errorf("insights cache not available yet: %w", err)
	}
	insights, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = insights.Close() }()
	insights.SetMaxOpenConns(1)

	rows, err := insights.Query("SELECT fw_id, results_json FROM audit_cache")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := map[int]bool{}
	for rows.Next() {
		var fwID int
		var blob string
		if scanErr := rows.Scan(&fwID, &blob); scanErr != nil {
			continue
		}
		var res struct {
			Switches []json.RawMessage `json:"switches"`
		}
		if jsonErr := json.Unmarshal([]byte(blob), &res); jsonErr == nil && len(res.Switches) > 0 {
			out[fwID] = true
		}
	}
	return out, rows.Err()
}

// deviceRetention bounds how long a device row survives without being seen
// again. Retaining rows across refreshes (instead of wiping them) preserves
// first-seen/last-seen history and keeps devices visible through Graylog
// gaps; the stale fade in the UI marks the ones not seen recently.
const deviceRetention = 30 * 24 * time.Hour

// refreshFirewall fetches the device inventory for one firewall from Graylog
// and upserts its stored rows: known devices keep their first_seen, unseen
// devices survive until deviceRetention. Returns the number of devices in
// this fetch. rangeSec optionally narrows the Graylog search window (used by
// the live topology refresh); "" uses the configured default.
func (e *Extension) refreshFirewall(fwID int, fqdn, rangeSec string) (int, error) {
	devices, err := e.fetchDevices(fqdn, rangeSec)
	if err != nil {
		return 0, err
	}
	now := time.Now().Format("2006-01-02 15:04:05")

	tx, err := e.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	for _, d := range devices {
		firstSeen := d.LastSeen
		if firstSeen == "" {
			firstSeen = now
		}
		// Newer log records may lack fields older ones had (hostname, VLAN):
		// only overwrite with non-empty values.
		if _, err := tx.Exec(`INSERT INTO devices
			(fw_id, mac, ip, vlan, port, switch_id, hostname, devtype, osname, osversion, vendor, first_seen, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, mac, ip) DO UPDATE SET
				vlan       = CASE WHEN excluded.vlan != '' THEN excluded.vlan ELSE vlan END,
				port       = CASE WHEN excluded.port != '' THEN excluded.port ELSE port END,
				switch_id  = CASE WHEN excluded.switch_id != '' THEN excluded.switch_id ELSE switch_id END,
				hostname   = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
				devtype    = CASE WHEN excluded.devtype != '' THEN excluded.devtype ELSE devtype END,
				osname     = CASE WHEN excluded.osname != '' THEN excluded.osname ELSE osname END,
				osversion  = CASE WHEN excluded.osversion != '' THEN excluded.osversion ELSE osversion END,
				vendor     = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE vendor END,
				last_seen  = excluded.last_seen,
				updated_at = excluded.updated_at`,
			fwID, d.Mac, d.IP, d.Vlan, d.Port, d.SwitchID, d.Hostname,
			d.DevType, d.OsName, d.OsVersion, d.Vendor, firstSeen, d.LastSeen, now); err != nil {
			return 0, err
		}
	}
	// Prune devices unseen past the retention window (updated_at is our own
	// lexicographically sortable format).
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM devices WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// STP/guard/link port states ride along on the same refresh; a failure
	// only costs the STP overlay (stale rows are kept), never the inventory.
	var edges []SwitchEdge
	if stp, events, recentEdges, serr := e.fetchStpStates(fqdn, rangeSec); serr != nil {
		e.logger.Warn("graylog stp fetch failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else {
		if serr := e.storeStp(fwID, stp, now); serr != nil {
			e.logger.Warn("graylog stp store failed", "fw_id", fwID, "err", serr)
		}
		if serr := e.storeStpEvents(fwID, events, now); serr != nil {
			e.logger.Warn("graylog stp event store failed", "fw_id", fwID, "err", serr)
		}
		edges = recentEdges
	}
	// Interlinks change rarely, so the recent STP window only reveals whichever
	// switch churned lately. A separate wide-window query keeps every switch's
	// stable uplinks; storeSwitchEdges upserts, keeping the newest role/ports.
	if topoEdges, serr := e.fetchSwitchEdges(fqdn); serr != nil {
		e.logger.Warn("graylog topology-edge fetch failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else {
		edges = append(edges, topoEdges...)
	}
	if len(edges) > 0 {
		if serr := e.storeSwitchEdges(fwID, edges, now); serr != nil {
			e.logger.Warn("graylog switch-edge store failed", "fw_id", fwID, "err", serr)
		}
	}

	// MAC add/move → wired switch-port sightings (the piece traffic logs lack).
	if mp, serr := e.fetchMacPorts(fqdn, rangeSec); serr != nil {
		e.logger.Warn("graylog mac-port fetch failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else if serr := e.storeMacSightings(fwID, mp, now); serr != nil {
		e.logger.Warn("graylog mac-port store failed", "fw_id", fwID, "err", serr)
	}

	// Wireless client ↔ AP ↔ SSID associations.
	if wc, serr := e.fetchWifiClients(fqdn, rangeSec); serr != nil {
		e.logger.Warn("graylog wifi fetch failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else if serr := e.storeWifi(fwID, wc, now); serr != nil {
		e.logger.Warn("graylog wifi store failed", "fw_id", fwID, "err", serr)
	}

	// VPN tunnel up/down state.
	if vs, serr := e.fetchVpnStatuses(fqdn, rangeSec); serr != nil {
		e.logger.Warn("graylog vpn fetch failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else if serr := e.storeVpn(fwID, vs, now); serr != nil {
		e.logger.Warn("graylog vpn store failed", "fw_id", fwID, "err", serr)
	}

	// HA liveness (newest HA event summary).
	if detail, serr := e.fetchHaDetail(fqdn, rangeSec); serr != nil {
		e.logger.Warn("graylog ha fetch failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else if detail != "" {
		if _, serr := e.db.Exec(`INSERT INTO ha_status (fw_id, detail, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(fw_id) DO UPDATE SET detail=excluded.detail, updated_at=excluded.updated_at`,
			fwID, detail, now); serr != nil {
			e.logger.Warn("graylog ha store failed", "fw_id", fwID, "err", serr)
		}
	}

	return len(devices), nil
}

// haDetail returns the stored HA event summary for a firewall ("" when none).
func (e *Extension) haDetail(fwID int) string {
	var detail string
	if err := e.db.QueryRow("SELECT detail FROM ha_status WHERE fw_id = ?", fwID).Scan(&detail); err != nil {
		return ""
	}
	return detail
}

// stpRetention bounds how long a port's STP/guard state survives without being
// seen again in a fetch. STP/guard events are one-time transitions, so a port
// whose triggering event has aged out of the Graylog query window stops
// appearing in fetchStpStates — wiping unseen ports on every refresh would make
// a still-active block silently vanish. Instead the last-known state is kept and
// only ports unseen for this long (decommissioned switches, renamed ports) are
// pruned, so the table cannot grow without bound.
const stpRetention = 30 * 24 * time.Hour

// storeStp upserts the STP port states returned by the latest fetch and prunes
// only ports not seen for stpRetention. It deliberately does not wipe unseen
// ports: a one-time BPDU/loop/root-guard block whose event is older than the
// query window stays visible until the port is seen forwarding again or ages
// out.
func (e *Extension) storeStp(fwID int, stp []StpPort, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range stp {
		// Per-field merge, not a full-row replace: a fetch often carries only
		// some event kinds for a port (e.g. a link flap with no fresh STP
		// event). role/state/link/serial are empty only when *not observed*
		// this fetch, so an empty value must keep the stored one — otherwise a
		// later link event would blank an aged-out "discarding"/"alternate"
		// block and it would silently drop off the dashboard, defeating the
		// retention above. guard is taken as-is: an empty guard is a recovery
		// that clears the block (matching the previous replace semantics).
		if _, err := tx.Exec(`INSERT INTO stp_ports
			(fw_id, switch_name, serial, port, role, state, guard, link, dot1x, last_change, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, switch_name, port) DO UPDATE SET
				serial      = CASE WHEN excluded.serial != '' THEN excluded.serial ELSE serial END,
				role        = CASE WHEN excluded.role   != '' THEN excluded.role   ELSE role   END,
				state       = CASE WHEN excluded.state  != '' THEN excluded.state  ELSE state  END,
				link        = CASE WHEN excluded.link   != '' THEN excluded.link   ELSE link   END,
				dot1x       = CASE WHEN excluded.dot1x  != '' THEN excluded.dot1x  ELSE dot1x  END,
				guard       = excluded.guard,
				last_change = excluded.last_change,
				updated_at  = excluded.updated_at`,
			fwID, p.SwitchName, p.Serial, p.Port, p.Role, p.State, p.Guard, p.Link, p.Dot1x, p.LastChange, now); err != nil {
			return err
		}
	}
	// updated_at is bumped above for every port in this fetch; the timestamp
	// format is lexicographically sortable, so a string comparison prunes the
	// ports that have been absent past the retention window.
	cutoff := time.Now().Add(-stpRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM stp_ports WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// BlockedPort is one switch port currently out of forwarding — blocked by STP
// or held down by a BPDU/loop/root guard — projected for the core dashboard's
// cross-firewall issue card. It is the extension's published view of the
// otherwise-private stp_ports table.
type BlockedPort struct {
	FwID   int
	Switch string
	Port   string
	Reason string // guard kind, else STP state, else role
	Since  string
}

// ListBlockedPorts opens the extension's private database read-only and returns
// every currently-blocked switch port across all firewalls. It is the exported
// entry point the dashboard uses instead of reaching into the schema directly,
// so the storage layout stays owned by this package. A missing database
// (extension disabled or never fetched) is not an error: it yields (nil, nil).
func ListBlockedPorts(dataDir string) ([]BlockedPort, error) {
	dbFile := filepath.Join(dataDir, "graylog-device-data.db")
	if _, err := os.Stat(dbFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil // extension disabled or never fetched: no blocked ports
		}
		return nil, err // permission / I/O error: surface it, don't hide as "none"
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	rows, err := db.Query(`SELECT fw_id, switch_name, port, role, state, guard, last_change
		FROM stp_ports
		WHERE guard != '' OR lower(state) IN ('discarding', 'blocking')
			OR lower(role) IN ('alternate', 'backup', 'disabled')
		ORDER BY fw_id, switch_name, port`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []BlockedPort
	for rows.Next() {
		var b BlockedPort
		var role, state, guard string
		// role/state/guard/last_change are NOT NULL DEFAULT '' in the schema, so
		// scanning into plain strings never hits a NULL.
		if scanErr := rows.Scan(&b.FwID, &b.Switch, &b.Port, &role, &state, &guard, &b.Since); scanErr != nil {
			return nil, scanErr
		}
		switch {
		case guard != "":
			b.Reason = guard
		case state != "":
			b.Reason = state
		default:
			b.Reason = role
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// listStp returns the stored STP port states of a firewall.
func (e *Extension) listStp(fwID int) ([]StpPort, error) {
	rows, err := e.db.Query(`SELECT switch_name, serial, port, role, state, guard, link, dot1x, last_change
		FROM stp_ports WHERE fw_id = ? ORDER BY switch_name, port`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StpPort
	for rows.Next() {
		var p StpPort
		if scanErr := rows.Scan(&p.SwitchName, &p.Serial, &p.Port, &p.Role, &p.State, &p.Guard, &p.Link, &p.Dot1x, &p.LastChange); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// stpEventRetention bounds the port event history (the port-detail timeline
// shows the last 48 hours).
const stpEventRetention = 48 * time.Hour

// storeStpEvents inserts the fetched events (idempotently — refreshes re-see
// events still inside the Graylog query window) and prunes history older
// than stpEventRetention. Event times are ISO-8601 from Graylog, so a string
// comparison against an ISO cutoff prunes correctly.
func (e *Extension) storeStpEvents(fwID int, events []StpEvent, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, ev := range events {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO stp_events
			(fw_id, switch_name, serial, port, kind, from_val, to_val, event_time, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fwID, ev.SwitchName, ev.Serial, ev.Port, ev.Kind, ev.From, ev.To, ev.Time, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().UTC().Add(-stpEventRetention).Format("2006-01-02T15:04:05")
	if _, err := tx.Exec("DELETE FROM stp_events WHERE fw_id = ? AND event_time < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// listStpEvents returns the stored port event history of a firewall, newest
// first, capped so a chatty network cannot flood the payload.
func (e *Extension) listStpEvents(fwID int) ([]StpEvent, error) {
	rows, err := e.db.Query(`SELECT switch_name, serial, port, kind, from_val, to_val, event_time
		FROM stp_events WHERE fw_id = ? ORDER BY event_time DESC LIMIT 500`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StpEvent
	for rows.Next() {
		var ev StpEvent
		if scanErr := rows.Scan(&ev.SwitchName, &ev.Serial, &ev.Port, &ev.Kind, &ev.From, &ev.To, &ev.Time); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// MultiMacPort flags a switch port behind which several distinct MACs were
// seen — usually an unmanaged mini-switch, an AP in bridge mode, or a
// virtualization host. Computed server-side so shared views and future
// dashboard cards get the same answer.
type MultiMacPort struct {
	SwitchID string `json:"switch_id"`
	Port     string `json:"port"`
	MacCount int    `json:"mac_count"`
}

// multiMacThreshold: two MACs are normal (phone + passthrough PC); three or
// more suggest a device hiding a network segment behind the port.
const multiMacThreshold = 3

// listMultiMacPorts returns the ports of a firewall with at least
// multiMacThreshold distinct MACs behind them, computed over the full MAC
// sighting graph (transit/uplink and AP ports naturally rank highest).
func (e *Extension) listMultiMacPorts(fwID int) ([]MultiMacPort, error) {
	rows, err := e.db.Query(`SELECT switch_name, port, COUNT(DISTINCT mac) AS macs
		FROM mac_sightings
		WHERE fw_id = ? AND port != '' AND switch_name != ''
		GROUP BY switch_name, port
		HAVING macs >= ?
		ORDER BY macs DESC`, fwID, multiMacThreshold)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MultiMacPort
	for rows.Next() {
		var m MultiMacPort
		if scanErr := rows.Scan(&m.SwitchID, &m.Port, &m.MacCount); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// storeMacSightings upserts the latest port per (MAC, switch) and prunes
// sightings unseen past the retention window. Every switch a frame transits
// learns the MAC, so keeping one row per switch preserves the topology signal
// (transit ports = uplinks) that a single-row-per-MAC table destroyed. A
// delete tombstone drops the MAC's row on that switch only (the MAC left THAT
// table; it may still be live elsewhere) — or everywhere when the event named
// no switch.
func (e *Extension) storeMacSightings(fwID int, ports []MacPort, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range ports {
		if p.Mac == "" {
			continue
		}
		if p.Deleted {
			if p.SwitchName != "" {
				if _, err := tx.Exec("DELETE FROM mac_sightings WHERE fw_id = ? AND mac = ? AND switch_name = ?",
					fwID, p.Mac, p.SwitchName); err != nil {
					return err
				}
			} else if _, err := tx.Exec("DELETE FROM mac_sightings WHERE fw_id = ? AND mac = ?", fwID, p.Mac); err != nil {
				return err
			}
			continue
		}
		if p.Port == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO mac_sightings (fw_id, mac, switch_name, port, vlan, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, mac, switch_name) DO UPDATE SET
				port       = excluded.port,
				vlan       = CASE WHEN excluded.vlan != '' THEN excluded.vlan ELSE vlan END,
				updated_at = excluded.updated_at`,
			fwID, p.Mac, p.SwitchName, p.Port, p.Vlan, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM mac_sightings WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// bestMacPins picks each MAC's most credible access-port sighting: the port
// carrying the FEWEST distinct MACs (a client port, not an uplink/AP trunk —
// a transit port sees every MAC crossing it), ties broken by recency. MACs
// whose every sighting is on a many-MAC port keep the least-crowded one; the
// multi-MAC flag in the UI marks the residual uncertainty.
func (e *Extension) bestMacPins(fwID int) (map[string]MacPort, error) {
	rows, err := e.db.Query(`SELECT mac, switch_name, port, vlan, updated_at
		FROM mac_sightings WHERE fw_id = ? AND port != ''`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	type sighting struct {
		MacPort
		updatedAt string
	}
	var all []sighting
	portMacs := map[string]int{} // "switch|port" → distinct MACs
	seenPortMac := map[string]bool{}
	for rows.Next() {
		var s sighting
		if scanErr := rows.Scan(&s.Mac, &s.SwitchName, &s.Port, &s.Vlan, &s.updatedAt); scanErr != nil {
			return nil, scanErr
		}
		all = append(all, s)
		pk := s.SwitchName + "|" + s.Port
		if !seenPortMac[pk+"|"+s.Mac] {
			seenPortMac[pk+"|"+s.Mac] = true
			portMacs[pk]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	best := map[string]MacPort{}
	bestScore := map[string]int{}
	bestTime := map[string]string{}
	for _, s := range all {
		score := portMacs[s.SwitchName+"|"+s.Port]
		if _, ok := best[s.Mac]; !ok || score < bestScore[s.Mac] ||
			(score == bestScore[s.Mac] && s.updatedAt > bestTime[s.Mac]) {
			best[s.Mac] = s.MacPort
			bestScore[s.Mac] = score
			bestTime[s.Mac] = s.updatedAt
		}
	}
	return best, nil
}

// storeSwitchEdges upserts the observed switch-side trunks (role updates only
// when the newer fetch carries one; member ports merge) and prunes stale rows.
func (e *Extension) storeSwitchEdges(fwID int, edges []SwitchEdge, now string) error {
	if len(edges) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, g := range edges {
		if g.SwitchSN == "" || g.Trunk == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO switch_edges (fw_id, switch_sn, switch_name, trunk, role, ports, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, switch_sn, trunk) DO UPDATE SET
				switch_name = CASE WHEN excluded.switch_name != '' THEN excluded.switch_name ELSE switch_name END,
				role        = CASE WHEN excluded.role != '' THEN excluded.role ELSE role END,
				ports       = CASE WHEN excluded.ports != '' THEN excluded.ports ELSE ports END,
				updated_at  = excluded.updated_at`,
			fwID, g.SwitchSN, g.SwitchName, g.Trunk, g.Role, strings.Join(g.Ports, ","), now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM switch_edges WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// listSwitchEdges returns the stored switch-edge observations for a firewall.
func (e *Extension) listSwitchEdges(fwID int) ([]SwitchEdge, error) {
	rows, err := e.db.Query(`SELECT switch_sn, switch_name, trunk, role, ports
		FROM switch_edges WHERE fw_id = ? ORDER BY switch_name, trunk`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SwitchEdge
	for rows.Next() {
		var g SwitchEdge
		var ports string
		if scanErr := rows.Scan(&g.SwitchSN, &g.SwitchName, &g.Trunk, &g.Role, &ports); scanErr != nil {
			return nil, scanErr
		}
		if ports != "" {
			g.Ports = strings.Split(ports, ",")
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// storeWifi upserts the latest wireless association per MAC (full field replace,
// since it is a live snapshot) and prunes stale rows.
func (e *Extension) storeWifi(fwID int, clients []WifiClient, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, w := range clients {
		if w.Mac == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO wifi_clients (fw_id, mac, ap, ssid, signal, channel, vlan, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, mac) DO UPDATE SET
				ap=excluded.ap, ssid=excluded.ssid, signal=excluded.signal,
				channel=excluded.channel,
				vlan=CASE WHEN excluded.vlan != '' THEN excluded.vlan ELSE vlan END,
				updated_at=excluded.updated_at`,
			fwID, w.Mac, w.Ap, w.Ssid, w.Signal, w.Channel, w.Vlan, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM wifi_clients WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// storeVpn upserts the latest up/down state per tunnel and prunes stale rows.
func (e *Extension) storeVpn(fwID int, statuses []VpnStatus, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, v := range statuses {
		if v.Name == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO vpn_status (fw_id, name, remip, type, status, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, name) DO UPDATE SET
				remip=CASE WHEN excluded.remip != '' THEN excluded.remip ELSE remip END,
				type=CASE WHEN excluded.type != '' THEN excluded.type ELSE type END,
				status=excluded.status, updated_at=excluded.updated_at`,
			fwID, v.Name, v.RemIP, v.Type, v.Status, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM vpn_status WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// listWifi returns the stored wireless associations of a firewall.
func (e *Extension) listWifi(fwID int) ([]WifiClient, error) {
	rows, err := e.db.Query(`SELECT mac, ap, ssid, signal, channel, vlan
		FROM wifi_clients WHERE fw_id = ? ORDER BY ap, ssid, mac`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []WifiClient
	for rows.Next() {
		var w WifiClient
		if scanErr := rows.Scan(&w.Mac, &w.Ap, &w.Ssid, &w.Signal, &w.Channel, &w.Vlan); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// listVpn returns the stored VPN tunnel states of a firewall.
func (e *Extension) listVpn(fwID int) ([]VpnStatus, error) {
	rows, err := e.db.Query(`SELECT name, remip, type, status
		FROM vpn_status WHERE fw_id = ? ORDER BY name`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []VpnStatus
	for rows.Next() {
		var v VpnStatus
		if scanErr := rows.Scan(&v.Name, &v.RemIP, &v.Type, &v.Status); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// listDevices returns the stored inventory of a firewall with MAC/IP sharing
// flags computed, plus the time of the last refresh ("" when never fetched).
// The wired switch/port comes from the mac_ports join (FortiSwitch MAC events)
// when present, and wireless AP/SSID/signal from the wifi_clients join.
func (e *Extension) listDevices(fwID int) ([]Device, string, error) {
	// Best access-port pin per MAC from the sighting graph (fewest-MACs port,
	// so a client is never pinned onto the uplink ports its frames transit).
	pins, err := e.bestMacPins(fwID)
	if err != nil {
		return nil, "", err
	}

	rows, err := e.db.Query(`SELECT d.mac, d.ip, d.vlan, d.port, d.switch_id, d.hostname,
			d.devtype, d.osname, d.osversion, d.vendor, d.first_seen, d.last_seen, d.updated_at,
			COALESCE(w.ap, ''), COALESCE(w.ssid, ''), COALESCE(w.signal, '')
		FROM devices d
		LEFT JOIN wifi_clients w ON w.fw_id = d.fw_id AND w.mac = d.mac
		WHERE d.fw_id = ? ORDER BY d.vlan, d.port, d.mac`, fwID)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	updatedAt := ""
	for rows.Next() {
		var d Device
		if scanErr := rows.Scan(&d.Mac, &d.IP, &d.Vlan, &d.Port, &d.SwitchID, &d.Hostname,
			&d.DevType, &d.OsName, &d.OsVersion, &d.Vendor, &d.FirstSeen, &d.LastSeen, &updatedAt,
			&d.Ap, &d.Ssid, &d.Signal); scanErr != nil {
			return nil, "", scanErr
		}
		// The FortiSwitch MAC-event pin is the authoritative wired location:
		// it carries the real switch + physical port, which the traffic-log
		// inventory lacks (its "port" is only the VLAN interface).
		if mp, ok := pins[d.Mac]; ok && mp.Port != "" {
			d.Port = mp.Port
			if mp.SwitchName != "" {
				d.SwitchID = mp.SwitchName
			}
			if mp.Vlan != "" {
				d.Vlan = mp.Vlan
			}
		}
		devices = append(devices, d)
	}

	// MAC/IP sharing: one MAC with several IPs, or one IP behind several MACs.
	macIPs := map[string]map[string]bool{}
	ipMacs := map[string]map[string]bool{}
	for _, d := range devices {
		if d.IP == "" {
			continue
		}
		if macIPs[d.Mac] == nil {
			macIPs[d.Mac] = map[string]bool{}
		}
		macIPs[d.Mac][d.IP] = true
		if ipMacs[d.IP] == nil {
			ipMacs[d.IP] = map[string]bool{}
		}
		ipMacs[d.IP][d.Mac] = true
	}
	for i := range devices {
		d := &devices[i]
		if len(macIPs[d.Mac]) > 1 {
			d.SharedMac = true
		}
		if d.IP != "" && len(ipMacs[d.IP]) > 1 {
			d.SharedIP = true
		}
	}
	return devices, updatedAt, nil
}
