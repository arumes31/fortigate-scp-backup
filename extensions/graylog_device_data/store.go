package graylogdevicedata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
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
	defer e.trackRunning("devicedata", fwID)()
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

	// Latest link up/down per switch port, from a server-side aggregation. The
	// capped STP message fetch above only returns the few ports that flap
	// constantly; this returns one authoritative row per port regardless of
	// event volume, so a long-unplugged (stable-down) port still reads "down" on
	// the faceplate. It rides the same refresh and only ever costs the link
	// column on failure (stale link state is kept).
	if links, serr := e.fetchLinkStates(fqdn); serr != nil {
		e.logger.Warn("graylog link-state aggregation failed", "fw_id", fwID, "fqdn", fqdn, "err", serr)
	} else if serr := e.storeLinkStates(fwID, links, now); serr != nil {
		e.logger.Warn("graylog link-state store failed", "fw_id", fwID, "err", serr)
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

// storeLinkStates writes the aggregation's latest link up/down per port. Unlike
// storeStp it touches only the link column: the aggregation observes nothing
// about STP role/state, guard blocks or 802.1X, so those stored fields must be
// left exactly as fetchStpStates set them (storeStp deliberately overwrites
// guard with the fetched value, which a blanket upsert here would wrongly clear).
// Ports first seen by the aggregation are inserted with only link set; existing
// ports keep their STP fields and just get the fresh link. updated_at is bumped
// so the port survives storeStp's retention prune.
func (e *Extension) storeLinkStates(fwID int, links []StpPort, now string) error {
	if len(links) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range links {
		if p.SwitchName == "" || p.Port == "" || p.Link == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO stp_ports
			(fw_id, switch_name, serial, port, role, state, guard, link, dot1x, last_change, updated_at)
			VALUES (?, ?, ?, ?, '', '', '', ?, '', '', ?)
			ON CONFLICT(fw_id, switch_name, port) DO UPDATE SET
				serial     = CASE WHEN excluded.serial != '' THEN excluded.serial ELSE serial END,
				link       = CASE WHEN excluded.link   != '' THEN excluded.link   ELSE link   END,
				updated_at = excluded.updated_at`,
			fwID, p.SwitchName, p.Serial, p.Port, p.Link, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// storeDiagStp writes the live SSH-diagnostics port state: authoritative link
// up/down, STP role/state (for link-up ports), guard, 802.1X, and the physical
// enrichment (media/speed/admin/poe/optic/health). It merges non-empty fields
// only and never touches last_change or prunes, so it augments the Graylog-derived
// rows (which own the event history) without disturbing them. A down port arrives
// with empty role/state, so it is shown as down, not blocked. Guard self-clearing
// on recovery is left to the Graylog path (its guard events carry recoveries);
// the non-empty merge here means an SSH poll adds a guard but does not clear one.
func (e *Extension) storeDiagStp(fwID int, ports []StpPort, now string) error {
	if len(ports) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range ports {
		if p.SwitchName == "" || p.Port == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO stp_ports
			(fw_id, switch_name, serial, port, role, state, guard, link, dot1x, media, speed, admin, poe, optic, health, neighbor, last_change, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?)
			ON CONFLICT(fw_id, switch_name, port) DO UPDATE SET
				serial     = CASE WHEN excluded.serial   != '' THEN excluded.serial   ELSE serial   END,
				role       = CASE WHEN excluded.role     != '' THEN excluded.role     ELSE role     END,
				state      = CASE WHEN excluded.state    != '' THEN excluded.state    ELSE state    END,
				guard      = CASE WHEN excluded.guard    != '' THEN excluded.guard    ELSE guard    END,
				link       = CASE WHEN excluded.link     != '' THEN excluded.link     ELSE link     END,
				dot1x      = CASE WHEN excluded.dot1x    != '' THEN excluded.dot1x    ELSE dot1x    END,
				media      = CASE WHEN excluded.media    != '' THEN excluded.media    ELSE media    END,
				speed      = CASE WHEN excluded.speed    != '' THEN excluded.speed    ELSE speed    END,
				admin      = CASE WHEN excluded.admin    != '' THEN excluded.admin    ELSE admin    END,
				poe        = CASE WHEN excluded.poe      != '' THEN excluded.poe      ELSE poe      END,
				optic      = CASE WHEN excluded.optic    != '' THEN excluded.optic    ELSE optic    END,
				health     = CASE WHEN excluded.health   != '' THEN excluded.health   ELSE health   END,
				neighbor   = CASE WHEN excluded.neighbor != '' THEN excluded.neighbor ELSE neighbor END,
				updated_at = excluded.updated_at`,
			fwID, p.SwitchName, p.Serial, p.Port, p.Role, p.State, p.Guard, p.Link, p.Dot1x,
			p.Media, p.Speed, p.Admin, p.Poe, p.Optic, p.Health, p.Neighbor, now); err != nil {
			return err
		}
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
//
// It applies the same gate as the topology view: STP role/state blocks only
// count on inter-switch (trunk) ports — on an edge/access port a discarding or
// disabled state is normal client churn (a laptop undocking drops the link),
// not a loop being broken. Only a fired BPDU/loop/root guard blocks an edge
// port.
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

	// Inter-switch port legs and switch identities from the stored trunk
	// observations. An old database without the switch_edges table just yields
	// empty sets (guard blocks still surface).
	interSwitch := map[string]bool{} // "fwID|switch(lower)|port"
	knownSwitch := map[string]bool{} // switch names + serials, lowercased
	if eRows, qErr := db.Query(`SELECT fw_id, switch_sn, switch_name, ports FROM switch_edges`); qErr == nil {
		defer func() { _ = eRows.Close() }()
		for eRows.Next() {
			var fwID int
			var sn, name, ports string
			if scanErr := eRows.Scan(&fwID, &sn, &name, &ports); scanErr != nil {
				return nil, scanErr
			}
			for _, key := range []string{strings.ToLower(sn), strings.ToLower(name)} {
				if key == "" {
					continue
				}
				knownSwitch[key] = true
				for _, p := range strings.Split(ports, ",") {
					if p != "" {
						interSwitch[fmt.Sprintf("%d|%s|%s", fwID, key, p)] = true
					}
				}
			}
		}
		if rErr := eRows.Err(); rErr != nil {
			return nil, rErr
		}
	}
	// Every switch the STP feed has seen counts as managed, so an LLDP neighbor
	// naming one marks the local port as inter-switch.
	sRows, err := db.Query(`SELECT DISTINCT switch_name, serial FROM stp_ports`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sRows.Close() }()
	for sRows.Next() {
		var name, serial string
		if scanErr := sRows.Scan(&name, &serial); scanErr != nil {
			return nil, scanErr
		}
		for _, key := range []string{strings.ToLower(name), strings.ToLower(serial)} {
			if key != "" {
				knownSwitch[key] = true
			}
		}
	}
	if err := sRows.Err(); err != nil {
		return nil, err
	}

	rows, err := db.Query(`SELECT fw_id, switch_name, serial, port, role, state, guard, neighbor, last_change
		FROM stp_ports
		WHERE guard != '' OR lower(state) IN ('discarding', 'blocking')
			OR lower(role) IN ('alternate', 'backup', 'disabled')
		ORDER BY fw_id, switch_name, port`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	type candidate struct {
		BlockedPort
		serial, neighbor, guard string
	}
	var cands []candidate
	for rows.Next() {
		var c candidate
		var role, state string
		// role/state/guard/neighbor/last_change are NOT NULL DEFAULT '' in the
		// schema, so scanning into plain strings never hits a NULL.
		if scanErr := rows.Scan(&c.FwID, &c.Switch, &c.serial, &c.Port, &role, &state, &c.guard, &c.neighbor, &c.Since); scanErr != nil {
			return nil, scanErr
		}
		switch {
		case c.guard != "":
			c.Reason = c.guard
		case state != "":
			c.Reason = state
		default:
			c.Reason = role
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []BlockedPort
	for _, c := range cands {
		inter := interSwitch[fmt.Sprintf("%d|%s|%s", c.FwID, strings.ToLower(c.Switch), c.Port)] ||
			interSwitch[fmt.Sprintf("%d|%s|%s", c.FwID, strings.ToLower(c.serial), c.Port)] ||
			(c.neighbor != "" && knownSwitch[strings.ToLower(c.neighbor)])
		if c.guard != "" || inter {
			out = append(out, c.BlockedPort)
		}
	}
	return out, nil
}

// SharedData opens the extension's private database read-only and returns the
// device inventory for one firewall, projected down to exactly the fields the
// public share consent promises: client MAC, IP, hostname and 802.1X identity
// (see the topo.share_devices_hint copy). It is the exported bridge the core's
// public share-link endpoint uses, gated by the share's include_devices flag.
//
// The full authenticated payload (STP/faceplate state, firewall/switch health,
// HA, SD-WAN, dual-homed servers, port-security violations, AP locations, live
// routes, throughput, plus each device's fingerprint/port/switch placement) is
// deliberately NOT exposed on a public link — none of it is covered by the
// consent. A missing database (extension disabled or never fetched) yields
// (nil, nil) so the caller serves the map without devices.
func SharedData(dataDir string, fwID int) ([]byte, error) {
	dbFile := filepath.Join(dataDir, "graylog-device-data.db")
	if _, err := os.Stat(dbFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	// A minimal read-only Extension: only db + a discard logger are needed.
	e := &Extension{db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	devices, _, err := e.listDevices(fwID)
	if err != nil {
		return nil, err
	}
	// Project each device to the consented subset via a dedicated struct, so a
	// future field added to Device cannot silently leak onto a public link.
	type sharedDevice struct {
		Mac        string `json:"mac"`
		IP         string `json:"ip,omitempty"`
		Hostname   string `json:"hostname,omitempty"`
		Dot1xUser  string `json:"dot1x_user,omitempty"`
		Dot1xGroup string `json:"dot1x_group,omitempty"`
	}
	out := struct {
		Devices []sharedDevice `json:"devices"`
	}{Devices: make([]sharedDevice, 0, len(devices))}
	for _, d := range devices {
		out.Devices = append(out.Devices, sharedDevice{
			Mac: d.Mac, IP: d.IP, Hostname: d.Hostname,
			Dot1xUser: d.Dot1xUser, Dot1xGroup: d.Dot1xGroup,
		})
	}
	return json.Marshal(out)
}

// listStp returns the stored STP port states of a firewall.
func (e *Extension) listStp(fwID int) ([]StpPort, error) {
	rows, err := e.db.Query(`SELECT switch_name, serial, port, role, state, guard, link, dot1x,
			media, speed, admin, poe, optic, health, neighbor, last_change
		FROM stp_ports WHERE fw_id = ? ORDER BY switch_name, port`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StpPort
	for rows.Next() {
		var p StpPort
		if scanErr := rows.Scan(&p.SwitchName, &p.Serial, &p.Port, &p.Role, &p.State, &p.Guard, &p.Link, &p.Dot1x,
			&p.Media, &p.Speed, &p.Admin, &p.Poe, &p.Optic, &p.Health, &p.Neighbor, &p.LastChange); scanErr != nil {
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

// dualHomeAccessMax bounds how many distinct MACs a port may carry to still
// count as a device's real attachment point. A server LAG member / access port
// carries the host (and maybe a few VMs); an uplink or transit trunk carries
// dozens — excluding those leaves only genuine attachment ports, so a MAC seen
// on such ports of two different switches is truly dual-homed (not just transit).
const dualHomeAccessMax = 4

// dualHomeFreshWindow bounds how far behind a MAC's newest sighting an
// attachment may lag and still count toward dual-homing. A genuine MC-LAG host
// refreshes on both cores every sweep (gap ~0); a device that has left a switch
// leaves a row that ages past this window within a couple of sweeps, so it no
// longer fakes a dual-home.
const dualHomeFreshWindow = 3 * time.Hour

// dualHomeFresh reports whether sighting ts is recent enough, relative to the
// MAC's newest sighting, to count as a live attachment. Timestamps use the fixed
// "2006-01-02 15:04:05" layout; an unparseable one is treated as fresh (fail
// open — never hide a real attachment on a parse glitch).
func dualHomeFresh(ts, newest string) bool {
	if ts == "" || ts == newest {
		return true
	}
	const layout = "2006-01-02 15:04:05"
	t, e1 := time.ParseInLocation(layout, ts, time.Local)
	n, e2 := time.ParseInLocation(layout, newest, time.Local)
	if e1 != nil || e2 != nil {
		return true
	}
	return n.Sub(t) <= dualHomeFreshWindow
}

// listDualHomed returns devices whose MAC appears on the access ports of two or
// more switches at once — the MC-LAG-attached servers the single-port pin hides.
func (e *Extension) listDualHomed(fwID int) ([]DualHomed, error) {
	rows, err := e.db.Query(`SELECT mac, switch_name, port, updated_at FROM mac_sightings
		WHERE fw_id = ? AND port != '' AND switch_name != ''`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	type sighting struct{ mac, sw, port, updatedAt string }
	var all []sighting
	portMacs := map[string]map[string]bool{} // "sw|port" → distinct MACs on that port
	// newest holds each MAC's freshest sighting timestamp.
	newest := map[string]string{}
	for rows.Next() {
		var s sighting
		if scanErr := rows.Scan(&s.mac, &s.sw, &s.port, &s.updatedAt); scanErr != nil {
			return nil, scanErr
		}
		all = append(all, s)
		pk := s.sw + "|" + s.port
		if portMacs[pk] == nil {
			portMacs[pk] = map[string]bool{}
		}
		portMacs[pk][s.mac] = true
		if s.updatedAt > newest[s.mac] { // lexicographic max == chronological max
			newest[s.mac] = s.updatedAt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Per MAC, keep the lowest-count access port per switch (the most credible
	// attachment on that switch); drop uplink/transit ports entirely.
	type att struct {
		port  string
		count int
	}
	perMac := map[string]map[string]att{} // mac → switch → best access attachment
	for _, s := range all {
		// Only a sighting as recent as this MAC's newest counts: a stale row on a
		// switch the device has left must not fake a dual-home.
		if !dualHomeFresh(s.updatedAt, newest[s.mac]) {
			continue
		}
		c := len(portMacs[s.sw+"|"+s.port])
		if c > dualHomeAccessMax {
			continue // uplink / transit trunk, not an attachment
		}
		if perMac[s.mac] == nil {
			perMac[s.mac] = map[string]att{}
		}
		if cur, ok := perMac[s.mac][s.sw]; !ok || c < cur.count {
			perMac[s.mac][s.sw] = att{port: s.port, count: c}
		}
	}
	var out []DualHomed
	for mac, switches := range perMac {
		if len(switches) < 2 {
			continue
		}
		names := make([]string, 0, len(switches))
		for sw := range switches {
			names = append(names, sw)
		}
		sort.Strings(names)
		dh := DualHomed{Mac: mac}
		for _, sw := range names {
			dh.Attachments = append(dh.Attachments, PortAttachment{Switch: sw, Port: switches[sw].port})
		}
		out = append(out, dh)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mac < out[j].Mac })
	return out, nil
}

// virtOUIs maps known hypervisor NIC OUIs (lowercase, 6 hex, no separators) to a
// vendor label. A physical switch port dominated by MACs from one of these is a
// virtualization host uplink, not a client access port.
var virtOUIs = map[string]string{
	"00155d": "Hyper-V",
	"005056": "VMware", "000c29": "VMware", "000569": "VMware", "001c14": "VMware",
	"525400": "KVM/QEMU",
	"080027": "VirtualBox",
	"00163e": "Xen",
}

const (
	teamMinCluster   = 3    // min same-OUI MACs on a port to treat it as a vhost uplink
	teamMinDominance = 0.50 // that OUI must be a majority of the port's MACs
)

// macOUI returns the 6-hex OUI of a MAC (lowercase, no separators), "" if short.
func macOUI(mac string) string {
	h := strings.NewReplacer(":", "", "-", "").Replace(strings.ToLower(mac))
	if len(h) < 6 {
		return ""
	}
	return h[:6]
}

// listSuspectedTeams heuristically pairs the uplinks of a switch-independent
// teamed virtualization host across switches — the case listDualHomed cannot see
// because that teaming pins each VM MAC to exactly one uplink, so the two ports
// share no MAC. Signature: a physical port (mac_sightings holds only physical
// ports; trunks are skipped upstream) that is NOT a switch interlink, dominated
// by one hypervisor OUI in one VLAN. Two such ports of the same port-name + VLAN
// + OUI on different switches are reported as one Suspected team, so the UI marks
// both without ever asserting the pairing.
func (e *Extension) listSuspectedTeams(fwID int) ([]DualHomed, error) {
	// Managed-switch identities (name + serial), to recognize interlink ports.
	swIdent := map[string]bool{}
	if rows, err := e.db.Query("SELECT DISTINCT switch_name, serial FROM stp_ports WHERE fw_id = ?", fwID); err == nil {
		for rows.Next() {
			var n, s string
			if rows.Scan(&n, &s) == nil {
				if n != "" {
					swIdent[strings.ToUpper(n)] = true
				}
				if s != "" {
					swIdent[strings.ToUpper(s)] = true
				}
			}
		}
		_ = rows.Close()
	}
	// A port whose LLDP neighbor is a managed switch is a switch↔switch link, not a
	// host uplink — exclude it (a single-link downlink to a small edge switch with
	// one host behind it would otherwise look host-like).
	interlink := map[string]bool{}
	if rows, err := e.db.Query("SELECT switch_name, port, neighbor FROM stp_ports WHERE fw_id = ? AND neighbor != ''", fwID); err == nil {
		for rows.Next() {
			var sw, port, nbr string
			if rows.Scan(&sw, &port, &nbr) == nil && swIdent[strings.ToUpper(nbr)] {
				interlink[sw+"|"+port] = true
			}
		}
		_ = rows.Close()
	}

	rows, err := e.db.Query(`SELECT mac, switch_name, port, vlan, updated_at FROM mac_sightings
		WHERE fw_id = ? AND port != '' AND switch_name != ''`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	type portAgg struct {
		total int
		oui   map[string]int
		vlan  map[string]int
	}
	type sighting struct{ mac, sw, port, vlan, ts string }
	var all []sighting
	newest := ""
	for rows.Next() {
		var s sighting
		if scanErr := rows.Scan(&s.mac, &s.sw, &s.port, &s.vlan, &s.ts); scanErr != nil {
			return nil, scanErr
		}
		all = append(all, s)
		if s.ts > newest {
			newest = s.ts
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	agg := map[string]*portAgg{} // "switch|port" → aggregate
	for _, s := range all {
		if !dualHomeFresh(s.ts, newest) {
			continue // stale: a removed VM must not keep a port looking populated
		}
		key := s.sw + "|" + s.port
		if interlink[key] {
			continue
		}
		a := agg[key]
		if a == nil {
			a = &portAgg{oui: map[string]int{}, vlan: map[string]int{}}
			agg[key] = a
		}
		a.total++
		if o := macOUI(s.mac); o != "" {
			a.oui[o]++
		}
		if s.vlan != "" {
			a.vlan[s.vlan]++
		}
	}

	// Classify vhost ports, then group across switches by port-name + VLAN + OUI
	// (the port name in the key means a switch contributes at most one port per
	// group — matching-port-number cabling is the norm for a teamed host).
	type vhost struct{ sw, port, vlan, oui string }
	groups := map[string][]vhost{}
	for key, a := range agg {
		bestOUI, bestN := "", 0
		for o, n := range a.oui {
			if _, ok := virtOUIs[o]; ok && n > bestN {
				bestOUI, bestN = o, n
			}
		}
		if bestOUI == "" || bestN < teamMinCluster || float64(bestN)/float64(a.total) < teamMinDominance {
			continue
		}
		bestVlan, bv := "", 0
		for v, n := range a.vlan {
			if n > bv {
				bestVlan, bv = v, n
			}
		}
		sw, port, _ := strings.Cut(key, "|")
		gkey := port + "|" + bestVlan + "|" + bestOUI
		groups[gkey] = append(groups[gkey], vhost{sw: sw, port: port, vlan: bestVlan, oui: bestOUI})
	}

	var out []DualHomed
	for _, g := range groups {
		sws := map[string]bool{}
		for _, h := range g {
			sws[h.sw] = true
		}
		if len(sws) < 2 {
			continue // a team must span ≥2 switches
		}
		sort.Slice(g, func(i, j int) bool { return g[i].sw < g[j].sw })
		dh := DualHomed{Suspected: true, Vlan: g[0].vlan, Note: virtOUIs[g[0].oui]}
		for _, h := range g {
			dh.Attachments = append(dh.Attachments, PortAttachment{Switch: h.sw, Port: h.port})
		}
		out = append(out, dh)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Attachments[0].Switch+out[i].Attachments[0].Port <
			out[j].Attachments[0].Switch+out[j].Attachments[0].Port
	})
	return out, nil
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
		if _, err := tx.Exec(`INSERT INTO switch_edges (fw_id, switch_sn, switch_name, trunk, role, state, ports, note, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, switch_sn, trunk) DO UPDATE SET
				switch_name = CASE WHEN excluded.switch_name != '' THEN excluded.switch_name ELSE switch_name END,
				role        = CASE WHEN excluded.role != '' THEN excluded.role ELSE role END,
				state       = CASE WHEN excluded.state != '' THEN excluded.state ELSE state END,
				ports       = CASE WHEN excluded.ports != '' THEN excluded.ports ELSE ports END,
				note        = CASE WHEN excluded.note != '' THEN excluded.note ELSE note END,
				updated_at  = excluded.updated_at`,
			fwID, g.SwitchSN, g.SwitchName, g.Trunk, g.Role, g.State, strings.Join(g.Ports, ","), g.Note, now); err != nil {
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
	rows, err := e.db.Query(`SELECT switch_sn, switch_name, trunk, role, state, ports, note
		FROM switch_edges WHERE fw_id = ? ORDER BY switch_name, trunk`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SwitchEdge
	for rows.Next() {
		var g SwitchEdge
		var ports string
		if scanErr := rows.Scan(&g.SwitchSN, &g.SwitchName, &g.Trunk, &g.Role, &g.State, &ports, &g.Note); scanErr != nil {
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

// storeMacEnrichArp upserts the ARP-resolved IP per MAC (device IP enrichment)
// and prunes stale rows. Only touches ip/iface, so it never clobbers the 802.1X
// identity written by storeMacEnrichDot1x for the same MAC.
func (e *Extension) storeMacEnrichArp(fwID int, arps []arpEntry, now string) error {
	if len(arps) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, a := range arps {
		if a.Mac == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO mac_enrich (fw_id, mac, ip, iface, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, mac) DO UPDATE SET
				ip=excluded.ip, iface=excluded.iface, updated_at=excluded.updated_at`,
			fwID, a.Mac, a.IP, a.Iface, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM mac_enrich WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// storeMacEnrichDot1x upserts the 802.1X RADIUS identity (AD user/machine,
// group) and dynamic VLAN per authenticated MAC. Only touches the dot1x_* fields.
func (e *Extension) storeMacEnrichDot1x(fwID int, sessions []dot1xSession, now string) error {
	if len(sessions) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, s := range sessions {
		if s.Mac == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO mac_enrich (fw_id, mac, dot1x_user, dot1x_group, dot1x_vlan, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, mac) DO UPDATE SET
				dot1x_user=excluded.dot1x_user, dot1x_group=excluded.dot1x_group,
				dot1x_vlan=excluded.dot1x_vlan, updated_at=excluded.updated_at`,
			fwID, s.Mac, s.User, s.Group, s.Vlan, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// storeFwHealth upserts the firewall node's live health summary. It reuses the
// ha_status row but a distinct `health` column, so it never fights the Graylog
// HA-event `detail` written by refreshFirewall.
func (e *Extension) storeFwHealth(fwID int, summary, now string) error {
	if summary == "" {
		return nil
	}
	_, err := e.db.Exec(`INSERT INTO ha_status (fw_id, health, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(fw_id) DO UPDATE SET health=excluded.health, updated_at=excluded.updated_at`,
		fwID, summary, now)
	return err
}

// fwHealth returns the stored SSH-derived firewall health summary ("" when none).
func (e *Extension) fwHealth(fwID int) string {
	var h string
	if err := e.db.QueryRow("SELECT health FROM ha_status WHERE fw_id = ?", fwID).Scan(&h); err != nil {
		return ""
	}
	return h
}

// storeSwitchHealth upserts each switch's fan/congestion state and prunes stale
// rows (decommissioned switches).
func (e *Extension) storeSwitchHealth(fwID int, hs []SwitchHealth, now string) error {
	if len(hs) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, h := range hs {
		if h.SwitchName == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO switch_health (fw_id, switch_name, fan, congestion, tcn, poe_used, poe_total, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, switch_name) DO UPDATE SET
				fan=CASE WHEN excluded.fan != '' THEN excluded.fan ELSE fan END,
				congestion=CASE WHEN excluded.congestion > 0 THEN excluded.congestion ELSE congestion END,
				tcn=CASE WHEN excluded.tcn > 0 THEN excluded.tcn ELSE tcn END,
				poe_used=CASE WHEN excluded.poe_total > 0 THEN excluded.poe_used ELSE poe_used END,
				poe_total=CASE WHEN excluded.poe_total > 0 THEN excluded.poe_total ELSE poe_total END,
				updated_at=excluded.updated_at`,
			fwID, h.SwitchName, h.Fan, h.Congestion, h.Tcn, h.PoeUsed, h.PoeTotal, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM switch_health WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// listSwitchHealth returns the stored per-switch health of a firewall.
func (e *Extension) listSwitchHealth(fwID int) ([]SwitchHealth, error) {
	rows, err := e.db.Query(`SELECT switch_name, fan, congestion, tcn, poe_used, poe_total FROM switch_health WHERE fw_id = ?`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SwitchHealth
	for rows.Next() {
		var h SwitchHealth
		if scanErr := rows.Scan(&h.SwitchName, &h.Fan, &h.Congestion, &h.Tcn, &h.PoeUsed, &h.PoeTotal); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// storeSdwanHealth replaces the firewall's per-member SD-WAN SLA snapshot.
func (e *Extension) storeSdwanHealth(fwID int, hs []SdwanHealth, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM sdwan_health WHERE fw_id = ?", fwID); err != nil {
		return err
	}
	for _, h := range hs {
		if h.Member == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO sdwan_health (fw_id, member, state, loss, latency, jitter, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, fwID, h.Member, h.State, h.Loss, h.Latency, h.Jitter, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// listSdwanHealth returns the firewall's per-member SD-WAN SLA.
func (e *Extension) listSdwanHealth(fwID int) ([]SdwanHealth, error) {
	rows, err := e.db.Query(`SELECT member, state, loss, latency, jitter FROM sdwan_health WHERE fw_id = ? ORDER BY member`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SdwanHealth
	for rows.Next() {
		var h SdwanHealth
		if scanErr := rows.Scan(&h.Member, &h.State, &h.Loss, &h.Latency, &h.Jitter); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// storeIfaceThroughput computes each interface's throughput (Mbps) from the byte
// delta against the previous stored counters, then persists the new counters +
// rate. The first sample yields no rate (no prior baseline).
func (e *Extension) storeIfaceThroughput(fwID int, counters []ifaceCounter, now string) error {
	if len(counters) == 0 {
		return nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// One sample instant for the whole batch: the counters were just read over
	// SSH, so nowT is when they were sampled. Store nowT (sampleTs) as the delta
	// baseline — not the collection-start `now`, which on a large fabric can be
	// minutes stale — and parse the previous baseline in the SAME location. `ts`
	// is written from local time, so parsing it as UTC (time.Parse) would skew
	// the delta by the zone offset — negative dt in any non-UTC deployment, which
	// pins every rate at 0.
	nowT := time.Now()
	sampleTs := nowT.Format("2006-01-02 15:04:05")
	for _, c := range counters {
		var prevRx, prevTx int64
		var prevTs string
		_ = tx.QueryRow("SELECT rxb, txb, ts FROM iface_stats WHERE fw_id = ? AND iface = ?", fwID, c.Iface).Scan(&prevRx, &prevTx, &prevTs)
		rxMbps, txMbps := 0.0, 0.0
		if t, perr := time.ParseInLocation("2006-01-02 15:04:05", prevTs, time.Local); perr == nil {
			if dt := nowT.Sub(t).Seconds(); dt >= 1 && c.RxB >= prevRx && c.TxB >= prevTx {
				rxMbps = float64(c.RxB-prevRx) * 8 / dt / 1e6
				txMbps = float64(c.TxB-prevTx) * 8 / dt / 1e6
			}
		}
		if _, err := tx.Exec(`INSERT INTO iface_stats (fw_id, iface, rxb, txb, ts, rx_mbps, tx_mbps, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, iface) DO UPDATE SET
				rxb=excluded.rxb, txb=excluded.txb, ts=excluded.ts,
				rx_mbps=excluded.rx_mbps, tx_mbps=excluded.tx_mbps, updated_at=excluded.updated_at`,
			fwID, c.Iface, c.RxB, c.TxB, sampleTs, rxMbps, txMbps, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM iface_stats WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// listIfaceThroughput returns interfaces with a nonzero derived throughput.
func (e *Extension) listIfaceThroughput(fwID int) ([]IfaceThroughput, error) {
	rows, err := e.db.Query(`SELECT iface, rx_mbps, tx_mbps FROM iface_stats
		WHERE fw_id = ? AND (rx_mbps > 0.1 OR tx_mbps > 0.1) ORDER BY (rx_mbps + tx_mbps) DESC`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []IfaceThroughput
	for rows.Next() {
		var t IfaceThroughput
		if scanErr := rows.Scan(&t.Iface, &t.RxMbps, &t.TxMbps); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// storePortCounters records each port's cumulative error/discard counters and
// returns, per port, how much the error counter GREW since the previous poll —
// the active error rate (only when a prior baseline existed; a counter reset on
// reboot, prev>cur, is not reported). A positive delta means the port is
// actively accumulating errors: a failing cable/SFP, distinct from old,
// no-longer-growing damage that the cumulative Health count alone can't tell apart.
func (e *Extension) storePortCounters(fwID int, sw, portStatsRaw, now string) map[string]int {
	deltas := map[string]int{}
	stats := parsePortStats(portStatsRaw)
	if len(stats) == 0 {
		return deltas
	}
	tx, err := e.db.Begin()
	if err != nil {
		return deltas
	}
	defer func() { _ = tx.Rollback() }()
	for port, ps := range stats {
		var prevErr, prevDisc int
		had := tx.QueryRow("SELECT errors, discards FROM port_counters WHERE fw_id = ? AND switch_name = ? AND port = ?",
			fwID, sw, port).Scan(&prevErr, &prevDisc) == nil
		if had && ps.Errors > prevErr {
			deltas[port] = ps.Errors - prevErr
		}
		if _, err := tx.Exec(`INSERT INTO port_counters (fw_id, switch_name, port, errors, discards, ts, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, switch_name, port) DO UPDATE SET
				errors=excluded.errors, discards=excluded.discards, ts=excluded.ts, updated_at=excluded.updated_at`,
			fwID, sw, port, ps.Errors, ps.Discards, now, now); err != nil {
			return deltas
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	_, _ = tx.Exec("DELETE FROM port_counters WHERE fw_id = ? AND updated_at < ?", fwID, cutoff)
	_ = tx.Commit()
	return deltas
}

// storeMacViolations replaces the firewall's current port-security violation
// snapshot (wipe + insert, so cleared violations disappear).
func (e *Extension) storeMacViolations(fwID int, vs []MacViolation, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM mac_violations WHERE fw_id = ?", fwID); err != nil {
		return err
	}
	for _, v := range vs {
		if v.Port == "" || v.Switch == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO mac_violations
			(fw_id, switch_name, port, vlan, mac, action, seen_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			fwID, v.Switch, v.Port, v.Vlan, v.Mac, v.Action, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// listMacViolations returns the firewall's current port-security violations.
func (e *Extension) listMacViolations(fwID int) ([]MacViolation, error) {
	rows, err := e.db.Query("SELECT switch_name, port, vlan, mac, action FROM mac_violations WHERE fw_id = ? ORDER BY switch_name, port", fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MacViolation
	for rows.Next() {
		var v MacViolation
		if scanErr := rows.Scan(&v.Switch, &v.Port, &v.Vlan, &v.Mac, &v.Action); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// storeDiagStatus records the outcome of an SSH collection sweep.
func (e *Extension) storeDiagStatus(fwID int, s CollectionStatus, now string) error {
	static := 0
	if s.Static {
		static = 1
	}
	_, err := e.db.Exec(`INSERT INTO diag_status (fw_id, last_run, switches, duration_ms, static, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(fw_id) DO UPDATE SET
			last_run=excluded.last_run, switches=excluded.switches,
			duration_ms=excluded.duration_ms, static=excluded.static, updated_at=excluded.updated_at`,
		fwID, s.LastRun, s.Switches, s.DurationMs, static, now)
	return err
}

// diagStatus returns the last SSH collection status for a firewall.
func (e *Extension) diagStatus(fwID int) CollectionStatus {
	var s CollectionStatus
	var static int
	if err := e.db.QueryRow("SELECT last_run, switches, duration_ms, static FROM diag_status WHERE fw_id = ?", fwID).
		Scan(&s.LastRun, &s.Switches, &s.DurationMs, &static); err != nil {
		return CollectionStatus{}
	}
	s.Static = static == 1
	return s
}

// storeLiveRoutes replaces the firewall's routing-egress summary (a full snapshot
// each poll, so wipe-and-insert keeps it exact).
func (e *Extension) storeLiveRoutes(fwID int, routes []LiveRoute, now string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM live_routes WHERE fw_id = ?", fwID); err != nil {
		return err
	}
	for _, r := range routes {
		if r.Device == "" {
			continue
		}
		def := 0
		if r.Default {
			def = 1
		}
		if _, err := tx.Exec(`INSERT INTO live_routes (fw_id, device, routes, is_default, updated_at)
			VALUES (?, ?, ?, ?, ?)`, fwID, r.Device, r.Routes, def, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// listLiveRoutes returns the firewall's routing-egress summary.
func (e *Extension) listLiveRoutes(fwID int) ([]LiveRoute, error) {
	rows, err := e.db.Query(`SELECT device, routes, is_default FROM live_routes WHERE fw_id = ? ORDER BY routes DESC`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []LiveRoute
	for rows.Next() {
		var r LiveRoute
		var def int
		if scanErr := rows.Scan(&r.Device, &r.Routes, &def); scanErr != nil {
			return nil, scanErr
		}
		r.Default = def == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// storeApLocation upserts each managed AP's wired switch/port (from wtp-status)
// and prunes APs unseen past the retention window. Non-empty merge on switch/
// port so a momentary LLDP blip on one poll keeps the last-known location; a
// genuine move overwrites it with the new (non-empty) switch/port.
func (e *Extension) storeApLocation(fwID int, aps []ApLocation, now string) error {
	// No early return on an empty slice: the retention prune below must still run
	// so the last AP's row is cleaned up when every AP has been removed.
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, a := range aps {
		if a.Serial == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO ap_location (fw_id, ap_serial, ap_name, board_mac, ip, switch_name, switch_port, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fw_id, ap_serial) DO UPDATE SET
				ap_name     = CASE WHEN excluded.ap_name     != '' THEN excluded.ap_name     ELSE ap_name     END,
				board_mac   = CASE WHEN excluded.board_mac   != '' THEN excluded.board_mac   ELSE board_mac   END,
				ip          = CASE WHEN excluded.ip          != '' THEN excluded.ip          ELSE ip          END,
				switch_name = CASE WHEN excluded.switch_name != '' THEN excluded.switch_name ELSE switch_name END,
				switch_port = CASE WHEN excluded.switch_port != '' THEN excluded.switch_port ELSE switch_port END,
				updated_at  = excluded.updated_at`,
			fwID, a.Serial, a.Name, a.BoardMac, a.IP, a.Switch, a.Port, now); err != nil {
			return err
		}
	}
	cutoff := time.Now().Add(-deviceRetention).Format("2006-01-02 15:04:05")
	if _, err := tx.Exec("DELETE FROM ap_location WHERE fw_id = ? AND updated_at < ?", fwID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// listApLocation returns the AP→switch-port map for a firewall.
func (e *Extension) listApLocation(fwID int) ([]ApLocation, error) {
	rows, err := e.db.Query(`SELECT ap_serial, ap_name, board_mac, ip, switch_name, switch_port
		FROM ap_location WHERE fw_id = ? ORDER BY ap_name, ap_serial`, fwID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ApLocation
	for rows.Next() {
		var a ApLocation
		if scanErr := rows.Scan(&a.Serial, &a.Name, &a.BoardMac, &a.IP, &a.Switch, &a.Port); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, a)
	}
	return out, rows.Err()
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
			COALESCE(w.ap, ''), COALESCE(w.ssid, ''), COALESCE(w.signal, ''),
			COALESCE(m.ip, ''), COALESCE(m.dot1x_user, ''), COALESCE(m.dot1x_group, '')
		FROM devices d
		LEFT JOIN wifi_clients w ON w.fw_id = d.fw_id AND w.mac = d.mac
		LEFT JOIN mac_enrich m ON m.fw_id = d.fw_id AND m.mac = d.mac
		WHERE d.fw_id = ? ORDER BY d.vlan, d.port, d.mac`, fwID)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	updatedAt := ""
	for rows.Next() {
		var d Device
		var arpIP string
		if scanErr := rows.Scan(&d.Mac, &d.IP, &d.Vlan, &d.Port, &d.SwitchID, &d.Hostname,
			&d.DevType, &d.OsName, &d.OsVersion, &d.Vendor, &d.FirstSeen, &d.LastSeen, &updatedAt,
			&d.Ap, &d.Ssid, &d.Signal, &arpIP, &d.Dot1xUser, &d.Dot1xGroup); scanErr != nil {
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
		// Origin badges: every row here is in the Graylog inventory; SSH also
		// contributed if it carries SSH-only enrichment (ARP IP or 802.1X identity).
		d.Sources = []string{"graylog"}
		if arpIP != "" || d.Dot1xUser != "" || d.Dot1xGroup != "" {
			d.Sources = append(d.Sources, "ssh")
		}
		if d.IP == "" && arpIP != "" { // ARP fills the IP the switch mac-table lacks
			d.IP = arpIP
		}
		devices = append(devices, d)
	}

	// SSH-discovered devices: MACs the FortiSwitch MAC table learned on an access
	// port (bestMacPins) that never appeared in the Graylog client-device logs —
	// most importantly servers wired directly to the core switches, which produce
	// no client-traffic logs. Without this they are invisible, because the Graylog
	// inventory alone drives device nodes and SSH only re-pins existing ones. They
	// carry no fingerprint (Source="ssh"); the ARP IP + 802.1X identity enrich them.
	//
	// Guard on pins alone (never len(pins) > len(devices)): the devices slice can
	// hold several rows per MAC — one MAC with multiple IPs — so a row count can
	// exceed the distinct-MAC pin count while genuine SSH-only MACs still go
	// undiscovered. The seen set below dedups by MAC, so iterating every pin is safe.
	if len(pins) > 0 {
		seen := make(map[string]bool, len(devices))
		for _, d := range devices {
			seen[d.Mac] = true
		}
		enrich := map[string]Device{}
		if er, eerr := e.db.Query("SELECT mac, ip, dot1x_user, dot1x_group, dot1x_vlan FROM mac_enrich WHERE fw_id = ?", fwID); eerr == nil {
			for er.Next() {
				var mac, ip, user, grp, vlan string
				if er.Scan(&mac, &ip, &user, &grp, &vlan) == nil {
					enrich[mac] = Device{IP: ip, Dot1xUser: user, Dot1xGroup: grp, Vlan: vlan}
				}
			}
			_ = er.Close()
		}
		for mac, mp := range pins {
			if seen[mac] || mp.Port == "" {
				continue
			}
			d := Device{Mac: mac, Port: mp.Port, SwitchID: mp.SwitchName, Vlan: mp.Vlan, Sources: []string{"ssh"}}
			en := enrich[mac]
			d.IP = en.IP
			d.Dot1xUser, d.Dot1xGroup = en.Dot1xUser, en.Dot1xGroup
			if d.Vlan == "" {
				d.Vlan = en.Vlan
			}
			devices = append(devices, d)
		}
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
