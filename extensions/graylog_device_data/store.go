package graylogdevicedata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// refreshFirewall fetches the device inventory for one firewall from Graylog
// and replaces its stored rows. Returns the number of devices stored.
func (e *Extension) refreshFirewall(fwID int, fqdn string) (int, error) {
	devices, err := e.fetchDevices(fqdn)
	if err != nil {
		return 0, err
	}
	now := time.Now().Format("2006-01-02 15:04:05")

	tx, err := e.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM devices WHERE fw_id = ?", fwID); err != nil {
		return 0, err
	}
	for _, d := range devices {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO devices
			(fw_id, mac, ip, vlan, port, switch_id, hostname, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fwID, d.Mac, d.IP, d.Vlan, d.Port, d.SwitchID, d.Hostname, d.LastSeen, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(devices), nil
}

// listDevices returns the stored inventory of a firewall with MAC/IP sharing
// flags computed, plus the time of the last refresh ("" when never fetched).
func (e *Extension) listDevices(fwID int) ([]Device, string, error) {
	rows, err := e.db.Query(`SELECT mac, ip, vlan, port, switch_id, hostname, last_seen, updated_at
		FROM devices WHERE fw_id = ? ORDER BY vlan, port, mac`, fwID)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var devices []Device
	updatedAt := ""
	for rows.Next() {
		var d Device
		if scanErr := rows.Scan(&d.Mac, &d.IP, &d.Vlan, &d.Port, &d.SwitchID, &d.Hostname, &d.LastSeen, &updatedAt); scanErr != nil {
			return nil, "", scanErr
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
