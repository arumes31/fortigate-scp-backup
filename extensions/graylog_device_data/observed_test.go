package graylogdevicedata

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestListObservedDevices verifies the published inventory view: switches from
// stp_ports ∪ switch_edges deduped by serial (newest row wins name/LastSeen),
// name-fallback switch_sn values rejected by the serial check, APs from
// ap_location, all keyed per firewall.
func TestListObservedDevices(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, "graylog-device-data.db")))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{createStpTableSQL, createSwitchEdgesSQL, createApLocationSQL} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	seed := []string{
		// fw 1: same switch in both tables; the newer switch_edges row must win
		// the name and LastSeen.
		`INSERT INTO stp_ports (fw_id, switch_name, serial, port, updated_at)
			VALUES (1, 'TEST-CORE01', 'S524DNTEST000001', 'port1', '2026-07-30T08:00:00Z')`,
		`INSERT INTO switch_edges (fw_id, switch_sn, switch_name, trunk, updated_at)
			VALUES (1, 'S524DNTEST000001', 'TEST-CORE01-NEW', 'trunkA', '2026-07-30T09:00:00Z')`,
		// Serial-less stp_ports row and a name-fallback switch_sn: both carry no
		// publishable serial and must be dropped.
		`INSERT INTO stp_ports (fw_id, switch_name, serial, port, updated_at)
			VALUES (1, 'TEST-EDGE01', '', 'port2', '2026-07-30T08:00:00Z')`,
		`INSERT INTO switch_edges (fw_id, switch_sn, switch_name, trunk, updated_at)
			VALUES (1, 'TEST-CORE02', '', 'trunkB', '2026-07-30T08:00:00Z')`,
		// fw 2: its own switch — per-firewall keying.
		`INSERT INTO stp_ports (fw_id, switch_name, serial, port, updated_at)
			VALUES (2, 'TEST-EDGE02', 'S108ENTEST000001', 'port1', '2026-07-30T07:00:00Z')`,
		// fw 1: one AP with IP.
		`INSERT INTO ap_location (fw_id, ap_serial, ap_name, ip, updated_at)
			VALUES (1, 'FP231FTEST0000A1', 'AP Test Basement', '10.0.0.5', '2026-07-30T06:00:00Z')`,
	}
	for _, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ListObservedDevices(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[1]) != 2 || len(got[2]) != 1 {
		t.Fatalf("per-fw counts = %d/%d, want 2/1: %+v", len(got[1]), len(got[2]), got)
	}
	sw := got[1][0]
	if sw.Kind != "switch" || sw.Serial != "S524DNTEST000001" ||
		sw.Name != "TEST-CORE01-NEW" || sw.LastSeen != "2026-07-30T09:00:00Z" {
		t.Errorf("fw1 switch = %+v (newest row must win name/LastSeen)", sw)
	}
	ap := got[1][1]
	if ap.Kind != "ap" || ap.Serial != "FP231FTEST0000A1" || ap.IP != "10.0.0.5" {
		t.Errorf("fw1 ap = %+v", ap)
	}
	if got[2][0].Serial != "S108ENTEST000001" {
		t.Errorf("fw2 switch = %+v", got[2][0])
	}

	// Missing DB (extension disabled) is not an error.
	if devs, err := ListObservedDevices(t.TempDir()); err != nil || devs != nil {
		t.Errorf("missing DB: got (%v, %v), want (nil, nil)", devs, err)
	}
}
