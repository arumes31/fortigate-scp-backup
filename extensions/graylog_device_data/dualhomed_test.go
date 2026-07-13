package graylogdevicedata

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestListDualHomed(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "d.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(createMacSightingsSQL); err != nil {
		t.Fatal(err)
	}
	e := &Extension{db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := "2026-07-13 10:00:00"
	ins := func(mac, sw, port string) {
		if _, err := db.Exec("INSERT INTO mac_sightings (fw_id, mac, switch_name, port, vlan, updated_at) VALUES (1, ?, ?, ?, '', ?)", mac, sw, port, now); err != nil {
			t.Fatal(err)
		}
	}

	// Dual-homed server: alone on the same server-port of both MC-LAG cores.
	ins("00:11:22:00:00:01", "SW-CORE01", "port5")
	ins("00:11:22:00:00:01", "SW-CORE02", "port5")

	// Normal single-homed device: on one access port (alone), plus TRANSIT across
	// a core uplink that carries many MACs — the uplink sighting must be ignored,
	// so this device is NOT dual-homed.
	ins("00:11:22:00:00:02", "SW-ACCESS01", "port10")
	ins("00:11:22:00:00:02", "SW-CORE01", "port48")
	for i := 0; i < 6; i++ { // push port48 well over the access threshold → uplink
		ins(fmt.Sprintf("00:11:22:00:99:%02d", i), "SW-CORE01", "port48")
	}

	got, err := e.listDualHomed(1)
	if err != nil {
		t.Fatalf("listDualHomed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 dual-homed device, got %d: %+v", len(got), got)
	}
	dh := got[0]
	if dh.Mac != "00:11:22:00:00:01" || len(dh.Attachments) != 2 {
		t.Fatalf("wrong dual-homed device: %+v", dh)
	}
	// Attachments are sorted by switch name.
	if dh.Attachments[0].Switch != "SW-CORE01" || dh.Attachments[0].Port != "port5" ||
		dh.Attachments[1].Switch != "SW-CORE02" || dh.Attachments[1].Port != "port5" {
		t.Fatalf("wrong attachments: %+v", dh.Attachments)
	}
}

// TestListSuspectedTeams covers the switch-independent teaming heuristic: a
// Hyper-V host teamed across two cores shares NO MAC (each VM pinned to one
// uplink), but each port26 is dominated by the Hyper-V OUI in one VLAN.
func TestListSuspectedTeams(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "d.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	for _, q := range []string{createMacSightingsSQL, createStpTableSQL} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	e := &Extension{db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := "2026-07-13 12:00:00"
	insMac := func(mac, sw, port, vlan string) {
		if _, err := db.Exec("INSERT INTO mac_sightings (fw_id, mac, switch_name, port, vlan, updated_at) VALUES (1, ?, ?, ?, ?, ?)", mac, sw, port, vlan, now); err != nil {
			t.Fatal(err)
		}
	}
	insStp := func(sw, port, neighbor string) {
		if _, err := db.Exec("INSERT INTO stp_ports (fw_id, switch_name, port, neighbor, updated_at) VALUES (1, ?, ?, ?, ?)", sw, port, neighbor, now); err != nil {
			t.Fatal(err)
		}
	}

	// The teamed Hyper-V host: disjoint VM MACs on port26 of each core, VLAN 51.
	for i := 0; i < 6; i++ {
		insMac(fmt.Sprintf("00:15:5d:aa:00:%02x", i), "SW-CORE01", "port26", "51")
		insMac(fmt.Sprintf("00:15:5d:bb:00:%02x", i), "SW-CORE02", "port26", "51")
	}
	// A normal client access port (few, non-virtual MACs) — must NOT be flagged.
	insMac("00:11:22:00:00:01", "SW-ACCESS01", "port5", "100")
	insMac("00:11:22:00:00:02", "SW-ACCESS01", "port5", "100")
	// A single-switch Hyper-V host — a vhost port, but on one switch only.
	for i := 0; i < 5; i++ {
		insMac(fmt.Sprintf("00:15:5d:cc:00:%02x", i), "SW-CORE01", "port30", "60")
	}
	// Interlink decoy: a Hyper-V cluster behind an edge switch appears on the
	// core's downlink port12 of two access switches, but those ports are LLDP
	// neighbors of a managed switch (SW-EDGE09) → excluded, not a team.
	insStp("SW-EDGE09", "port8", "")             // makes SW-EDGE09 a known switch
	insStp("SW-ACCESS03", "port12", "SW-EDGE09") // downlink → interlink
	insStp("SW-ACCESS04", "port12", "SW-EDGE09") // downlink → interlink
	for i := 0; i < 4; i++ {
		insMac(fmt.Sprintf("00:15:5d:dd:00:%02x", i), "SW-ACCESS03", "port12", "70")
		insMac(fmt.Sprintf("00:15:5d:ee:00:%02x", i), "SW-ACCESS04", "port12", "70")
	}

	teams, err := e.listSuspectedTeams(1)
	if err != nil {
		t.Fatalf("listSuspectedTeams: %v", err)
	}
	if len(teams) != 1 {
		t.Fatalf("expected exactly 1 suspected team, got %d: %+v", len(teams), teams)
	}
	tm := teams[0]
	if !tm.Suspected || tm.Vlan != "51" || tm.Note != "Hyper-V" || len(tm.Attachments) != 2 {
		t.Fatalf("wrong team: %+v", tm)
	}
	if tm.Attachments[0].Switch != "SW-CORE01" || tm.Attachments[0].Port != "port26" ||
		tm.Attachments[1].Switch != "SW-CORE02" || tm.Attachments[1].Port != "port26" {
		t.Fatalf("wrong attachments: %+v", tm.Attachments)
	}
}
