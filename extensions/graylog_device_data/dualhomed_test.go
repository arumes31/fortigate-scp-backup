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
	ins("00:11:22:00:00:01", "EX-CORE01", "port5")
	ins("00:11:22:00:00:01", "EX-CORE02", "port5")

	// Normal single-homed device: on one access port (alone), plus TRANSIT across
	// a core uplink that carries many MACs — the uplink sighting must be ignored,
	// so this device is NOT dual-homed.
	ins("00:11:22:00:00:02", "EX-ACCESS01", "port10")
	ins("00:11:22:00:00:02", "EX-CORE01", "port48")
	for i := 0; i < 6; i++ { // push port48 well over the access threshold → uplink
		ins(fmt.Sprintf("00:11:22:00:99:%02d", i), "EX-CORE01", "port48")
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
	if dh.Attachments[0].Switch != "EX-CORE01" || dh.Attachments[0].Port != "port5" ||
		dh.Attachments[1].Switch != "EX-CORE02" || dh.Attachments[1].Port != "port5" {
		t.Fatalf("wrong attachments: %+v", dh.Attachments)
	}
}
