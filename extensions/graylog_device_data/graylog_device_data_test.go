package graylogdevicedata

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestSourceHost(t *testing.T) {
	cases := map[string]string{
		"fw1.example.com": "fw1",
		"fw1":             "fw1",
		"":                "",
	}
	for in, want := range cases {
		if got := sourceHost(in); got != want {
			t.Errorf("sourceHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeviceFromMessage(t *testing.T) {
	d, ok := deviceFromMessage(map[string]any{
		"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.10.5", "vlan": "10",
		"portname": "port3", "switchid": "S124EP0000000001",
		"hostname": "printer-01", "timestamp": "2026-07-08T10:00:00Z",
	})
	if !ok {
		t.Fatal("expected a device")
	}
	if d.Mac != "aa:bb:cc:dd:ee:ff" || d.IP != "10.0.10.5" || d.Vlan != "10" ||
		d.Port != "port3" || d.SwitchID != "S124EP0000000001" || d.Hostname != "printer-01" {
		t.Fatalf("wrong parse: %+v", d)
	}

	// Alias fields (DHCP-style logs).
	d, ok = deviceFromMessage(map[string]any{"srcmac": "11:22:33:44:55:66", "assignedip": "10.0.1.9", "srcintf": "port5"})
	if !ok || d.Mac != "11:22:33:44:55:66" || d.IP != "10.0.1.9" || d.Port != "port5" {
		t.Fatalf("alias parse wrong: %+v ok=%t", d, ok)
	}

	// Records without a MAC are skipped.
	if _, ok = deviceFromMessage(map[string]any{"ip": "10.0.0.1"}); ok {
		t.Error("record without mac must be skipped")
	}
	if _, ok = deviceFromMessage(map[string]any{"mac": "00:00:00:00:00:00"}); ok {
		t.Error("null mac must be skipped")
	}
}

// graylogFake serves a canned universal/relative search response.
func graylogFake(t *testing.T, messages []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/search/universal/relative" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		wrapped := make([]map[string]any, 0, len(messages))
		for _, m := range messages {
			wrapped = append(wrapped, map[string]any{"message": m})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": wrapped})
	}))
}

func testExt(t *testing.T, graylogURL string) *Extension {
	t.Helper()
	cfg := &config.Config{
		GraylogURL:         graylogURL,
		GraylogToken:       "test-token",
		GraylogDeviceQuery: `source:"%s" AND mac:*`,
		GraylogDeviceRange: "3600",
	}
	e := New(cfg, slog.New(slog.DiscardHandler))
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dev.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	return e
}

func TestFetchAndStoreDevices(t *testing.T) {
	srv := graylogFake(t, []map[string]any{
		// newest first: the first record for a mac+ip wins
		{"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.10.5", "vlan": "10", "portname": "port1", "timestamp": "T2"},
		{"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.10.5", "vlan": "10", "portname": "port1", "timestamp": "T1"}, // duplicate, older
		{"mac": "aa:aa:aa:aa:aa:01", "ip": "10.0.10.99", "vlan": "10", "portname": "port1"},                   // same MAC, second IP
		{"mac": "bb:bb:bb:bb:bb:02", "ip": "10.0.10.99", "vlan": "20", "portname": "port2"},                   // same IP, second MAC
		{"mac": "cc:cc:cc:cc:cc:03", "ip": "10.0.20.7", "vlan": "20", "portname": "port2"},                    // clean
	})
	defer srv.Close()

	e := testExt(t, srv.URL)
	n, err := e.refreshFirewall(1, "fw1.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 { // duplicate collapsed
		t.Fatalf("expected 4 stored devices, got %d", n)
	}

	devices, updatedAt, err := e.listDevices(1)
	if err != nil || updatedAt == "" {
		t.Fatalf("list failed: %v (updated %q)", err, updatedAt)
	}
	byKey := map[string]Device{}
	for _, d := range devices {
		byKey[d.Mac+"|"+d.IP] = d
	}
	if d := byKey["aa:aa:aa:aa:aa:01|10.0.10.5"]; !d.SharedMac || d.SharedIP {
		t.Errorf("mac with two IPs must be shared_mac: %+v", d)
	}
	if d := byKey["bb:bb:bb:bb:bb:02|10.0.10.99"]; !d.SharedIP {
		t.Errorf("ip behind two MACs must be shared_ip: %+v", d)
	}
	if d := byKey["cc:cc:cc:cc:cc:03|10.0.20.7"]; d.SharedMac || d.SharedIP {
		t.Errorf("clean device must not be flagged: %+v", d)
	}
	// Deduped newest record kept its timestamp.
	if d := byKey["aa:aa:aa:aa:aa:01|10.0.10.5"]; d.LastSeen != "T2" {
		t.Errorf("expected newest record to win, got last_seen %q", d.LastSeen)
	}

	// A refresh replaces the previous inventory.
	srv2 := graylogFake(t, []map[string]any{{"mac": "dd:dd:dd:dd:dd:04", "ip": "10.0.30.1"}})
	defer srv2.Close()
	e.cfg.GraylogURL = srv2.URL
	if _, err := e.refreshFirewall(1, "fw1.example.com"); err != nil {
		t.Fatal(err)
	}
	devices, _, _ = e.listDevices(1)
	if len(devices) != 1 || devices[0].Mac != "dd:dd:dd:dd:dd:04" {
		t.Fatalf("refresh must replace inventory, got %+v", devices)
	}
}

func TestFetchDevicesUnconfigured(t *testing.T) {
	e := testExt(t, "")
	if _, err := e.fetchDevices("fw1"); err == nil {
		t.Fatal("missing graylog config must error")
	}
}

func TestEscapeGraylogValue(t *testing.T) {
	if got := escapeGraylogValue(`a"b\c`); got != `a\"b\\c` {
		t.Errorf("escape wrong: %q", got)
	}
}
