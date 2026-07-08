package graylogdevicedata

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

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

func TestBuildSourceQuery(t *testing.T) {
	tmpl := `source:"%s" AND (mac:* OR srcmac:*)`
	if got := buildSourceQuery(tmpl, []string{"FW-N1"}); got != `source:"FW-N1" AND (mac:* OR srcmac:*)` {
		t.Errorf("single source wrong: %q", got)
	}
	// HA cluster: grouped OR so the mac filter applies to both nodes.
	got := buildSourceQuery(tmpl, []string{"FW-N1", "FW-N2"})
	want := `(source:"FW-N1" OR source:"FW-N2") AND (mac:* OR srcmac:*)`
	if got != want {
		t.Errorf("cluster source wrong:\n got %q\nwant %q", got, want)
	}
	// A double quote in a source name must be escaped, not break out of the term.
	if got := buildSourceQuery(tmpl, []string{`a"b`}); got != `source:"a\"b" AND (mac:* OR srcmac:*)` {
		t.Errorf("escaping wrong: %q", got)
	}
}

func TestGraylogSourcesFromVpnConfig(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE vpn_config (
		firewallname TEXT, dns_name TEXT, dns_name_full TEXT, cluster_hostnames TEXT)`); err != nil {
		t.Fatal(err)
	}
	// A cluster (two nodes) matched by dns_name_full, and a standalone matched by firewallname.
	if _, err := db.Exec(`INSERT INTO vpn_config VALUES
		('FGT100F-SITE-A', 'site-a', 'site-a.example.com', 'FGT100F-SITE-A-N1, FGT100F-SITE-A-N2'),
		('FGT40F-SITE-B', 'site-b', 'site-b.example.com', '')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	e := &Extension{dataDir: dir, logger: slog.New(slog.DiscardHandler)}

	// Cluster: both node hostnames returned (matched via dns_name_full).
	got := e.graylogSources("site-a.example.com")
	if len(got) != 2 || got[0] != "FGT100F-SITE-A-N1" || got[1] != "FGT100F-SITE-A-N2" {
		t.Fatalf("cluster sources wrong: %v", got)
	}
	// Standalone (no cluster_hostnames): the firewallname, matched case-insensitively.
	if got := e.graylogSources("site-b.example.com"); len(got) != 1 || got[0] != "FGT40F-SITE-B" {
		t.Fatalf("standalone source wrong: %v", got)
	}
	// No matching row: fall back to the FQDN short host.
	if got := e.graylogSources("unknown-fw.example.com"); len(got) != 1 || got[0] != "unknown-fw" {
		t.Fatalf("fallback source wrong: %v", got)
	}
}

func TestGraylogSourcesFallbackNoDB(t *testing.T) {
	// No adm-vpn-conf DB present → derive from the FQDN.
	e := &Extension{dataDir: t.TempDir(), logger: slog.New(slog.DiscardHandler)}
	if got := e.graylogSources("fw2.example.com"); len(got) != 1 || got[0] != "fw2" {
		t.Fatalf("fallback wrong: %v", got)
	}
}

func TestMacEventFromMessage(t *testing.T) {
	// MAC add: mac + port + vlan + switch parsed from free-text msg.
	mp, ok := macEventFromMessage(map[string]any{
		"name": "SW-ACCESS01",
		"msg":  "50:4f:94:a2:df:e8 discovered on interface port11 in vlan 1 on Switch SW-ACCESS01",
	})
	if !ok || mp.Mac != "50:4f:94:a2:df:e8" || mp.Port != "port11" || mp.Vlan != "1" || mp.SwitchName != "SW-ACCESS01" {
		t.Fatalf("add parse wrong: %+v ok=%t", mp, ok)
	}
	// MAC move: the destination (newest) port wins; indexed sn is the switch.
	mp, ok = macEventFromMessage(map[string]any{
		"sn":  "SW-SERIAL-01",
		"msg": "46:a8:d4:89:ff:39 moved from interface port11 to interface port8 in vlan 100 on Switch SW-ACCESS03",
	})
	if !ok || mp.Port != "port8" || mp.Vlan != "100" || mp.SwitchName != "SW-SERIAL-01" {
		t.Fatalf("move parse wrong: %+v ok=%t", mp, ok)
	}
	// MAC delete has no port → tombstone so the stored binding is dropped.
	mp, ok = macEventFromMessage(map[string]any{"msg": "fa:40:d7:3f:63:2a deleted from vlan 300 on Switch X"})
	if !ok || !mp.Deleted || mp.Mac != "fa:40:d7:3f:63:2a" || mp.Port != "" {
		t.Fatalf("delete parse wrong: %+v ok=%t", mp, ok)
	}
	// Label-prefixed wording (MAC not at position 0) must still parse.
	mp, ok = macEventFromMessage(map[string]any{
		"msg": "MAC 00:11:22:33:44:55 has added on interface port3 in vlan 20 on Switch SW-ACCESS02",
	})
	if !ok || mp.Mac != "00:11:22:33:44:55" || mp.Port != "port3" || mp.Vlan != "20" || mp.SwitchName != "SW-ACCESS02" {
		t.Fatalf("label-prefixed parse wrong: %+v ok=%t", mp, ok)
	}
	// The indexed serial (sn) outranks the friendly name: it is the key the
	// config backup's managed-switch entries use, so the frontend can match it.
	mp, _ = macEventFromMessage(map[string]any{
		"sn": "SW-SERIAL-01", "name": "SW-ACCESS01",
		"msg": "50:4f:94:a2:df:e8 discovered on interface port11 in vlan 1 on Switch SW-ACCESS01",
	})
	if mp.SwitchName != "SW-SERIAL-01" {
		t.Fatalf("sn must outrank name: %+v", mp)
	}
	// NAC device addition: fully structured fields (MAC/sn/port/vlan), no
	// free-text parsing; vlan carries the VLAN *name*.
	mp, ok = macEventFromMessage(map[string]any{
		"MAC": "00:0C:42:AA:87:8E", "sn": "SW-SERIAL-01", "sw": "SW-ACCESS01",
		"port": "port4", "vlan": "VL100", "action": "nac-device-add",
		"logdesc": "NAC device addition",
		"msg":     "New NAC device added with MAC=00:0c:42:aa:87:8e sw=SW-ACCESS01 port=port4 vlan=VL100",
	})
	if !ok || mp.Deleted || mp.Mac != "00:0c:42:aa:87:8e" || mp.Port != "port4" ||
		mp.Vlan != "VL100" || mp.SwitchName != "SW-SERIAL-01" {
		t.Fatalf("nac add parse wrong: %+v ok=%t", mp, ok)
	}
	// NAC device deletion → tombstone.
	mp, ok = macEventFromMessage(map[string]any{
		"MAC": "00:0c:42:aa:87:8e", "sn": "SW-SERIAL-01",
		"action": "nac-device-del", "logdesc": "NAC device deletion",
	})
	if !ok || !mp.Deleted || mp.Mac != "00:0c:42:aa:87:8e" {
		t.Fatalf("nac delete parse wrong: %+v ok=%t", mp, ok)
	}
	// Unparsable free text → skipped.
	if _, ok := macEventFromMessage(map[string]any{"msg": "spanning tree state change"}); ok {
		t.Error("non-MAC event must be skipped")
	}
}

func TestVpnFromMessage(t *testing.T) {
	v, ok := vpnFromMessage(map[string]any{"vpntunnel": "site-a", "remip": "1.2.3.4", "tunneltype": "ipsec", "action": "tunnel-up"})
	if !ok || v.Status != "up" || v.RemIP != "1.2.3.4" || v.Type != "ipsec" {
		t.Fatalf("vpn up wrong: %+v ok=%t", v, ok)
	}
	if v, _ := vpnFromMessage(map[string]any{"tunnelid": "9", "logdesc": "IPsec phase 2 down"}); v.Status != "down" {
		t.Fatalf("vpn down wrong: %+v", v)
	}
	if _, ok := vpnFromMessage(map[string]any{"remip": "1.2.3.4"}); ok {
		t.Error("record without a tunnel name/id must be skipped")
	}
}

func TestWifiFromMessage(t *testing.T) {
	w, ok := wifiFromMessage(map[string]any{"stamac": "CA:02:3A:6E:E7:2C", "ap": "AP-01", "ssid": "GuestWiFi", "signal": "-37", "channel": "1"})
	if !ok || w.Mac != "ca:02:3a:6e:e7:2c" || w.Ap != "AP-01" || w.Ssid != "GuestWiFi" || w.Signal != "-37" {
		t.Fatalf("wifi parse wrong: %+v ok=%t", w, ok)
	}
	if _, ok := wifiFromMessage(map[string]any{"ssid": "x"}); ok {
		t.Error("record without a station MAC must be skipped")
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

	// Device-identification logs (macaddr + srcip; devname is the FortiGate
	// hostname and must NOT be used as the client hostname).
	d, ok = deviceFromMessage(map[string]any{"macaddr": "AA:11:22:33:44:55", "srcip": "10.0.5.1", "devname": "FGT40F_MyFirewall"})
	if !ok || d.Mac != "aa:11:22:33:44:55" || d.IP != "10.0.5.1" {
		t.Fatalf("macaddr alias wrong: %+v ok=%t", d, ok)
	}
	if d.Hostname == "FGT40F_MyFirewall" {
		t.Error("devname (FortiGate hostname) must not be used as device hostname")
	}

	// Switch-controller event logs (switchphysicalport + sn).
	d, ok = deviceFromMessage(map[string]any{"srcmac": "BB:CC:DD:EE:FF:00", "switchphysicalport": "port15", "sn": "S448EP0000000002"})
	if !ok || d.Port != "port15" || d.SwitchID != "S448EP0000000002" {
		t.Fatalf("switchphysicalport alias wrong: %+v ok=%t", d, ok)
	}

	// Traffic logs (dstmac + dstip).
	d, ok = deviceFromMessage(map[string]any{"dstmac": "CC:DD:EE:FF:00:11", "dstip": "192.168.1.50"})
	if !ok || d.Mac != "cc:dd:ee:ff:00:11" || d.IP != "192.168.1.50" {
		t.Fatalf("dstmac alias wrong: %+v ok=%t", d, ok)
	}

	// Traffic log with mastersrcmac (FortiGate uses this for the device MAC).
	d, ok = deviceFromMessage(map[string]any{"mastersrcmac": "AA:BB:CC:12:34:56", "srcip": "192.0.2.12"})
	if !ok || d.Mac != "aa:bb:cc:12:34:56" || d.IP != "192.0.2.12" {
		t.Fatalf("mastersrcmac alias wrong: %+v ok=%t", d, ok)
	}

	// Real traffic log: srcmac + srcname + unauthuser — srcname wins for hostname.
	d, ok = deviceFromMessage(map[string]any{
		"srcmac": "AA:BB:CC:12:34:56", "srcip": "192.0.2.12",
		"srcname": "TEST-CLIENT01", "unauthuser": "T.User",
		"devname": "FGT40F_TestCustomer-Site01", "srcintf": "_default",
	})
	if !ok || d.Mac != "aa:bb:cc:12:34:56" || d.IP != "192.0.2.12" || d.Hostname != "TEST-CLIENT01" {
		t.Fatalf("traffic log parse wrong: %+v ok=%t", d, ok)
	}

	// unauthuser as hostname fallback (when srcname is absent).
	d, ok = deviceFromMessage(map[string]any{
		"srcmac": "AA:BB:CC:12:34:56", "srcip": "192.0.2.12",
		"unauthuser": "T.User", "devname": "FGT40F_TestCustomer-Site01",
	})
	if !ok || d.Hostname != "T.User" {
		t.Fatalf("unauthuser fallback wrong: got %q, want T.User", d.Hostname)
	}

	// VLAN alias (cvid).
	d, ok = deviceFromMessage(map[string]any{"srcmac": "DD:EE:FF:00:11:22", "cvid": "42"})
	if !ok || d.Vlan != "42" {
		t.Fatalf("cvid alias wrong: %+v ok=%t", d, ok)
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
		GraylogDeviceQuery: `source:"%s" AND (mac:* OR srcmac:* OR macaddr:*)`,
		GraylogDeviceRange: "3600",
	}
	e := New(cfg, slog.New(slog.DiscardHandler))
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dev.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		createTableSQL, createStpTableSQL, createStpEventsSQL,
		createMacSightingsSQL, createSwitchEdgesSQL, createWifiSQL, createVpnStatusSQL, createHaStatusSQL,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
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
	n, err := e.refreshFirewall(1, "fw1.example.com", "")
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

	// A refresh RETAINS previously seen devices (30d retention) and keeps
	// their first_seen; the new device joins the inventory.
	srv2 := graylogFake(t, []map[string]any{{"mac": "dd:dd:dd:dd:dd:04", "ip": "10.0.30.1", "timestamp": "T9"}})
	defer srv2.Close()
	e.cfg.GraylogURL = srv2.URL
	if _, err := e.refreshFirewall(1, "fw1.example.com", ""); err != nil {
		t.Fatal(err)
	}
	devices, _, _ = e.listDevices(1)
	if len(devices) != 5 {
		t.Fatalf("refresh must retain previous devices (4) plus the new one, got %d: %+v", len(devices), devices)
	}
	byKey = map[string]Device{}
	for _, d := range devices {
		byKey[d.Mac+"|"+d.IP] = d
	}
	if d := byKey["dd:dd:dd:dd:dd:04|10.0.30.1"]; d.FirstSeen != "T9" || d.LastSeen != "T9" {
		t.Fatalf("new device first/last seen wrong: %+v", d)
	}
	if d := byKey["aa:aa:aa:aa:aa:01|10.0.10.5"]; d.FirstSeen != "T2" {
		t.Fatalf("retained device must keep first_seen: %+v", d)
	}
}

func TestFetchDevicesUnconfigured(t *testing.T) {
	e := testExt(t, "")
	if _, err := e.fetchDevices("fw1", ""); err == nil {
		t.Fatal("missing graylog config must error")
	}
}

func TestEscapeGraylogValue(t *testing.T) {
	if got := escapeGraylogValue(`a"b\c`); got != `a\"b\\c` {
		t.Errorf("escape wrong: %q", got)
	}
}

func TestStpFromMessage(t *testing.T) {
	// Role change (real sample: FortiSwitch spanning Tree event).
	p, ev := stpFromMessage(map[string]any{
		"name": "S124FPTF20001769", "sn": "S124FPTF20001769",
		"switchphysicalport": "port11",
		"msg":                "primary port port11 instance 0 changed role from designated to disabled",
		"timestamp":          "2026-07-08T16:20:37.000Z",
	})
	if p == nil || ev.kind != "role" || ev.value != "disabled" || p.Port != "port11" {
		t.Fatalf("role parse wrong: %+v ev=%+v", p, ev)
	}

	// State change.
	p, ev = stpFromMessage(map[string]any{
		"name": "VER-TFL-ACCESS04", "sn": "S148FFTF23066317",
		"switchphysicalport": "port30",
		"msg":                "primary port port30 instance 0 changed state from forwarding to discarding",
	})
	if p == nil || ev.kind != "state" || ev.value != "discarding" || p.SwitchName != "VER-TFL-ACCESS04" {
		t.Fatalf("state parse wrong: %+v ev=%+v", p, ev)
	}

	// BPDU guard trigger.
	p, ev = stpFromMessage(map[string]any{
		"name": "SW1", "switchphysicalport": "port5",
		"msg": "port5 has been shutdown by BPDU-guard",
	})
	if p == nil || ev.kind != "guard" || ev.value != "bpdu-guard" {
		t.Fatalf("bpdu guard parse wrong: %+v ev=%+v", p, ev)
	}

	// Loop guard recovery clears the block.
	p, ev = stpFromMessage(map[string]any{
		"name": "SW1", "switchphysicalport": "port5",
		"msg": "loop-guard on port5 recovered, port re-enabled",
	})
	if p == nil || ev.kind != "guard" || ev.value != "" {
		t.Fatalf("guard recovery parse wrong: %+v ev=%+v", p, ev)
	}

	// Link status via the status field (port status events).
	p, ev = stpFromMessage(map[string]any{
		"name": "SW1", "switchphysicalport": "port7",
		"status": "down", "msg": "port7 status changed",
	})
	if p == nil || ev.kind != "link" || ev.value != "down" {
		t.Fatalf("link status-field parse wrong: %+v ev=%+v", p, ev)
	}

	// Link status via message wording.
	p, ev = stpFromMessage(map[string]any{
		"name": "SW1", "switchphysicalport": "port8",
		"msg": "port8 link status: up",
	})
	if p == nil || ev.kind != "link" || ev.value != "up" {
		t.Fatalf("link msg parse wrong: %+v ev=%+v", p, ev)
	}

	// No transition → skipped (status "None" from STP events must not parse
	// as a link event).
	if p, _ := stpFromMessage(map[string]any{"name": "SW1", "switchphysicalport": "port5", "status": "None", "msg": "STP enabled"}); p != nil {
		t.Fatalf("expected nil for non-transition message, got %+v", p)
	}
}

// TestFetchStpStatesFold: newest-first messages fold into the latest role,
// state and guard per port.
func TestFetchStpStatesFold(t *testing.T) {
	msgs := []map[string]any{
		// newest: port11 back to designated; port30 discarding; port5 bpdu blocked
		{"name": "SW1", "switchphysicalport": "port11", "msg": "changed role from disabled to designated"},
		{"name": "SW1", "switchphysicalport": "port30", "msg": "changed state from forwarding to discarding"},
		{"name": "SW2", "switchphysicalport": "port5", "msg": "port5 shutdown by bpdu guard"},
		// older events that must NOT win
		{"name": "SW1", "switchphysicalport": "port11", "msg": "changed role from designated to disabled"},
		{"name": "SW1", "switchphysicalport": "port30", "msg": "changed state from discarding to forwarding"},
		{"name": "SW2", "switchphysicalport": "port5", "msg": "bpdu guard recovered on port5"},
		// link events: newest (down) wins over the older up
		{"name": "SW3", "switchphysicalport": "port7", "status": "down", "msg": "port7 status down"},
		{"name": "SW3", "switchphysicalport": "port7", "status": "up", "msg": "port7 status up"},
		// switch-edge observations: a trunk named after the peer's serial
		// fragment with an STP root role (= SW-ACCESS04's uplink toward it),
		// plus MC-LAG trunk membership legs on two switches.
		{"name": "SW-ACCESS04", "sn": "S424EP0000000004", "switchphysicalport": "8EN0000000003-0",
			"msg": "primary port 8EN0000000003-0 instance 0 changed role from designated to root"},
		{"name": "SW-CORE01", "sn": "S524DN0000000001",
			"msg": "Physical port (port27) became active member of trunk (_FlInK1_MLAG0_)"},
		{"name": "SW-CORE01", "sn": "S524DN0000000001",
			"msg": "Physical port (port28) became active member of trunk (_FlInK1_MLAG0_)"},
		{"name": "SW-CORE02", "sn": "S524DN0000000002",
			"msg": "Physical port (port28) became active member of trunk (_FlInK1_MLAG0_)"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type m struct {
			Message map[string]any `json:"message"`
		}
		var out struct {
			Messages []m `json:"messages"`
		}
		for _, mm := range msgs {
			out.Messages = append(out.Messages, m{Message: mm})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	e := &Extension{cfg: &config.Config{
		GraylogURL: srv.URL, GraylogToken: "t",
		GraylogStpQuery: `source:"%s"`,
	}, logger: slog.New(slog.DiscardHandler)}

	stp, events, edges, err := e.fetchStpStates("fw1.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]StpPort{}
	for _, p := range stp {
		byKey[p.SwitchName+"|"+p.Port] = p
	}
	if p := byKey["SW1|port11"]; p.Role != "designated" {
		t.Fatalf("port11 role = %q, want designated (newest wins)", p.Role)
	}
	if p := byKey["SW1|port30"]; p.State != "discarding" {
		t.Fatalf("port30 state = %q, want discarding", p.State)
	}
	if p := byKey["SW2|port5"]; p.Guard != "bpdu-guard" {
		t.Fatalf("port5 guard = %q, want bpdu-guard (newest wins)", p.Guard)
	}
	if p := byKey["SW3|port7"]; p.Link != "down" {
		t.Fatalf("port7 link = %q, want down (newest wins)", p.Link)
	}
	// Every parsed message lands in the event history.
	if len(events) != 9 {
		t.Fatalf("events = %d, want 9", len(events))
	}
	if events[0].Kind != "role" || events[0].To != "designated" || events[0].From != "disabled" {
		t.Fatalf("first event wrong: %+v", events[0])
	}
	// Switch-edge observations: the serial-fragment trunk with its root role
	// (physical "portN" ports must NOT create edges), and the MC-LAG trunk
	// resolved into its member legs on both cores.
	edgeByKey := map[string]SwitchEdge{}
	for _, g := range edges {
		edgeByKey[g.SwitchSN+"|"+g.Trunk] = g
	}
	if len(edges) != 3 {
		t.Fatalf("edges = %d, want 3 (%+v)", len(edges), edges)
	}
	up := edgeByKey["S424EP0000000004|8EN0000000003-0"]
	if up.Role != "root" || up.SwitchName != "SW-ACCESS04" {
		t.Fatalf("uplink edge wrong: %+v", up)
	}
	c1 := edgeByKey["S524DN0000000001|_FlInK1_MLAG0_"]
	if len(c1.Ports) != 2 || c1.Ports[0] != "port27" || c1.Ports[1] != "port28" {
		t.Fatalf("core1 mlag legs wrong: %+v", c1)
	}
	if c2 := edgeByKey["S524DN0000000002|_FlInK1_MLAG0_"]; len(c2.Ports) != 1 || c2.Ports[0] != "port28" {
		t.Fatalf("core2 mlag legs wrong: %+v", c2)
	}
}

// TestBestMacPins: a client seen on its access port AND on the uplink ports
// its frames transit must pin to the access port (fewest distinct MACs), and
// a per-switch delete tombstone must only clear that switch's sighting.
func TestBestMacPins(t *testing.T) {
	e := testExt(t, "http://unused.invalid")
	now := time.Now().Format("2006-01-02 15:04:05")
	sightings := []MacPort{
		// client-01: true access port on SW-ACCESS01 port7 (1 MAC there)...
		{Mac: "00:11:22:00:00:01", SwitchName: "SW-ACCESS01", Port: "port7", Vlan: "100"},
		// ...also learned on the core uplink port, which carries many MACs.
		{Mac: "00:11:22:00:00:01", SwitchName: "SW-CORE01", Port: "port26"},
		{Mac: "00:11:22:00:00:02", SwitchName: "SW-CORE01", Port: "port26"},
		{Mac: "00:11:22:00:00:03", SwitchName: "SW-CORE01", Port: "port26"},
	}
	if err := e.storeMacSightings(1, sightings, now); err != nil {
		t.Fatal(err)
	}
	pins, err := e.bestMacPins(1)
	if err != nil {
		t.Fatal(err)
	}
	if p := pins["00:11:22:00:00:01"]; p.SwitchName != "SW-ACCESS01" || p.Port != "port7" || p.Vlan != "100" {
		t.Fatalf("client must pin to the access port, got %+v", p)
	}
	// Tombstone on the access switch only: the pin falls back to the
	// remaining (uplink) sighting rather than vanishing entirely.
	if err := e.storeMacSightings(1, []MacPort{
		{Mac: "00:11:22:00:00:01", SwitchName: "SW-ACCESS01", Deleted: true},
	}, now); err != nil {
		t.Fatal(err)
	}
	pins, err = e.bestMacPins(1)
	if err != nil {
		t.Fatal(err)
	}
	if p := pins["00:11:22:00:00:01"]; p.SwitchName != "SW-CORE01" || p.Port != "port26" {
		t.Fatalf("after tombstone the core sighting must remain, got %+v", p)
	}
}

// TestStoreStpKeepsAgedOutBlock guards the retention contract: once an STP
// block is stored, a later fetch that only re-sees the port via a different
// event kind (e.g. a link flap, after the blocking event has aged out of the
// Graylog query window) must NOT blank the port's role/state — otherwise the
// still-blocked port silently drops off the dashboard.
func TestStoreStpKeepsAgedOutBlock(t *testing.T) {
	dataDir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "graylog-device-data.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createStpTableSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE stp_ports ADD COLUMN link TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	e := &Extension{db: db, logger: slog.New(slog.DiscardHandler)}

	// Use recent updated_at values (within the retention window) so the row is
	// kept, not pruned.
	layout := "2006-01-02 15:04:05"
	t1 := time.Now().Add(-time.Hour).Format(layout)
	t2 := time.Now().Format(layout)

	// Fetch 1: the STP block is observed.
	if err := e.storeStp(1, []StpPort{{
		SwitchName: "SW1", Port: "port30", Role: "alternate", State: "discarding",
		Link: "up", LastChange: "T1",
	}}, t1); err != nil {
		t.Fatal(err)
	}
	// Fetch 2: the discarding event has aged out; only a link event remains.
	if err := e.storeStp(1, []StpPort{{
		SwitchName: "SW1", Port: "port30", Link: "up", LastChange: "T2",
	}}, t2); err != nil {
		t.Fatal(err)
	}

	got, err := e.listStp(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 stored port, got %d: %+v", len(got), got)
	}
	if got[0].State != "discarding" || got[0].Role != "alternate" {
		t.Fatalf("link-only refresh wiped the aged-out block: %+v", got[0])
	}

	blocked, err := ListBlockedPorts(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 || blocked[0].Reason != "discarding" {
		t.Fatalf("port must still report as blocked, got %+v", blocked)
	}
}
