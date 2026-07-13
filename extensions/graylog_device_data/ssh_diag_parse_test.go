package graylogdevicedata

import (
	"sort"
	"testing"
)

// Fixtures below mirror the real FortiOS 7.6 CLI output format but use
// placeholder switch names/serials/MACs (never real customer data).

const invSample = `Vdom: root
Managed Switch : SW-CORE01     0
Version: FortiSwitch-524D v7.6.6,build1137,251212 (GA)
Serial-Number: FS5240000000001
Hostname: SW-CORE01

Managed Switch : SW-ACC01     0
Version: FortiSwitch-448E v7.6.6,build1137,251212 (GA)
Serial-Number: FS4480000000002
Hostname: SW-ACC01
`

const portStatsSample = `Vdom: root

SW-CORE01:
Port(port1) is HW Admin up, SW Admin up, line protocol is up
full-duplex, 1000 Mb/s, link type is auto
input  : 100 bytes, 5 packets, 0 errors, 2 drops, 0 oversizes
output : 200 bytes, 6 packets, 0 errors, 3 drops, 0 oversizes

Port(port4) is HW Admin up, SW Admin up, line protocol is down
half-duplex, 1000 Mb/s, link type is auto
input  : 0 bytes, 0 packets, 0 errors, 0 drops, 0 oversizes
`

const stpSample = `SW-CORE01:

Instance ID 0 (CST)
  Root           MAC 001122334455, Priority 20480, Path Cost 0
                 (This bridge is the root)
  Port               Speed   Cost       Priority   Role         State        HelloTime  Flags
  ________________   ______  _________  _________  ___________  __________   _________  _______________
  port1              1G      20000      128        DESIGNATED   FORWARDING   2          EN ED
  port4              -       200000000  128        DISABLED     DISCARDING   2          ED
  port25             10G     2000       128        ROOT         FORWARDING   2          EN ED
  internal           1G      20000      128        DESIGNATED   FORWARDING   2          ED
  _FlInK1_ICL0_      80G     1          128        DESIGNATED   FORWARDING   2          EN ED
  111122223333-0     10G     1          128        ROOT         FORWARDING   2          EN
  Flags: EN(STP enable), ED(Edge), LP(Loop Protection Triggered)
`

func TestParseSwitchInventory(t *testing.T) {
	inv := parseSwitchInventory(invSample)
	if len(inv) != 2 {
		t.Fatalf("want 2 switches, got %d: %+v", len(inv), inv)
	}
	if inv[0].Name != "SW-CORE01" || inv[0].Serial != "FS5240000000001" {
		t.Errorf("switch[0] = %+v", inv[0])
	}
	if inv[1].Name != "SW-ACC01" || inv[1].Serial != "FS4480000000002" {
		t.Errorf("switch[1] = %+v", inv[1])
	}
}

func TestParsePortStats(t *testing.T) {
	links := parsePortStats(portStatsSample)
	if up, ok := links["port1"]; !ok || !up {
		t.Errorf("port1 should be up, got %v/%v", up, ok)
	}
	if up, ok := links["port4"]; !ok || up {
		t.Errorf("port4 should be down, got %v/%v", up, ok)
	}
	if len(links) != 2 {
		t.Errorf("want 2 ports, got %d", len(links))
	}
}

func TestParseStp(t *testing.T) {
	ports, edges := parseStp(stpSample)
	if p := ports["port1"]; p.Role != "designated" || p.State != "forwarding" {
		t.Errorf("port1 = %+v", p)
	}
	if p := ports["port4"]; p.Role != "disabled" || p.State != "discarding" {
		t.Errorf("port4 = %+v", p)
	}
	if p := ports["port25"]; p.Role != "root" {
		t.Errorf("port25 role = %q, want root", p.Role)
	}
	if _, ok := ports["internal"]; ok {
		t.Error("internal must not be a physical STP port")
	}
	if len(ports) != 3 {
		t.Errorf("want 3 physical ports, got %d: %+v", len(ports), ports)
	}
	// Interlink trunks: ICL + peer-serial trunk, but not "internal".
	got := map[string]string{}
	for _, e := range edges {
		got[e.Trunk] = e.Role
	}
	if got["_FlInK1_ICL0_"] != "designated" {
		t.Errorf("ICL edge role = %q", got["_FlInK1_ICL0_"])
	}
	if got["111122223333-0"] != "root" {
		t.Errorf("peer trunk edge role = %q (root = uplink)", got["111122223333-0"])
	}
	if len(edges) != 2 {
		t.Errorf("want 2 interlink edges, got %d: %+v", len(edges), edges)
	}
}

func TestBuildDiagPorts(t *testing.T) {
	sw := diagSwitch{Name: "SW-CORE01", Serial: "FS5240000000001"}
	ports, edges := buildDiagPorts(sw, portStatsSample, stpSample)

	byPort := map[string]StpPort{}
	for _, p := range ports {
		if p.SwitchName != "SW-CORE01" || p.Serial != "FS5240000000001" {
			t.Errorf("port %q wrong switch identity: %+v", p.Port, p)
		}
		byPort[p.Port] = p
	}
	// Up port keeps STP role/state.
	if p := byPort["port1"]; p.Link != "up" || p.Role != "designated" || p.State != "forwarding" {
		t.Errorf("port1 = %+v", p)
	}
	// Down port: link down, and NO STP role/state (so it renders as down, not blocked).
	if p := byPort["port4"]; p.Link != "down" || p.Role != "" || p.State != "" {
		t.Errorf("port4 = %+v (down port must not carry role/state)", p)
	}
	// Port present only in STP (no port-stats) is inferred up and marked as the uplink.
	if p := byPort["port25"]; p.Link != "up" || p.Role != "root" {
		t.Errorf("port25 = %+v (should be inferred up + root uplink)", p)
	}
	// Edges carry this switch's serial as the key the frontend resolves peers by.
	trunks := make([]string, 0, len(edges))
	for _, e := range edges {
		if e.SwitchSN != "FS5240000000001" {
			t.Errorf("edge %q missing switch serial: %+v", e.Trunk, e)
		}
		trunks = append(trunks, e.Trunk)
	}
	sort.Strings(trunks)
	if len(trunks) != 2 || trunks[0] != "111122223333-0" || trunks[1] != "_FlInK1_ICL0_" {
		t.Errorf("edges = %v", trunks)
	}
}
