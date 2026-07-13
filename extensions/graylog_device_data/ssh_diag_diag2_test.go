package graylogdevicedata

import (
	"strings"
	"testing"
)

// Real port-stats layout with a half-duplex, downshifted, error-accumulating port.
const portStatsFixture = `Vdom: root

SW1:
Port(port1) is HW Admin up, SW Admin up, line protocol is up
Interface Type is SGMII
Address is E0:23:FF:00:00:01, None loopback
MTU 9216 bytes, Encapsulation IEEE 802.3/Ethernet-II
half-duplex, 100 Mb/s, link type is auto
input  : 1000 bytes, 10 packets, 42 errors, 3 drops, 1 oversizes
         5 unicasts, 2 multicasts, 3 broadcasts, 0 unknowns
output : 2000 bytes, 20 packets, 8 errors, 1 drops, 0 oversizes
         6 unicasts, 1 multicasts, 2 broadcasts
0 fragments, 0 undersizes, 9 collisions, 0 jabbers

Port(port2) is HW Admin up, SW Admin up, line protocol is down
`

func TestParsePortStatsCounters(t *testing.T) {
	m := parsePortStats(portStatsFixture)
	p1, ok := m["port1"]
	if !ok {
		t.Fatal("port1 missing")
	}
	if !p1.Up || !p1.Half || p1.SpeedM != 100 || p1.Speed != "100M/half" {
		t.Errorf("port1 link/duplex/speed wrong: %+v", p1)
	}
	// Errors = err(42+8) + ovr(1+0) + frag(0) + undr(0) + col(9) + jab(0) = 60.
	if p1.Errors != 60 {
		t.Errorf("port1 Errors = %d, want 60", p1.Errors)
	}
	// Discards = drops(3+1) = 4.
	if p1.Discards != 4 {
		t.Errorf("port1 Discards = %d, want 4", p1.Discards)
	}
	if m["port2"].Up {
		t.Error("port2 should be down")
	}
}

func TestMaxSpeedMbps(t *testing.T) {
	cases := map[string]int{
		"10Mhalf/10Mfull/100Mhalf/100Mfull/1Gauto/auto": 1000,
		"1000full/10Gfull/auto":                         10000,
		"100Mfull":                                      100,
		"auto":                                          0,
	}
	for in, want := range cases {
		if got := maxSpeedMbps(in); got != want {
			t.Errorf("maxSpeedMbps(%q) = %d, want %d", in, got, want)
		}
	}
}

// buildDiagPorts folds the half-duplex physical-layer fault into the port
// health. A speed below the port's local capability is intentionally NOT a
// fault (a slower peer negotiates legitimately), so it must NOT appear.
func TestBuildDiagPortsPhysFaults(t *testing.T) {
	props := "Port: port1\n  Connector\t: RJ45\n  Speed\t\t: 10Mhalf/100Mfull/1Gauto/auto\n"
	ports, _ := buildDiagPorts(diagSwitch{Name: "SW1", Serial: "S1"}, portStatsFixture, "", props, "", "", "", "")
	var p1 *StpPort
	for i := range ports {
		if ports[i].Port == "port1" {
			p1 = &ports[i]
		}
	}
	if p1 == nil {
		t.Fatal("port1 not built")
	}
	if !strings.Contains(p1.Health, "half-duplex") {
		t.Errorf("expected half-duplex flag in health, got %q", p1.Health)
	}
	if strings.Contains(p1.Health, "downshift") {
		t.Errorf("capability-vs-negotiated downshift must not be flagged, got %q", p1.Health)
	}
}

func TestParseMacLimitViolations(t *testing.T) {
	out := `Managed Switch : SW1 0
      Port		VLAN ID		MAC Address			Timestamp		Action
---------------------------------------------------------------------
    port5   100   00:11:22:aa:bb:cc   2026-07-13 10:00:00   drop

Managed Switch : SW2 0
      Port		VLAN ID		MAC Address			Timestamp		Action
---------------------------------------------------------------------
`
	vs := parseMacLimitViolations(out)
	if len(vs) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(vs), vs)
	}
	v := vs[0]
	if v.Switch != "SW1" || v.Port != "port5" || v.Vlan != "100" || v.Mac != "00:11:22:aa:bb:cc" {
		t.Errorf("violation parsed wrong: %+v", v)
	}
	if !strings.Contains(v.Action, "drop") {
		t.Errorf("action should include drop: %q", v.Action)
	}
}
