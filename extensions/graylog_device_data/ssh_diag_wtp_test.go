package graylogdevicedata

import "testing"

// Redacted fixture mirroring the real `get wireless-controller wtp-status`
// layout (serials/MACs/IPs/names are placeholders): two connected APs whose
// embedded LLDP report names the wired switch (sys name) + port (port id), and
// one AP with LLDP disabled (no switch/port). Field spacing is intentionally
// irregular, matching the device output.
const wtpStatusFixture = `WTP: AP TEST ONE  0-10.0.0.11:5246
    vdom             : root
    wtp-id           : FP000FTEST0000001
    name             : AP TEST ONE
    mgmt_vlanid      : 0
    local-ip-addr   : 10.0.0.11
    board-mac        : 00:11:22:AA:BB:01
    connection-state : Connected
  LLDP               : enabled (total 1)
    local port       : lan1
    chassis id       : mac 00:11:22:CC:DD:01
    sys name         : FSW-FLOOR1-SW01
    sys description  : FortiSwitch-424E-POE v7.6.6
    capability       : Bridge Router
    port id          : port5
    port description : FortiAP-TEST-ONE
    ip               : 10.99.0.10
  Radio 1            : AP
    client-count     : 3
    base-bssid       : 00:11:22:AA:BB:05
WTP: AP TEST TWO  0-10.0.0.12:5246
    vdom             : root
    wtp-id           : FP000FTEST0000002
    name             : AP TEST TWO
    local-ip-addr   : 10.0.0.12
    board-mac        : 00:11:22:AA:BB:02
    connection-state : Connected
  LLDP               : enabled (total 1)
    local port       : lan1
    chassis id       : mac 00:11:22:CC:DD:02
    sys name         : FSW-FLOOR2-SW02
    port id          : port12 (ifname)
    port description : FortiAP-TEST-TWO
  Radio 1            : AP
    client-count     : 0
WTP: AP TEST NOLLDP  0-10.0.0.13:5246
    vdom             : root
    wtp-id           : FP000FTEST0000003
    name             : AP TEST NOLLDP
    local-ip-addr   : 10.0.0.13
    board-mac        : 00:11:22:AA:BB:03
    connection-state : Connected
  LLDP               : disabled
  Radio 1            : AP
`

func TestParseWtpStatus(t *testing.T) {
	got := parseWtpStatus(wtpStatusFixture)
	if len(got) != 3 {
		t.Fatalf("expected 3 APs, got %d: %+v", len(got), got)
	}
	byId := map[string]ApLocation{}
	for _, a := range got {
		byId[a.Serial] = a
	}

	one, ok := byId["FP000FTEST0000001"]
	if !ok {
		t.Fatal("AP one missing")
	}
	if one.Name != "AP TEST ONE" || one.Switch != "FSW-FLOOR1-SW01" || one.Port != "port5" {
		t.Errorf("AP one: name=%q switch=%q port=%q", one.Name, one.Switch, one.Port)
	}
	if one.BoardMac != "00:11:22:aa:bb:01" { // lowercased
		t.Errorf("AP one board-mac not lowercased: %q", one.BoardMac)
	}
	if one.IP != "10.0.0.11" {
		t.Errorf("AP one ip=%q", one.IP)
	}

	two := byId["FP000FTEST0000002"]
	if two.Switch != "FSW-FLOOR2-SW02" || two.Port != "port12" { // "(ifname)" suffix stripped
		t.Errorf("AP two: switch=%q port=%q (want FSW-FLOOR2-SW02/port12)", two.Switch, two.Port)
	}

	// LLDP-disabled AP is still inventoried (serial present) but has no location.
	three := byId["FP000FTEST0000003"]
	if three.Name != "AP TEST NOLLDP" {
		t.Errorf("AP three name=%q", three.Name)
	}
	if three.Switch != "" || three.Port != "" {
		t.Errorf("AP three should have no location, got switch=%q port=%q", three.Switch, three.Port)
	}
}
