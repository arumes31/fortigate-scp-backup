package graylogdevicedata

import (
	"sort"
	"strings"
	"testing"
)

// Fixtures mirror the real FortiOS 7.6 CLI output but use placeholder switch
// names / serials / MACs (never real customer data).

const invSample = `Vdom: root
Managed Switch : SW-CORE01     0
Version: FortiSwitch-524D v7.6.6,build1137,251212 (GA)
Serial-Number: FS5240000000001
Hostname: SW-CORE01

Managed Switch : SW-ACC01     0
Serial-Number: FS4480000000002
Hostname: SW-ACC01
`

const portStatsSample = `Vdom: root

SW-CORE01:
Port(port1) is HW Admin up, SW Admin up, line protocol is up
full-duplex, 1000 Mb/s, link type is auto
input  : 100 bytes, 5 packets, 0 errors, 38 drops, 0 oversizes
output : 200 bytes, 6 packets, 0 errors, 97 drops, 0 oversizes
0 fragments, 0 undersizes, 0 collisions, 0 jabbers

Port(port2) is HW Admin up, SW Admin up, line protocol is up
half-duplex, 10 Mb/s, link type is auto
input  : 10 bytes, 1 packets, 2 errors, 36 drops, 0 oversizes
output : 20 bytes, 2 packets, 0 errors, 202 drops, 0 oversizes
0 fragments, 0 undersizes, 9 collisions, 0 jabbers

Port(port4) is HW Admin down, SW Admin down, line protocol is down
half-duplex, 1000 Mb/s, link type is auto
input  : 0 bytes, 0 packets, 0 errors, 0 drops, 0 oversizes
output : 0 bytes, 0 packets, 0 errors, 0 drops, 0 oversizes
0 fragments, 0 undersizes, 0 collisions, 0 jabbers
`

const stpSample = `SW-CORE01:
  Port               Speed   Cost       Priority   Role         State        HelloTime  Flags
  ________________   ______  _________  _________  ___________  __________   _________  _______________
  port1              1G      20000      128        DESIGNATED   FORWARDING   2          EN ED
  port2              1G      20000      128        DESIGNATED   FORWARDING   2          EN ED BG
  port4              -       200000000  128        DISABLED     DISCARDING   2          ED
  port25             10G     2000       128        ROOT         FORWARDING   2          EN ED
  444455556666-0    10G     1          128        ROOT         FORWARDING   2          EN
  _FlInK1_ICL0_      80G     1          128        DESIGNATED   FORWARDING   2          EN ED
  111122223333-0     20G     1          128        ALTERNATIVE  DISCARDING   2          EN
  internal           1G      20000      128        DESIGNATED   FORWARDING   2          ED
  Flags: EN(STP enable), ED(Edge), LP(Loop Protection), RG(Root Guard), BG(BPDU Guard)
`

const portPropsSample = `Vdom: root
Switch: SW-CORE01
Port: port1
  PoE		: 802.3af/at,30.0W
  Connector	: RJ45
  Speed		: 10Mhalf/100Mfull/1Gauto/auto
Port: port25
  PoE		:
  Connector	: SFP+
  Speed		: 1G/10G/auto-module
`

const poeSample = `Unit Power Budget: 250.00W
Unit Power Consumption: 6.40W

Interface   Status    State             Max-Power(W)   Power-consumption(W)   Priority   Class   Error
port1       Enabled   Delivering Power  30.0           6.40                   Low        4
port5       Enabled   Searching         0.00           0.00                   Low        0
port6       Disabled  Disabled          0.00           0.00                   Low        0
`

const modulesSample = `  Portname   State    Type      DMI  Transceiver    RX  Vendor
  ________   _____    ____      ___  ___________    __  ______
  port25     INSERT   SFP/SFP+  N    10G-Base-CR    OK  VendorX
  port26     EMPTY    -         -    -              -   -
`

const dot1xSample = `Managed Switch : SW-ACC01
   port1 : Mode: port-based (mac-by-pass enable)
           Port State: authorized: (  )
           Dynamic Authorized Vlan : 101
           Sessions info:
           aa:bb:cc:dd:ee:ff	 Type=802.1x,TLS,state=AUTHENTICATED,etime=7 params:reAuth=3600
           user="host/PC-01.example.local",security_grp="GRP-A",radsec="disable"
   port2 : Mode: port-based
           Port State: unauthorized: (  )
`

const lldpSample = `Managed Switch : SW-ACC01	0
_______________________________________________________________
Neighbor learned on port port1 by LLDP protocol
Chassis ID: PC-01 (local)
Port ID: aa:bb:cc:dd:ee:ff (mac)
_______________________________________________________________
Neighbor learned on port port25 by LLDP protocol
Chassis ID: SW-CORE01 (local)
Port ID: 00:11:22:33:44:55 (mac)
`

const arpSample = `Address           Age(min)   Hardware Addr      Interface
192.168.1.10      0          aa:bb:cc:dd:ee:ff VL101
10.0.0.5          82         00:11:22:33:44:55 VL100
`

const perfSample = `CPU states: 4% user 1% system 0% nice 95% idle 0% iowait
Memory: 7662456k total, 2702156k used (35.3%), 4458428k free
Average sessions: 6524 sessions in 1 minute, 6046 sessions in 10 minutes
Uptime: 21 days,  7 hours,  18 minutes
`

const haSample = `[Debug_Zone HA information]
FGT90GTK00000001:      Primary, serialno_prio=0, usr_priority=128, hostname=FGT-N2
FGT90GTK00000002:    Secondary, serialno_prio=1, usr_priority=128, hostname=FGT-N1
vcluster 1, state=work, primary_ip=169.254.0.1
`

const macTableSample = `Vdom: root

Managed Switch : SW-CORE01 0
MAC: 00:11:22:33:44:55	VLAN: 100 Port: port1(port-id 1)
  Flags: 0x00010441 [ hit dynamic src-hit native ]
MAC: 66:77:88:99:AA:BB	VLAN: 101 Trunk: 444455556666-0(trunk-id 1)
  Flags: 0x000104c1 [ hit trunk dynamic ]
MAC: cc:dd:ee:ff:00:11	VLAN: 4092 Port: internal(port-id 53)
  Flags: 0x00000020 [ static ]
`

func TestParseSwitchInventory(t *testing.T) {
	inv := parseSwitchInventory(invSample)
	if len(inv) != 2 || inv[0].Name != "SW-CORE01" || inv[0].Serial != "FS5240000000001" {
		t.Fatalf("inventory = %+v", inv)
	}
}

func TestParsePortStats(t *testing.T) {
	ps := parsePortStats(portStatsSample)
	if p := ps["port1"]; !p.Up || !p.AdminUp || p.Speed != "1G/full" || p.Health != "" {
		t.Errorf("port1 = %+v", p)
	}
	if p := ps["port2"]; p.Speed != "10M/half" || p.Health != "err:2 col:9" {
		t.Errorf("port2 = %+v (want speed 10M/half, health 'err:2 col:9')", p)
	}
	if p := ps["port4"]; p.Up || p.AdminUp {
		t.Errorf("port4 should be down + admin-down: %+v", p)
	}
}

func TestParseStp(t *testing.T) {
	ports, edges := parseStp(stpSample)
	if p := ports["port2"]; p.Role != "designated" || p.Guard != "bpdu-guard" {
		t.Errorf("port2 = %+v (want designated + bpdu-guard)", p)
	}
	if p := ports["port25"]; p.Role != "root" {
		t.Errorf("port25 role = %q, want root", p.Role)
	}
	if _, ok := ports["internal"]; ok {
		t.Error("internal must not be a physical STP port")
	}
	got := map[string]diagEdge{}
	for _, e := range edges {
		got[e.Trunk] = e
	}
	if e := got["444455556666-0"]; e.Role != "root" || e.State != "forwarding" {
		t.Errorf("uplink edge = %+v", e)
	}
	if e := got["111122223333-0"]; e.Role != "alternate" || e.State != "discarding" {
		t.Errorf("blocked lateral edge = %+v (want alternate/discarding)", e)
	}
}

func TestParsePortProperties(t *testing.T) {
	pp := parsePortProperties(portPropsSample)
	if p := pp["port1"]; p.Media != "RJ45" || !p.PoeCapable || p.HasSFP {
		t.Errorf("port1 = %+v (want RJ45, PoE-capable, not SFP)", p)
	}
	if p := pp["port25"]; p.Media != "SFP+" || p.PoeCapable || !p.HasSFP {
		t.Errorf("port25 = %+v (want SFP+, not PoE, HasSFP)", p)
	}
}

func TestParsePoeSummary(t *testing.T) {
	poe := parsePoeSummary(poeSample)
	if poe["port1"] != "deliver:6.40/30.0W:cls4" {
		t.Errorf("port1 poe = %q", poe["port1"])
	}
	if poe["port5"] != "search" {
		t.Errorf("port5 poe = %q, want search", poe["port5"])
	}
	if poe["port6"] != "off" {
		t.Errorf("port6 poe = %q, want off", poe["port6"])
	}
}

func TestParseModulesSummary(t *testing.T) {
	m := parseModulesSummary(modulesSample)
	if m["port25"] != "10G-Base-CR" {
		t.Errorf("port25 optic = %q", m["port25"])
	}
	if m["port26"] != "empty" {
		t.Errorf("port26 optic = %q, want empty", m["port26"])
	}
}

func TestParseDot1x(t *testing.T) {
	d := parseDot1x(dot1xSample)
	if d["port1"] != "authorized" || d["port2"] != "unauthorized" {
		t.Errorf("dot1x = %+v (indented port headers must parse)", d)
	}
}

func TestParseDot1xSessions(t *testing.T) {
	s := parseDot1xSessions(dot1xSample)
	if len(s) != 1 { // only port1 has an authenticated session
		t.Fatalf("want 1 session, got %d: %+v", len(s), s)
	}
	if s[0].Mac != "aa:bb:cc:dd:ee:ff" || s[0].User != "host/PC-01.example.local" ||
		s[0].Group != "GRP-A" || s[0].Vlan != "101" {
		t.Errorf("session = %+v", s[0])
	}
}

func TestParseArp(t *testing.T) {
	a := parseArp(arpSample)
	if len(a) != 2 {
		t.Fatalf("want 2 arp entries, got %d", len(a))
	}
	if a[0].Mac != "aa:bb:cc:dd:ee:ff" || a[0].IP != "192.168.1.10" || a[0].Iface != "VL101" {
		t.Errorf("arp[0] = %+v", a[0])
	}
}

func TestParseLldp(t *testing.T) {
	l := parseLldp(lldpSample)
	if l["port1"] != "PC-01" || l["port25"] != "SW-CORE01" {
		t.Errorf("lldp = %+v", l)
	}
}

// Real FortiSwitch LLDP detail reports the neighbor's Chassis ID as a base MAC
// while also giving its System Name / Serial-num. The MAC does not resolve to a
// managed switch (it is outside the port-MAC range), so the parser must prefer
// the name/serial; only a bare host with no name falls back to the MAC.
const lldpDetailSample = `Managed Switch : SW-ACCESS04	0
_______________________________________________________________
Neighbor learned on port port12 by LLDP protocol
Last change 100 seconds ago
Chassis ID: aa:bb:cc:00:00:12 (mac)
System Name: SW-EDGE01
System Description:
FortiSwitch-108E v7.6.6
System Serial-num: S108EN0000000001
Port ID: port8 (ifname)
_______________________________________________________________
Neighbor learned on port port2 by LLDP protocol
Chassis ID: aa:bb:cc:00:00:02 (mac)
System Name: FortiAP-231F
Port ID: 00:11:22:33:44:55 (mac)
_______________________________________________________________
Neighbor learned on port port25 by LLDP protocol
Chassis ID: aa:bb:cc:00:00:25 (mac)
Port ID: aa:bb:cc:00:00:25 (mac)
`

func TestParseLldpPrefersName(t *testing.T) {
	l := parseLldp(lldpDetailSample)
	if l["port12"] != "SW-EDGE01" { // System Name wins over the chassis MAC
		t.Errorf("port12 = %q, want SW-EDGE01 (name, not chassis MAC)", l["port12"])
	}
	if l["port2"] != "FortiAP-231F" {
		t.Errorf("port2 = %q, want FortiAP-231F", l["port2"])
	}
	if l["port25"] != "aa:bb:cc:00:00:25" { // no name → fall back to chassis MAC
		t.Errorf("port25 = %q, want chassis MAC fallback", l["port25"])
	}
}

const mclagIclSample = `Vdom: root
Managed Switch : SW-CORE01	0
_FlInK1_ICL0_
    icl-ports            29-30
    egress-block-ports   23-24
    local-serial-number  FS5240000000001
    peer-serial-number   FS5240000000002
    split-brain          Disabled

Counters
    received keepalive packets          169063
    received keepalive drop packets     14
`

const fanSample = `Managed Switch : SW-ACC01     0

Module		Status
___________________________________
FAN1		OK(40.4 %)
`

const qosSample = `SW-ACC01:
port1 QoS Stats:
 queue |              pkts |             bytes |         drop pkts
------------------------------------------------------------------
     0 |                 0 |                 0 |             14997
     1 |                 0 |                 0 |                 0
------------------------------------------------------------------
`

const routesSample = `Routing table for VRF=0
S*      0.0.0.0/0 [1/0] via 1.2.3.4, wan1, [30/255]
                  [1/0] via 5.6.7.8, wan2, [30/254]
S       10.0.0.0/24 [10/0] via TUN_A tunnel 9.9.9.9, [1/0]
S       10.0.2.0/24 [10/0] via TUN_A tunnel 9.9.9.9, [1/0]
C       192.168.1.0/24 is directly connected, VL100
`

func TestExpandPortRange(t *testing.T) {
	if got := expandPortRange("29-30,25"); len(got) != 3 || got[0] != "port29" || got[2] != "port25" {
		t.Errorf("expandPortRange = %v", got)
	}
}

func TestParseMclagIcl(t *testing.T) {
	m := parseMclagIcl(mclagIclSample)
	if m == nil {
		t.Fatal("nil ICL")
	}
	if m.Trunk != "_FlInK1_ICL0_" || m.PeerSerial != "FS5240000000002" || m.SplitBrain != "Disabled" || m.KeepaliveDrop != 14 {
		t.Errorf("icl = %+v", m)
	}
	if len(m.Ports) != 2 || m.Ports[0] != "port29" || m.Ports[1] != "port30" {
		t.Errorf("icl ports = %v", m.Ports)
	}
	if parseMclagIcl("no icl here") != nil {
		t.Error("expected nil for non-ICL output")
	}
}

func TestParseFan(t *testing.T) {
	if parseFan(fanSample) != "OK" {
		t.Errorf("fan = %q", parseFan(fanSample))
	}
	if f := parseFan("Module\tStatus\nFAN1\tFAIL\n"); f == "" || !strings.Contains(f, "FAULT") {
		t.Errorf("fault fan = %q", f)
	}
	if parseFan("no fans") != "" {
		t.Error("expected empty for no fans")
	}
}

func TestParseQosCongestion(t *testing.T) {
	if n := parseQosCongestion(qosSample); n != 14997 {
		t.Errorf("congestion = %d, want 14997", n)
	}
}

func TestParseRoutes(t *testing.T) {
	got := map[string]LiveRoute{}
	for _, r := range parseRoutes(routesSample) {
		got[r.Device] = r
	}
	if r := got["TUN_A"]; r.Routes != 2 || r.Default {
		t.Errorf("TUN_A = %+v (want 2 routes, not default)", r)
	}
	if r := got["wan1"]; r.Routes != 1 || !r.Default {
		t.Errorf("wan1 = %+v (want default)", r)
	}
	if r := got["wan2"]; !r.Default { // ECMP continuation line still marked default
		t.Errorf("wan2 = %+v (want default)", r)
	}
	if r := got["VL100"]; r.Routes != 1 || r.Default {
		t.Errorf("VL100 = %+v", r)
	}
}

const sdwanSample = `Health Check(HC1):
Seq(1 VL1831): state(alive), packet-loss(0.000%), latency(5.382), jitter(0.051), mos(4.402), bandwidth-up(304700)
Seq(2 x2): state(alive), packet-loss(0.000%), latency(10.737), jitter(10.606), mos(4.388)
Health Check(HC2):
Seq(1 VL1831): state(alive), packet-loss(11.000%), latency(160.119), jitter(34.229), mos(4.064)
Seq(2 x2): state(dead), packet-loss(15.000%), latency(175.699), jitter(60.566), mos(3.785)
`

const netlinkSample = `if=x2 family=00 type=1 index=4 mtu=1500
ref=169 state=start present
stat: rxp=70 txp=22 rxb=8809383782340 txb=444504850638 rxe=0 txe=0 rxd=0 @ time=1783951295
if=port1 family=00
stat: rxp=1 txp=2 rxb=1000 txb=2000 rxe=3 txe=4 @ time=1
`

func TestParseSdwanHealth(t *testing.T) {
	got := map[string]SdwanHealth{}
	for _, h := range parseSdwanHealth(sdwanSample) {
		got[h.Member] = h
	}
	if h := got["VL1831"]; h.Loss != 11 || h.Latency != 160.119 || h.State != "alive" {
		t.Errorf("VL1831 = %+v (want worst loss 11, latency 160.119, alive)", h)
	}
	if h := got["x2"]; h.Loss != 15 || h.State != "dead" {
		t.Errorf("x2 = %+v (want loss 15, dead)", h)
	}
}

func TestParseStpTcn(t *testing.T) {
	if n := parseStpTcn("TCN Events  Triggered 3 (1d ago)\nTCN Events  Triggered 5 (2h ago)"); n != 5 {
		t.Errorf("tcn = %d, want 5", n)
	}
}

func TestParsePoeBudget(t *testing.T) {
	used, total := parsePoeBudget(poeSample)
	if used != 6.40 || total != 250.00 {
		t.Errorf("poe budget = %v/%v, want 6.40/250.00", used, total)
	}
}

func TestParseNetlinkIfaces(t *testing.T) {
	got := map[string]ifaceCounter{}
	for _, c := range parseNetlinkIfaces(netlinkSample) {
		got[c.Iface] = c
	}
	if c := got["x2"]; c.RxB != 8809383782340 || c.TxB != 444504850638 {
		t.Errorf("x2 = %+v", c)
	}
	if c := got["port1"]; c.RxB != 1000 || c.TxE != 4 {
		t.Errorf("port1 = %+v", c)
	}
}

func TestParseFwHealth(t *testing.T) {
	h := parseFwHealth(perfSample, haSample)
	if h.CPU != "5%" || h.Mem != "35.3%" || h.Sessions != "6524" || h.Uptime != "21d 7h" {
		t.Errorf("health = %+v", h)
	}
	if h.HA != "FGT-N2 Primary · FGT-N1 Secondary (work)" {
		t.Errorf("HA = %q", h.HA)
	}
	if s := h.summary(); s == "" || !strings.Contains(s, "CPU 5%") || !strings.Contains(s, "HA:") {
		t.Errorf("summary = %q", s)
	}
}

func TestParseMacTable(t *testing.T) {
	mp := parseMacTable(macTableSample)
	if len(mp) != 1 { // only the Port: portN row; Trunk + internal skipped
		t.Fatalf("want 1 access-port sighting, got %d: %+v", len(mp), mp)
	}
	if mp[0].Mac != "00:11:22:33:44:55" || mp[0].Port != "port1" || mp[0].Vlan != "100" || mp[0].SwitchName != "SW-CORE01" {
		t.Errorf("mac sighting = %+v", mp[0])
	}
}

func TestBuildDiagPorts(t *testing.T) {
	sw := diagSwitch{Name: "SW-CORE01", Serial: "FS5240000000001"}
	ports, edges := buildDiagPorts(sw, portStatsSample, stpSample, portPropsSample, poeSample, modulesSample, dot1xSample, lldpSample)

	by := map[string]StpPort{}
	for _, p := range ports {
		by[p.Port] = p
	}
	// Up port keeps role/state + physical enrichment.
	if p := by["port1"]; p.Link != "up" || p.Role != "designated" || p.Admin != "up" ||
		p.Speed != "1G/full" || p.Media != "RJ45" || p.Poe != "deliver:6.40/30.0W:cls4" || p.Dot1x != "authorized" {
		t.Errorf("port1 = %+v", p)
	}
	// Guard + health on an up port (half-duplex now flagged as a physical fault).
	if p := by["port2"]; p.Guard != "bpdu-guard" || p.Health != "err:2 col:9 half-duplex" || p.Dot1x != "unauthorized" {
		t.Errorf("port2 = %+v", p)
	}
	// Down + admin-down port: no role/state (not "blocked").
	if p := by["port4"]; p.Link != "down" || p.Role != "" || p.State != "" || p.Admin != "down" {
		t.Errorf("port4 = %+v", p)
	}
	// STP-only port inferred up + uplink; SFP optic + LLDP neighbor attached.
	if p := by["port25"]; p.Link != "up" || p.Role != "root" || p.Media != "SFP+" || p.Optic != "10G-Base-CR" || p.Neighbor != "SW-CORE01" {
		t.Errorf("port25 = %+v", p)
	}
	// 802.1X port state + LLDP neighbor on an access port.
	if p := by["port1"]; p.Dot1x != "authorized" || p.Neighbor != "PC-01" {
		t.Errorf("port1 dot1x/neighbor = %+v", p)
	}
	// Edges carry state; the blocked lateral is captured.
	es := map[string]string{}
	for _, e := range edges {
		es[e.Trunk] = e.Role + "/" + e.State
	}
	if es["111122223333-0"] != "alternate/discarding" {
		t.Errorf("blocked lateral edge = %q", es["111122223333-0"])
	}
	trunks := make([]string, 0, len(edges))
	for _, e := range edges {
		trunks = append(trunks, e.Trunk)
	}
	sort.Strings(trunks)
	if len(trunks) != 3 {
		t.Errorf("edges = %v (want 3: uplink, ICL, blocked lateral)", trunks)
	}
}
