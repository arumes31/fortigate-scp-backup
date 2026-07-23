package fgt_confconv

import "testing"

const testConfig = `#config-version=FGT90G-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin
#conf_file_ver=1234
#buildno=3704
config system interface
    edit "port3"
        set vdom "root"
        set ip 0.0.0.0 0.0.0.0
        set allowaccess ping
        set type physical
    next
    edit "port4"
        set vdom "root"
        set ip 0.0.0.0 0.0.0.0
        set type physical
    next
    edit "hwsw1"
        set vdom "root"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping https ssh
        set type hard-switch
        set member "port5" "port6"
    next
    edit "VL100"
        set vdom "root"
        set ip 10.0.100.1 255.255.255.0
        set allowaccess ping https
        set role lan
        set interface "fortilink1"
        set vlanid 100
    next
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.10 255.255.255.0
        set role wan
        set type physical
    next
    edit "wan2"
        set vdom "root"
        set ip 203.0.113.20 255.255.255.0
        set role wan
        set type physical
    next
    edit "wan10"
        set vdom "root"
        set ip 203.0.113.30 255.255.255.0
        set role wan
        set type physical
    next
end
config system zone
    edit "zone-dmz"
        set interface "port3" "port4"
        set intrazone-deny disable
    next
end
config firewall policy
    edit 5
        set name "Open Policy"
        set srcintf "port3" "port4"
        set dstintf "wan1"
        set action accept
    next
    edit 6
        set name "WAN Out"
        set srcintf "VL100"
        set dstintf "wan1" "wan2"
        set action accept
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
    edit 2
        set gateway 203.0.113.2
        set device "wan2"
    next
    edit 3
        set dst 10.10.10.0 255.255.255.0
        set gateway 192.168.1.254
        set device "hwsw1"
    next
end
config firewall vip
    edit "VIP-WEB"
        set extip 203.0.113.10
        set extintf "wan1"
        set mappedip "10.0.100.5"
    next
end
config vpn ipsec phase1-interface
    edit "branch-tunnel"
        set interface "wan1"
        set remote-gw 198.51.100.1
    next
end
`

const testConfigSDWAN = `#config-version=FGT90G-7.6.7-FW-build3704-260601:opmode=0:vdom=0:user=admin
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set gateway 203.0.113.1
        next
        edit 2
            set interface "wan2"
            set gateway 203.0.113.2
        next
    end
    config health-check
        edit "ping-ISP"
            set server "8.8.8.8"
        next
    end
end
`

const testConfigOldVersion = `#config-version=FGT60E-7.0.5-FW-build0304-201123:opmode=0:vdom=0:user=admin
config system interface
    edit "wan1"
    next
end
`

func TestParseFortiOSVersion(t *testing.T) {
	v, ok := ParseFortiOSVersion(testConfig)
	if !ok {
		t.Fatal("version header not found")
	}
	if v.Major != 7 || v.Minor != 6 || v.Patch != 7 {
		t.Errorf("version = %+v, want 7.6.7", v)
	}
	if !v.SupportsSDWANSyntax() {
		t.Error("7.6.7 must support the modern sdwan syntax")
	}
	if got, want := v.String(), "7.6.7"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	old, ok := ParseFortiOSVersion(testConfigOldVersion)
	if !ok {
		t.Fatal("old version header not found")
	}
	if old.SupportsSDWANSyntax() {
		t.Error("7.0.5 must NOT support the modern sdwan syntax")
	}

	// Some devices mask/omit the real version string (a 7.4.x box can report
	// "7.00"); the build number is the reliable signal. Build 2902 is 7.4.12,
	// which is >= the 7.4.0 GA build (2360), so it must count as 7.4+.
	masked, ok := ParseFortiOSVersion("#config-version=FG100F-7.00-FW-build2902-000000:opmode=0:vdom=0:user=admin\n")
	if !ok {
		t.Fatal("masked version header not found")
	}
	if masked.Build != 2902 {
		t.Errorf("build = %d, want 2902", masked.Build)
	}
	if !masked.SupportsSDWANSyntax() {
		t.Error("build 2902 (7.4.12) must be treated as 7.4+ despite the masked '7.00' version string")
	}
	if got, want := masked.String(), "build 2902"; got != want {
		t.Errorf("String() = %q, want %q (unparseable version falls back to build)", got, want)
	}

	// A genuine pre-7.4 build (7.0.5, build 0304) must still be gated out.
	if ok := (FortiOSVersion{Major: 7, Minor: 0, Patch: 5, Build: 304}).SupportsSDWANSyntax(); ok {
		t.Error("7.0.5 / build 304 must NOT support the modern sdwan syntax")
	}
}

func TestParseConfigInterfaces(t *testing.T) {
	cfg := ParseConfig(testConfig)

	port3, ok := cfg.Interfaces["port3"]
	if !ok {
		t.Fatal("port3 not parsed")
	}
	if port3.Allowaccess != "ping" {
		t.Errorf("port3 allowaccess = %q", port3.Allowaccess)
	}

	hwsw, ok := cfg.Interfaces["hwsw1"]
	if !ok {
		t.Fatal("hwsw1 not parsed")
	}
	if hwsw.Type != "hard-switch" {
		t.Errorf("hwsw1 type = %q", hwsw.Type)
	}
	if len(hwsw.Members) != 2 || hwsw.Members[0] != "port5" || hwsw.Members[1] != "port6" {
		t.Errorf("hwsw1 members = %v", hwsw.Members)
	}

	vl100, ok := cfg.Interfaces["VL100"]
	if !ok {
		t.Fatal("VL100 not parsed")
	}
	if vl100.Parent != "fortilink1" || vl100.VLANID != 100 {
		t.Errorf("VL100 parent/vlanid = %q/%d", vl100.Parent, vl100.VLANID)
	}
	// FortiGate omits `set type vlan`; the parser must infer it from the tag so
	// VLAN detection and the bulk FortiLink move find it.
	if vl100.Type != "vlan" {
		t.Errorf("VL100 type should be inferred as vlan, got %q", vl100.Type)
	}
	if vl100.IP != "10.0.100.1 255.255.255.0" {
		t.Errorf("VL100 ip = %q", vl100.IP)
	}
	if vl100.Role != "lan" {
		t.Errorf("VL100 role = %q", vl100.Role)
	}

	if len(cfg.Interfaces) != 7 {
		t.Errorf("interface count = %d, want 7", len(cfg.Interfaces))
	}
}

func TestParseConfigZones(t *testing.T) {
	cfg := ParseConfig(testConfig)
	z, ok := cfg.Zones["zone-dmz"]
	if !ok {
		t.Fatal("zone-dmz not parsed")
	}
	if len(z.Interfaces) != 2 || z.Interfaces[0] != "port3" || z.Interfaces[1] != "port4" {
		t.Errorf("zone-dmz interfaces = %v", z.Interfaces)
	}
	if z.IntrazoneDeny {
		t.Error("zone-dmz intrazone-deny should be false (disable)")
	}
}

func TestParseConfigPolicies(t *testing.T) {
	cfg := ParseConfig(testConfig)
	if len(cfg.Policies) != 2 {
		t.Fatalf("policy count = %d, want 2", len(cfg.Policies))
	}
	p5 := cfg.Policies[0]
	if p5.ID != 5 {
		t.Errorf("policy[0].ID = %d, want 5", p5.ID)
	}
	if len(p5.SrcIntf) != 2 || p5.SrcIntf[0] != "port3" || p5.SrcIntf[1] != "port4" {
		t.Errorf("policy 5 srcintf = %v", p5.SrcIntf)
	}
	if len(p5.DstIntf) != 1 || p5.DstIntf[0] != "wan1" {
		t.Errorf("policy 5 dstintf = %v", p5.DstIntf)
	}

	p6 := cfg.Policies[1]
	if len(p6.DstIntf) != 2 || p6.DstIntf[0] != "wan1" || p6.DstIntf[1] != "wan2" {
		t.Errorf("policy 6 dstintf = %v", p6.DstIntf)
	}
}

func TestParseConfigStaticRoutes(t *testing.T) {
	cfg := ParseConfig(testConfig)
	if len(cfg.StaticRoutes) != 3 {
		t.Fatalf("route count = %d, want 3", len(cfg.StaticRoutes))
	}
	r1 := cfg.StaticRoutes[0]
	if r1.Device != "wan1" || r1.Gateway != "203.0.113.1" {
		t.Errorf("route 1 = %+v", r1)
	}
	if r1.Dst != "" {
		t.Errorf("route 1 dst should be empty (default route), got %q", r1.Dst)
	}
	r3 := cfg.StaticRoutes[2]
	if r3.Dst != "10.10.10.0 255.255.255.0" || r3.Device != "hwsw1" {
		t.Errorf("route 3 = %+v", r3)
	}
}

func TestParseConfigSDWAN(t *testing.T) {
	cfg := ParseConfig(testConfigSDWAN)
	if len(cfg.SDWANMembers) != 2 {
		t.Fatalf("sdwan member count = %d, want 2", len(cfg.SDWANMembers))
	}
	m1 := cfg.SDWANMembers[0]
	if m1.Seq != 1 || m1.Interface != "wan1" || m1.Gateway != "203.0.113.1" {
		t.Errorf("member 1 = %+v", m1)
	}
	if _, ok := cfg.SDWANZones["virtual-wan-link"]; !ok {
		t.Error("virtual-wan-link zone not parsed")
	}
	if len(cfg.SDWANHealthChecks) != 1 || cfg.SDWANHealthChecks[0] != "ping-ISP" {
		t.Errorf("sdwan health checks = %v, want [ping-ISP]", cfg.SDWANHealthChecks)
	}

	// A plain `config system zone` (top-level) must never be confused with
	// sdwan's nested `config zone` -- confirm the DMZ zone from testConfig
	// does not leak into SDWANZones and vice versa.
	main := ParseConfig(testConfig)
	if len(main.SDWANZones) != 0 {
		t.Errorf("testConfig has no sdwan section, want 0 SDWANZones, got %v", main.SDWANZones)
	}
	if _, ok := cfg.Zones["virtual-wan-link"]; ok {
		t.Error("sdwan zone must not leak into the plain Zones map")
	}
}

func TestScanReferences(t *testing.T) {
	cfg := ParseConfig(testConfig)

	hits := ScanReferences(cfg, "wan1")
	if len(hits) != 2 {
		t.Fatalf("wan1 reference hits = %d, want 2 (vip + ipsec phase1)", len(hits))
	}
	var sections []string
	for _, h := range hits {
		sections = append(sections, h.Section)
	}
	wantSections := map[string]bool{"firewall vip": true, "vpn ipsec phase1-interface": true}
	for _, s := range sections {
		if !wantSections[s] {
			t.Errorf("unexpected section in hits: %q", s)
		}
	}

	// wan10 must never be treated as a hit for wan1 (whole-token match only).
	hits10 := ScanReferences(cfg, "wan10")
	if len(hits10) != 0 {
		t.Errorf("wan10 must have 0 reference hits (no substring false-positive on wan1's hits), got %v", hits10)
	}

	// An interface with no watched-section references gets no hits, not an error.
	if hits := ScanReferences(cfg, "port3"); len(hits) != 0 {
		t.Errorf("port3 should have 0 reference hits, got %v", hits)
	}
}

func TestFGConfigClone(t *testing.T) {
	cfg := ParseConfig(testConfig)
	clone := cfg.Clone()

	clone.Interfaces["port3"].Allowaccess = "mutated"
	clone.Policies[0].SrcIntf[0] = "mutated"
	clone.StaticRoutes[0].Device = "mutated"

	if cfg.Interfaces["port3"].Allowaccess == "mutated" {
		t.Error("mutating the clone's interface must not affect the original")
	}
	if cfg.Policies[0].SrcIntf[0] == "mutated" {
		t.Error("mutating the clone's policy slice must not affect the original")
	}
	if cfg.StaticRoutes[0].Device == "mutated" {
		t.Error("mutating the clone's route must not affect the original")
	}
}
