package web

import (
	"os"
	"testing"
)

// nestedConfig reproduces the structures that broke the old line-based
// parser: `config ipv6` inside an interface, `config igmp-snooping` inside a
// switch, and multiple switches after such nested blocks.
const nestedConfig = `config system interface
    edit "FortiLink"
        set ip 10.99.254.1 255.255.255.0
        set allowaccess ping fabric
        set type aggregate
        set member "a" "b"
        config ipv6
            set ip6-send-adv enable
        end
    next
    edit "VL100"
        set ip 192.168.100.1 255.255.255.0
        set interface "FortiLink"
        set vlanid 100
        set alias "servers"
        set role lan
    next
end
config switch-controller managed-switch
    edit "SW-CORE01"
        set sn "S524DN5020000043"
        set fsw-wan1-peer "FortiLink"
        config ports
            edit "port1"
                set vlan "VL100"
                set mac-addr e0:23:ff:52:47:98
            next
            edit "port29"
                set vlan "_default"
                set lldp-profile "default-auto-mclag-icl"
                set mac-addr e0:23:ff:52:47:b4
            next
            edit "port30"
                set vlan "_default"
                set lldp-profile "default-auto-mclag-icl"
                set mac-addr e0:23:ff:52:47:b5
            next
        end
        config igmp-snooping
            set local-override enable
        end
    next
    edit "SW-CORE02"
        set sn "S524DN5020000027"
        set fsw-wan1-peer "FortiLink"
        config ports
            edit "port29"
                set lldp-profile "default-auto-mclag-icl"
            next
            edit "port30"
                set lldp-profile "default-auto-mclag-icl"
            next
        end
        config igmp-snooping
            set local-override enable
        end
    next
    edit "SW-ACCESS01"
        set sn "S448EN0000000001"
        set description "rack 3"
        config ports
            edit "port49"
                set vlan "VL110"
                set allowed-vlans "VL051" "VL090" "VL100"
            next
            edit "port50"
                set vlan "_default"
                set allowed-vlans-all enable
                set speed auto-module
            next
            edit "SW-ACCESS01-0"
                set type trunk
                set members "port50"
                set isl-peer-device-name "SW-CORE01"
                set isl-peer-port-name "port1"
            next
        end
    next
end
config switch-controller switch-group
    edit "GRP-CORE"
        set fortilink "FortiLink"
        set members "SW-CORE01" "SW-CORE02"
    next
end
`

func TestParseConfigDataNestedBlocks(t *testing.T) {
	ifaces, _, _, switches, groups := parseConfigData(parseCfg(nestedConfig))

	// The VLAN interface after the nested `config ipv6` block must survive.
	if len(ifaces) != 2 {
		t.Fatalf("interfaces = %d, want 2 (%+v)", len(ifaces), ifaces)
	}
	fl := ifaces[0]
	if fl.Name != "FortiLink" || len(fl.Members) != 2 || fl.Members[0] != "a" {
		t.Fatalf("FortiLink parse wrong: %+v", fl)
	}
	vl := ifaces[1]
	if vl.Name != "VL100" || vl.VlanID != 100 || vl.Interface != "FortiLink" || vl.Alias != "servers" {
		t.Fatalf("VL100 parse wrong: %+v", vl)
	}

	// Switches after `config igmp-snooping` blocks must survive.
	if len(switches) != 3 {
		t.Fatalf("switches = %d, want 3 (%+v)", len(switches), switches)
	}
	core1 := switches[0]
	if core1.SwitchID != "SW-CORE01" || core1.Serial != "S524DN5020000043" || core1.Model != "FS-524D" ||
		core1.Fortilink != "FortiLink" || len(core1.Ports) != 3 {
		t.Fatalf("SW-CORE01 parse wrong: %+v", core1)
	}
	if p := core1.Ports[1]; p.Name != "port29" || p.LldpProfile != "default-auto-mclag-icl" || p.Mac != "e0:23:ff:52:47:b4" {
		t.Fatalf("port29 parse wrong: %+v", p)
	}
	acc := switches[2]
	if acc.Description != "rack 3" || len(acc.Ports) != 3 {
		t.Fatalf("SW-ACCESS01 parse wrong: %+v", acc)
	}
	if p := acc.Ports[0]; p.Name != "port49" || len(p.AllowedVlans) != 3 || p.AllowedVlans[0] != "VL051" || p.AllowedVlansAll {
		t.Fatalf("port49 tagged VLANs wrong: %+v", p)
	}
	if p := acc.Ports[1]; p.Name != "port50" || !p.AllowedVlansAll || len(p.AllowedVlans) != 0 {
		t.Fatalf("port50 allowed-vlans-all wrong: %+v", p)
	}
	trunk := acc.Ports[2]
	if trunk.Type != "trunk" || trunk.IslPeerDevice != "SW-CORE01" || trunk.IslPeerPort != "port1" ||
		len(trunk.Members) != 1 || trunk.Members[0] != "port50" {
		t.Fatalf("trunk parse wrong: %+v", trunk)
	}

	if len(groups) != 1 || groups[0].Name != "GRP-CORE" || len(groups[0].Members) != 2 {
		t.Fatalf("groups parse wrong: %+v", groups)
	}
}

func TestBuildSwitchLinks(t *testing.T) {
	_, _, _, switches, _ := parseConfigData(parseCfg(nestedConfig))
	links := buildSwitchLinks(switches)
	if len(links) != 2 {
		t.Fatalf("links = %d, want 2 (%+v)", len(links), links)
	}
	byKind := map[string]SwitchLink{}
	for _, l := range links {
		byKind[l.Kind] = l
	}
	isl, ok := byKind["isl"]
	if !ok || isl.From != "SW-ACCESS01" || isl.To != "SW-CORE01" ||
		len(isl.FromPorts) != 1 || isl.FromPorts[0] != "port50" ||
		len(isl.ToPorts) != 1 || isl.ToPorts[0] != "port1" {
		t.Fatalf("isl link wrong: %+v", isl)
	}
	icl, ok := byKind["mclag-icl"]
	if !ok || icl.From != "SW-CORE01" || icl.To != "SW-CORE02" ||
		len(icl.FromPorts) != 2 || len(icl.ToPorts) != 2 {
		t.Fatalf("icl link wrong: %+v", icl)
	}
}

// TestBuildSwitchLinksDedup: both sides persisting the same trunk must yield
// one link.
func TestBuildSwitchLinksDedup(t *testing.T) {
	switches := []FortiSwitch{
		{SwitchID: "A", Ports: []SwitchPort{{Name: "A-0", Type: "trunk", Members: []string{"port1"}, IslPeerDevice: "B", IslPeerPort: "port2"}}},
		{SwitchID: "B", Ports: []SwitchPort{{Name: "B-0", Type: "trunk", Members: []string{"port2"}, IslPeerDevice: "A", IslPeerPort: "port1"}}},
	}
	links := buildSwitchLinks(switches)
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1 (%+v)", len(links), links)
	}
}

// TestSplitCfgValues: quoted values with spaces must stay single tokens
// (address/service/member names regularly contain spaces).
func TestSplitCfgValues(t *testing.T) {
	got := splitCfgValues(`"Internal Net" "all" plain 'single quoted' "esc\"aped"`)
	want := []string{"Internal Net", "all", "plain", "single quoted", `esc"aped`}
	if len(got) != len(want) {
		t.Fatalf("splitCfgValues = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCfgValues[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestBuildSwitchLinksTrunkIcl: an MC-LAG ICL persisted only as a trunk with
// `set mclag-icl enable` (no isl-peer data) must still pair the switches,
// with the trunk members as the link ports.
func TestBuildSwitchLinksTrunkIcl(t *testing.T) {
	switches := []FortiSwitch{
		{SwitchID: "A", Ports: []SwitchPort{
			{Name: "port27", LldpProfile: "default-auto-mclag-icl"},
			{Name: "A-ICL", Type: "trunk", MclagIcl: true, Members: []string{"port27", "port28"}},
		}},
		{SwitchID: "B", Ports: []SwitchPort{
			{Name: "B-ICL", Type: "trunk", MclagIcl: true, Members: []string{"port27", "port28"}},
		}},
	}
	links := buildSwitchLinks(switches)
	if len(links) != 1 || links[0].Kind != "mclag-icl" {
		t.Fatalf("links = %+v, want one mclag-icl link", links)
	}
	// port27 appears via its LLDP profile AND as trunk member: deduplicated.
	if len(links[0].FromPorts) != 2 || links[0].FromPorts[0] != "port27" || links[0].FromPorts[1] != "port28" {
		t.Fatalf("FromPorts = %v, want [port27 port28]", links[0].FromPorts)
	}
	if len(links[0].ToPorts) != 2 {
		t.Fatalf("ToPorts = %v, want [port27 port28]", links[0].ToPorts)
	}
}

// TestParseConfigDataExample2 exercises the parser against the full real-world
// fixture (skipped when the file is absent, e.g. in stripped-down checkouts).
func TestParseConfigDataExample2(t *testing.T) {
	b, err := os.ReadFile("../../example2.conf")
	if err != nil {
		t.Skip("example2.conf not found")
	}
	ifaces, routes, pols, switches, groups := parseConfigData(parseCfg(string(b)))

	if len(ifaces) < 100 {
		t.Fatalf("interfaces = %d, want >= 100 (nested-block truncation regressed?)", len(ifaces))
	}
	if len(routes) == 0 || len(pols) == 0 {
		t.Fatalf("routes/policies empty: %d/%d", len(routes), len(pols))
	}
	if len(switches) != 12 {
		t.Fatalf("switches = %d, want 12", len(switches))
	}
	if len(groups) != 5 {
		t.Fatalf("switch groups = %d, want 5", len(groups))
	}
	for _, sw := range switches {
		if len(sw.Ports) == 0 {
			t.Fatalf("switch %s has no ports", sw.SwitchID)
		}
		if sw.Model == "" {
			t.Fatalf("switch %s has no derived model (serial %q)", sw.SwitchID, sw.Serial)
		}
	}

	links := buildSwitchLinks(switches)
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1 MC-LAG ICL (%+v)", len(links), links)
	}
	icl := links[0]
	if icl.Kind != "mclag-icl" || icl.From != "SW-CORE01" || icl.To != "SW-CORE02" {
		t.Fatalf("ICL link wrong: %+v", icl)
	}
	if len(icl.FromPorts) != 2 || icl.FromPorts[0] != "port29" || icl.FromPorts[1] != "port30" ||
		len(icl.ToPorts) != 2 || icl.ToPorts[0] != "port29" || icl.ToPorts[1] != "port30" {
		t.Fatalf("ICL ports wrong: %+v", icl)
	}
}
