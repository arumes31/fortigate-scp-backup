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
        set sn "S524DN0000000001"
        set fsw-wan1-peer "FortiLink"
        config ports
            edit "port1"
                set vlan "VL100"
                set mac-addr e0:23:ff:00:00:01
            next
            edit "port29"
                set vlan "_default"
                set lldp-profile "default-auto-mclag-icl"
                set mac-addr e0:23:ff:00:00:02
            next
            edit "port30"
                set vlan "_default"
                set lldp-profile "default-auto-mclag-icl"
                set mac-addr e0:23:ff:00:00:03
            next
        end
        config igmp-snooping
            set local-override enable
        end
    next
    edit "SW-CORE02"
        set sn "S524DN0000000002"
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
config system zone
    edit "VPN_Kunden"
        set interface "B_Branch1" "B_Branch2"
    next
end
config system dhcp server
    edit 2
        set default-gateway 192.168.100.1
        set netmask 255.255.255.0
        set interface "VL100"
        config ip-range
            edit 1
                set start-ip 192.168.100.101
                set end-ip 192.168.100.199
            next
        end
    next
end
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
    end
    config health-check
        edit "Cloudflare"
            set server "1.1.1.1"
            set members 1
        next
    end
end
config vpn ipsec phase1-interface
    edit "B_Branch1"
        set interface "wan1"
        set ike-version 2
        set remote-gw 198.51.100.7
    next
end
config system ha
    set group-name "ha-grp"
    set mode a-p
    set hbdev "port5" 100 "port6" 50
    set monitor "wan1"
end
config wireless-controller vap
    edit "corp_wifi"
        set ssid "Corp WiFi"
        set security wpa3-only-enterprise
        set vlanid 101
    next
end
config wireless-controller wtp-profile
    edit "FAP231F-default"
        config platform
            set type 231F
        end
        config radio-1
            set vaps "corp_wifi"
        end
    next
end
config wireless-controller wtp
    edit "FP231FTF00000001"
        set name "AP Office"
        set wtp-profile "FAP231F-default"
    next
end
`

func TestParseConfigDataNestedBlocks(t *testing.T) {
	pc := parseConfigData(parseCfg(nestedConfig))
	ifaces, switches, groups := pc.Interfaces, pc.Switches, pc.SwitchGroups

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
	if core1.SwitchID != "SW-CORE01" || core1.Serial != "S524DN0000000001" || core1.Model != "FS-524D" ||
		core1.Fortilink != "FortiLink" || len(core1.Ports) != 3 {
		t.Fatalf("SW-CORE01 parse wrong: %+v", core1)
	}
	if p := core1.Ports[1]; p.Name != "port29" || p.LldpProfile != "default-auto-mclag-icl" || p.Mac != "e0:23:ff:00:00:02" {
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

// TestParseConfigDataSections covers the zone / DHCP / SD-WAN / VPN / HA /
// wireless extraction from the shared fixture.
func TestParseConfigDataSections(t *testing.T) {
	pc := parseConfigData(parseCfg(nestedConfig))

	if len(pc.Zones) != 1 || pc.Zones[0].Name != "VPN_Kunden" || len(pc.Zones[0].Interfaces) != 2 {
		t.Fatalf("zones wrong: %+v", pc.Zones)
	}
	if len(pc.DhcpServers) != 1 {
		t.Fatalf("dhcp wrong: %+v", pc.DhcpServers)
	}
	dh := pc.DhcpServers[0]
	if dh.Interface != "VL100" || dh.Gateway != "192.168.100.1" ||
		len(dh.Ranges) != 1 || dh.Ranges[0] != "192.168.100.101 – 192.168.100.199" {
		t.Fatalf("dhcp fields wrong: %+v", dh)
	}
	if pc.Sdwan == nil || pc.Sdwan.Status != "enable" || len(pc.Sdwan.Members) != 1 ||
		pc.Sdwan.Members[0].Interface != "wan1" || pc.Sdwan.Members[0].Gateway != "203.0.113.1" {
		t.Fatalf("sdwan wrong: %+v", pc.Sdwan)
	}
	if len(pc.Sdwan.HealthChecks) != 1 || pc.Sdwan.HealthChecks[0].Name != "Cloudflare" ||
		len(pc.Sdwan.HealthChecks[0].Members) != 1 || pc.Sdwan.HealthChecks[0].Members[0] != "1" {
		t.Fatalf("sdwan health checks wrong: %+v", pc.Sdwan.HealthChecks)
	}
	if len(pc.Vpns) != 1 || pc.Vpns[0].Name != "B_Branch1" || pc.Vpns[0].RemoteGw != "198.51.100.7" ||
		pc.Vpns[0].Interface != "wan1" || pc.Vpns[0].IkeVersion != "2" {
		t.Fatalf("vpns wrong: %+v", pc.Vpns)
	}
	if pc.HA == nil || pc.HA.Mode != "a-p" || pc.HA.GroupName != "ha-grp" ||
		len(pc.HA.Hbdev) != 2 || pc.HA.Hbdev[1] != "port6" ||
		len(pc.HA.Monitor) != 1 || pc.HA.Monitor[0] != "wan1" {
		t.Fatalf("ha wrong: %+v", pc.HA)
	}
	if len(pc.SSIDs) != 1 || pc.SSIDs[0].SSID != "Corp WiFi" || pc.SSIDs[0].VlanID != 101 ||
		pc.SSIDs[0].Security != "wpa3-only-enterprise" {
		t.Fatalf("ssids wrong: %+v", pc.SSIDs)
	}
	if len(pc.APs) != 1 {
		t.Fatalf("aps wrong: %+v", pc.APs)
	}
	ap := pc.APs[0]
	if ap.Name != "AP Office" || ap.Platform != "231F" || len(ap.SSIDs) != 1 || ap.SSIDs[0] != "corp_wifi" {
		t.Fatalf("ap fields wrong: %+v", ap)
	}
}

func TestBuildSwitchLinks(t *testing.T) {
	links := buildSwitchLinks(parseConfigData(parseCfg(nestedConfig)).Switches, nil, nil)
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
	links := buildSwitchLinks(switches, nil, nil)
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
	links := buildSwitchLinks(switches, nil, nil)
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

// TestBuildSwitchLinksIslCustom: `config switch-controller auto-config custom`
// records auto-ISL trunks named after the PEER's serial fragment, bound to the
// owning switch — must yield an isl link owner→peer (serial suffix match).
func TestBuildSwitchLinksIslCustom(t *testing.T) {
	cfg := `config switch-controller managed-switch
    edit "S424EP0000000004"
        set name "SW-ACCESS04"
    next
    edit "S108EN0000000003"
        set name "SW-EDGE03"
    next
end
config switch-controller auto-config custom
    edit "8EN0000000003-0"
        config switch-binding
            edit "SW-ACCESS04"
                set policy "pse"
            next
        end
    next
end
`
	pc := parseConfigData(parseCfg(cfg))
	if len(pc.IslCustom) != 1 || pc.IslCustom[0].Trunk != "8EN0000000003-0" || pc.IslCustom[0].Switch != "SW-ACCESS04" {
		t.Fatalf("isl custom parse wrong: %+v", pc.IslCustom)
	}
	links := buildSwitchLinks(pc.Switches, pc.SwitchGroups, pc.IslCustom)
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1 (%+v)", len(links), links)
	}
	l := links[0]
	if l.Kind != "isl" || l.From != "SW-ACCESS04" || l.To != "SW-EDGE03" ||
		len(l.FromPorts) != 1 || l.FromPorts[0] != "8EN0000000003-0" {
		t.Fatalf("isl custom link wrong: %+v", l)
	}
}

// TestBuildSwitchLinksTwoMclagPairs: four ICL switches (two MC-LAG pairs) must
// pair within their switch-groups — the old global "exactly two" rule yielded
// zero links for such fabrics.
func TestBuildSwitchLinksTwoMclagPairs(t *testing.T) {
	icl := func(id string) FortiSwitch {
		return FortiSwitch{SwitchID: id, Ports: []SwitchPort{{Name: "port29", LldpProfile: "default-auto-mclag-icl"}}}
	}
	switches := []FortiSwitch{icl("CORE01"), icl("CORE02"), icl("DIST01"), icl("DIST02")}
	groups := []SwitchGroup{
		{Name: "core", Members: []string{"CORE01", "CORE02"}},
		{Name: "dist", Members: []string{"DIST01", "DIST02"}},
		{Name: "edge", Members: []string{"EDGE01"}}, // no ICL sides: ignored
	}
	links := buildSwitchLinks(switches, groups, nil)
	if len(links) != 2 {
		t.Fatalf("links = %d, want 2 (%+v)", len(links), links)
	}
	pairs := map[string]bool{}
	for _, l := range links {
		if l.Kind != "mclag-icl" {
			t.Fatalf("kind = %q, want mclag-icl", l.Kind)
		}
		pairs[l.From+"-"+l.To] = true
	}
	if !pairs["CORE01-CORE02"] || !pairs["DIST01-DIST02"] {
		t.Fatalf("wrong pairing: %+v", pairs)
	}
	// Without groups, >2 ICL sides stay unpaired (no reliable signal).
	if got := buildSwitchLinks(switches, nil, nil); len(got) != 0 {
		t.Fatalf("ungrouped >2 sides must yield no links, got %+v", got)
	}
}

// TestParseConfigDataExample2 exercises the parser against the full real-world
// fixture (skipped when the file is absent, e.g. in stripped-down checkouts).
func TestParseConfigDataExample2(t *testing.T) {
	b, err := os.ReadFile("../../example2.conf")
	if err != nil {
		t.Skip("example2.conf not found")
	}
	pc := parseConfigData(parseCfg(string(b)))
	ifaces, routes, pols, switches, groups := pc.Interfaces, pc.Routes, pc.Policies, pc.Switches, pc.SwitchGroups

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

	// New sections (zones, DHCP, SD-WAN, VPN, HA, wireless).
	if len(pc.Zones) != 1 || pc.Zones[0].Name != "VPN_Kunden" || len(pc.Zones[0].Interfaces) < 40 {
		t.Fatalf("zones wrong: %+v", pc.Zones)
	}
	if len(pc.DhcpServers) == 0 || pc.DhcpServers[0].Interface == "" || len(pc.DhcpServers[0].Ranges) == 0 {
		t.Fatalf("dhcp servers wrong: %+v", pc.DhcpServers)
	}
	if pc.Sdwan == nil || len(pc.Sdwan.Members) != 4 || len(pc.Sdwan.Zones) != 2 || len(pc.Sdwan.HealthChecks) < 3 {
		t.Fatalf("sdwan wrong: %+v", pc.Sdwan)
	}
	if len(pc.Vpns) < 10 {
		t.Fatalf("vpns = %d, want >= 10", len(pc.Vpns))
	}
	if pc.HA == nil || pc.HA.Mode != "a-p" || pc.HA.GroupName == "" ||
		len(pc.HA.Hbdev) != 2 || pc.HA.Hbdev[0] != "port5" {
		t.Fatalf("ha wrong: %+v", pc.HA)
	}
	if len(pc.APs) != 5 || len(pc.SSIDs) < 3 {
		t.Fatalf("wireless wrong: %d APs / %d SSIDs", len(pc.APs), len(pc.SSIDs))
	}
	for _, ap := range pc.APs {
		if ap.Name == "" || ap.Platform == "" || len(ap.SSIDs) == 0 {
			t.Fatalf("AP incomplete: %+v", ap)
		}
	}
	// 802.1X policy on access ports parsed.
	dot1x := false
	for _, sw := range switches {
		for _, p := range sw.Ports {
			if p.SecurityPolicy != "" {
				dot1x = true
			}
		}
	}
	if !dot1x {
		t.Fatal("no port-security-policy parsed")
	}

	links := buildSwitchLinks(switches, nil, nil)
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1 MC-LAG ICL (%+v)", len(links), links)
	}
	// Real-fixture assertions stay name-agnostic: no customer identifiers in
	// the repo. The ICL must join two distinct parsed switches.
	icl := links[0]
	if icl.Kind != "mclag-icl" || icl.From == "" || icl.To == "" || icl.From == icl.To {
		t.Fatalf("ICL link wrong: %+v", icl)
	}
	if len(icl.FromPorts) != 2 || icl.FromPorts[0] != "port29" || icl.FromPorts[1] != "port30" ||
		len(icl.ToPorts) != 2 || icl.ToPorts[0] != "port29" || icl.ToPorts[1] != "port30" {
		t.Fatalf("ICL ports wrong: %+v", icl)
	}
}
