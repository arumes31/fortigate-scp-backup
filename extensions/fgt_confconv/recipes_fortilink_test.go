package fgt_confconv

import (
	"encoding/json"
	"strings"
	"testing"
)

func freshFortiLinkConfig() *FGConfig {
	return &FGConfig{
		Interfaces: map[string]*InterfaceEntry{
			"port5": {Name: "port5", IP: "0.0.0.0 0.0.0.0"},
			"port6": {Name: "port6", IP: "0.0.0.0 0.0.0.0"},
			"hwsw1": {Name: "hwsw1", Type: "hard-switch", Members: []string{"port5", "port7"}},
			"lan1":  {Name: "lan1", IP: "10.10.10.1 255.255.255.0", Allowaccess: "ping https", Role: "lan"},
			"wan1":  {Name: "wan1", IP: "203.0.113.1 255.255.255.0", Role: "wan"},
		},
		Zones:      map[string]*ZoneEntry{},
		SDWANZones: map[string]*SDWANZone{},
		Policies: []*PolicyEntry{
			{ID: 1, SrcIntf: []string{"lan1"}, DstIntf: []string{"wan1"}},
		},
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal opts: %v", err)
	}
	return b
}

func TestFortiLinkRecipe_HappyPath(t *testing.T) {
	cfg := freshFortiLinkConfig()
	r := fortiLinkRecipe{}

	cli, warnings, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"port5", "port6"},
		FortilinkName: "fortilink1",
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// Creating a FortiLink always emits the switch-authorization guidance note.
	if len(warnings) != 1 || !strings.Contains(warnings[0].Detail, "managed-switch") {
		t.Errorf("expected the FortiLink authorization guidance warning, got %v", warnings)
	}

	fl, ok := cfg.Interfaces["fortilink1"]
	if !ok {
		t.Fatal("fortilink1 was not created")
	}
	if fl.Type != "aggregate" || !fl.Fortilink {
		t.Errorf("fortilink1 = %+v", fl)
	}
	if len(fl.Members) != 2 || fl.Members[0] != "port5" || fl.Members[1] != "port6" {
		t.Errorf("fortilink1 members = %v", fl.Members)
	}

	// port5 must have been pulled out of hwsw1's member list.
	if containsStr(cfg.Interfaces["hwsw1"].Members, "port5") {
		t.Error("port5 should have been removed from hwsw1's members")
	}
	if !containsStr(cfg.Interfaces["hwsw1"].Members, "port7") {
		t.Error("port7 should remain a member of hwsw1")
	}

	joined := blockLines(cli)
	for _, want := range []string{
		`edit "fortilink1"`, "set type aggregate", `set member "port5" "port6"`, "set fortilink enable",
		// A usable FortiLink needs fabric access, LLDP discovery and (single
		// switch) split-interface off -- not just the bare aggregate.
		"set fortilink-split-interface disable", "set allowaccess ping fabric",
		"set lldp-reception enable", "set lldp-transmission enable",
		`edit "hwsw1"`, `set member "port7"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cli missing %q:\n%s", want, joined)
		}
	}
}

func TestFortiLinkRecipe_ManagementIPAndMCLAG(t *testing.T) {
	cfg := freshFortiLinkConfig()
	r := fortiLinkRecipe{}
	cli, _, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"port5", "port6"},
		FortilinkName: "fortilink1",
		FortilinkIP:   "10.255.1.1 255.255.255.0",
		DualHomed:     true,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	joined := blockLines(cli)
	for _, want := range []string{
		"set ip 10.255.1.1 255.255.255.0",
		"set fortilink-split-interface enable", // dual-homed => split on
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cli missing %q:\n%s", want, joined)
		}
	}
}

func TestFortiLinkRecipe_VLANMove(t *testing.T) {
	cfg := freshFortiLinkConfig()
	r := fortiLinkRecipe{}

	_, _, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"port5", "port6"},
		FortilinkName: "fortilink1",
		VLANMoves:     []VLANMove{{Interface: "lan1", VLANID: 100}},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	lan1 := cfg.Interfaces["lan1"]
	if lan1.Type != "vlan" || lan1.Parent != "fortilink1" || lan1.VLANID != 100 {
		t.Errorf("lan1 after move = %+v", lan1)
	}
	if lan1.IP != "10.10.10.1 255.255.255.0" {
		t.Errorf("lan1 IP should be preserved, got %q", lan1.IP)
	}

	// The policy referencing "lan1" must NOT need rewriting -- the name was
	// preserved across the move.
	if cfg.Policies[0].SrcIntf[0] != "lan1" {
		t.Errorf("policy srcintf should still read lan1, got %v", cfg.Policies[0].SrcIntf)
	}
}

func TestFortiLinkRecipe_RejectsLiveMemberPort(t *testing.T) {
	cfg := freshFortiLinkConfig()
	r := fortiLinkRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"lan1", "port6"},
		FortilinkName: "fortilink1",
	}))
	if err == nil {
		t.Fatal("expected an error for a member port with a live IP")
	}
	if !strings.Contains(err.Error(), "lan1") {
		t.Errorf("error should name the offending port, got: %v", err)
	}
}

func TestFortiLinkRecipe_RejectsPolicyReferencedMemberPort(t *testing.T) {
	cfg := freshFortiLinkConfig()
	cfg.Interfaces["port5"].IP = "" // clear the IP so only the policy reference trips it
	cfg.Policies = append(cfg.Policies, &PolicyEntry{ID: 2, SrcIntf: []string{"port5"}})
	r := fortiLinkRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"port5", "port6"},
		FortilinkName: "fortilink1",
	}))
	if err == nil {
		t.Fatal("expected an error for a member port referenced by a policy")
	}
}

func TestFortiLinkRecipe_UseExistingRequiresFortilinkEnabled(t *testing.T) {
	cfg := freshFortiLinkConfig()
	cfg.Interfaces["fortilink1"] = &InterfaceEntry{Name: "fortilink1", Type: "aggregate"} // Fortilink: false
	r := fortiLinkRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"port5", "port6"},
		FortilinkName: "fortilink1",
		UseExisting:   true,
	}))
	if err == nil {
		t.Fatal("expected an error: fortilink1 exists but is not fortilink-enabled")
	}
}

func TestFortiLinkRecipe_WarnsOnUntouchedReferences(t *testing.T) {
	cfg := freshFortiLinkConfig()
	cfg.WatchedLines = []WatchedLine{
		{Section: "vpn ipsec phase1-interface", Edit: "branch", Line: `set interface "lan1"`},
	}
	r := fortiLinkRecipe{}
	_, warnings, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:   []string{"port5", "port6"},
		FortilinkName: "fortilink1",
		VLANMoves:     []VLANMove{{Interface: "lan1", VLANID: 100}},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var ipsec *Warning
	for i := range warnings {
		if warnings[i].Section == "vpn ipsec phase1-interface" {
			ipsec = &warnings[i]
		}
	}
	if ipsec == nil {
		t.Fatalf("expected an ipsec reference warning, got %v", warnings)
	}
	// The name is preserved across a VLAN move, so the reference stays valid --
	// the warning must read as informational, not as a required rewrite.
	if !strings.Contains(ipsec.Detail, "stays valid") {
		t.Errorf("VLAN-move reference warning should be informational, got: %q", ipsec.Detail)
	}
}

func TestFortiLinkRecipe_BulkVLANMove(t *testing.T) {
	cfg := &FGConfig{
		Interfaces: map[string]*InterfaceEntry{
			"x1":    {Name: "x1", IP: "0.0.0.0 0.0.0.0"},
			"x2":    {Name: "x2", IP: "0.0.0.0 0.0.0.0"},
			"agg1":  {Name: "agg1", Type: "aggregate", Members: []string{"x1", "x2"}},
			"VL10":  {Name: "VL10", Type: "vlan", Parent: "agg1", VLANID: 10, IP: "10.0.10.1 255.255.255.0"},
			"VL20":  {Name: "VL20", Type: "vlan", Parent: "agg1", VLANID: 20},
			"VL30":  {Name: "VL30", Type: "vlan", Parent: "agg1", VLANID: 30},
			"other": {Name: "other", Type: "vlan", Parent: "someport", VLANID: 99},
		},
		Zones:      map[string]*ZoneEntry{},
		SDWANZones: map[string]*SDWANZone{},
	}
	r := fortiLinkRecipe{}

	cli, _, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:     []string{"x1", "x2"},
		FortilinkName:   "fortilink1",
		BulkVLANParents: []string{"agg1"},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Every VLAN that sat on agg1 must be re-parented onto the FortiLink,
	// keeping its name and tag; a VLAN on a different parent stays put.
	for _, name := range []string{"VL10", "VL20", "VL30"} {
		v := cfg.Interfaces[name]
		if v.Type != "vlan" || v.Parent != "fortilink1" {
			t.Errorf("%s should have moved onto fortilink1, got %+v", name, v)
		}
	}
	if cfg.Interfaces["other"].Parent != "someport" {
		t.Errorf("a VLAN on a different parent must not move, got %+v", cfg.Interfaces["other"])
	}

	joined := blockLines(cli)
	for _, want := range []string{
		`edit "VL10"`, "set vlanid 10", `edit "VL20"`, "set vlanid 20", `edit "VL30"`, "set vlanid 30",
		`set interface "fortilink1"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cli missing %q:\n%s", want, joined)
		}
	}
}

func TestFortiLinkRecipe_BulkVLANMoveEmptyParentWarns(t *testing.T) {
	cfg := freshFortiLinkConfig() // lan1 carries no stacked VLANs
	r := fortiLinkRecipe{}
	_, warnings, err := r.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:     []string{"port5", "port6"},
		FortilinkName:   "fortilink1",
		BulkVLANParents: []string{"lan1"},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var sawEmpty bool
	for _, w := range warnings {
		if strings.Contains(w.Detail, "nothing to move") {
			sawEmpty = true
		}
	}
	if !sawEmpty {
		t.Errorf("expected a 'nothing to move' warning for a parent with no VLANs, got %v", warnings)
	}
}

func TestRecipeVersionGating(t *testing.T) {
	// FortiLink and zone recipes emit version-agnostic CLI and must run on
	// pre-7.4 trains; only the SD-WAN recipes need the 7.4+ `config system
	// sdwan` syntax.
	old := &FGConfig{Version: FortiOSVersion{Major: 7, Minor: 0}}
	if ok, reason := (fortiLinkRecipe{}).Applicable(old); !ok {
		t.Errorf("FortiLink recipe should be applicable on FortiOS 7.0, got %q", reason)
	}
	if ok, reason := (zoneRecipe{}).Applicable(old); !ok {
		t.Errorf("zone recipe should be applicable on FortiOS 7.0, got %q", reason)
	}
	if ok, reason := (sdwanRecipe{}).Applicable(old); ok || !strings.Contains(reason, "7.4+") {
		t.Errorf("SD-WAN recipe should be gated on 7.0, got ok=%v reason=%q", ok, reason)
	}
}

const fullSectionConfig = `#config-version=FGxx-7.4.1-FW-build2463-230101:opmode=0
config system interface
edit "port1"
set vdom "root"
set type physical
next
edit "port2"
set vdom "root"
set type physical
next
edit "wan1"
set vdom "root"
set ip 203.0.113.1 255.255.255.0
set type physical
set role wan
next
edit "agg1"
set vdom "root"
set type aggregate
set member "port1" "port2"
next
edit "VL10"
set vdom "root"
set ip 10.0.10.1 255.255.255.0
set allowaccess ping https
set snmp-index 5
set interface "agg1"
set vlanid 10
config secondaryip
edit 1
set ip 10.0.11.1 255.255.255.0
next
end
next
edit "VL20"
set vdom "root"
set ip 10.0.20.1 255.255.255.0
set interface "agg1"
set vlanid 20
next
end
`

func TestFortiLinkRecipe_FullSectionOutput(t *testing.T) {
	cfg := ParseConfig(fullSectionConfig)
	cli, _, err := fortiLinkRecipe{}.Run(cfg, mustJSON(t, FortiLinkOptions{
		MemberPorts:     []string{"port1", "port2"},
		FortilinkName:   "fortilink",
		BulkVLANParents: []string{"agg1"},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(cli) != 1 {
		t.Fatalf("want a single consolidated block, got %d", len(cli))
	}
	joined := blockLines(cli)

	if n := strings.Count(joined, "config system interface"); n != 1 {
		t.Errorf("want exactly one `config system interface` wrapper, got %d:\n%s", n, joined)
	}
	// Unchanged interfaces must be reproduced, verbatim detail preserved.
	for _, want := range []string{
		`edit "wan1"`, "set role wan", // untouched interface carried through
		`edit "VL10"`, "set snmp-index 5", "config secondaryip", // VLAN detail kept
		`edit "fortilink"`, "set fortilink enable", // FortiLink created
		`delete "agg1"`, // emptied aggregate deleted
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("output missing %q:\n%s", want, joined)
		}
	}
	// Both VLANs re-parented onto the FortiLink; none left on agg1.
	if strings.Contains(joined, `set interface "agg1"`) {
		t.Errorf("a VLAN is still parented to agg1:\n%s", joined)
	}
	if c := strings.Count(joined, `set interface "fortilink"`); c != 2 {
		t.Errorf("want 2 VLANs re-parented onto fortilink, got %d", c)
	}
	// FortiLink must sit above the VLANs that reference it.
	if fl, vl := strings.Index(joined, `edit "fortilink"`), strings.Index(joined, `edit "VL10"`); fl < 0 || fl > vl {
		t.Errorf("FortiLink (idx %d) must appear above the VLANs (VL10 idx %d)", fl, vl)
	}
}

// blockLines flattens every CLIBlock's lines into one string for substring
// assertions.
func blockLines(blocks []CLIBlock) string {
	var sb strings.Builder
	for _, b := range blocks {
		for _, l := range b.Lines {
			sb.WriteString(l)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
