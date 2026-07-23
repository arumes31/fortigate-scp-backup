package fgt_confconv

import (
	"strings"
	"testing"
)

func freshZoneConfig() *FGConfig {
	return &FGConfig{
		Interfaces: map[string]*InterfaceEntry{
			"port1": {Name: "port1", IP: "10.1.0.1 255.255.255.0"},
			"port2": {Name: "port2", IP: "10.2.0.1 255.255.255.0"},
			"port3": {Name: "port3", IP: "10.3.0.1 255.255.255.0"},
		},
		Zones:      map[string]*ZoneEntry{},
		SDWANZones: map[string]*SDWANZone{},
		Policies: []*PolicyEntry{
			{ID: 1, SrcIntf: []string{"port1"}, DstIntf: []string{"port3"}},
			{ID: 2, SrcIntf: []string{"port2", "port3"}, DstIntf: []string{"port1"}},
		},
	}
}

func TestZoneRecipe_HappyPath(t *testing.T) {
	cfg := freshZoneConfig()
	r := zoneRecipe{}

	cli, warnings, err := r.Run(cfg, mustJSON(t, ZoneOptions{
		Interfaces: []string{"port1", "port2"},
		ZoneName:   "zone-lan",
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	zone, ok := cfg.Zones["zone-lan"]
	if !ok {
		t.Fatal("zone-lan was not created")
	}
	if len(zone.Interfaces) != 2 {
		t.Errorf("zone interfaces = %v", zone.Interfaces)
	}

	// Policy 1: srcintf port1 -> zone-lan.
	p1 := cfg.Policies[0]
	if len(p1.SrcIntf) != 1 || p1.SrcIntf[0] != "zone-lan" {
		t.Errorf("policy 1 srcintf = %v", p1.SrcIntf)
	}

	// Policy 2 referenced BOTH port2 and port3 in srcintf; port2 is zoned but
	// port3 is not -- after substitution it must dedupe to just [zone-lan,
	// port3] rather than leaving two separate entries if both had matched
	// the same zone (they don't here, but the dedupe path must still work).
	p2 := cfg.Policies[1]
	if len(p2.SrcIntf) != 2 || !containsStr(p2.SrcIntf, "zone-lan") || !containsStr(p2.SrcIntf, "port3") {
		t.Errorf("policy 2 srcintf = %v", p2.SrcIntf)
	}
	if p2.DstIntf[0] != "zone-lan" {
		t.Errorf("policy 2 dstintf = %v", p2.DstIntf)
	}

	joined := blockLines(cli)
	if !strings.Contains(joined, `edit "zone-lan"`) || !strings.Contains(joined, "set intrazone-deny disable") {
		t.Errorf("cli missing zone block:\n%s", joined)
	}
}

func TestZoneRecipe_DedupesWhenBothSidesJoinSameZone(t *testing.T) {
	cfg := freshZoneConfig()
	r := zoneRecipe{}
	// Policy 2 has srcintf ["port2","port3"]; zoning BOTH into the same zone
	// must collapse the list to a single "zone-both" entry, not repeat it.
	_, _, err := r.Run(cfg, mustJSON(t, ZoneOptions{
		Interfaces: []string{"port2", "port3"},
		ZoneName:   "zone-both",
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	p2 := cfg.Policies[1]
	if len(p2.SrcIntf) != 1 || p2.SrcIntf[0] != "zone-both" {
		t.Errorf("policy 2 srcintf should collapse to a single zone-both entry, got %v", p2.SrcIntf)
	}
}

func TestZoneRecipe_RejectsFewerThanTwoInterfaces(t *testing.T) {
	cfg := freshZoneConfig()
	r := zoneRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, ZoneOptions{Interfaces: []string{"port1"}, ZoneName: "zone-lan"}))
	if err == nil {
		t.Fatal("expected an error: fewer than 2 interfaces")
	}
}

func TestZoneRecipe_RejectsInterfaceAlreadyInAnotherZone(t *testing.T) {
	cfg := freshZoneConfig()
	cfg.Zones["zone-dmz"] = &ZoneEntry{Name: "zone-dmz", Interfaces: []string{"port1"}}
	r := zoneRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, ZoneOptions{Interfaces: []string{"port1", "port2"}, ZoneName: "zone-lan"}))
	if err == nil {
		t.Fatal("expected an error: port1 already belongs to zone-dmz")
	}
}

func TestZoneRecipe_RejectsSDWANMember(t *testing.T) {
	cfg := freshZoneConfig()
	cfg.SDWANMembers = []*SDWANMember{{Seq: 1, Interface: "port1"}}
	r := zoneRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, ZoneOptions{Interfaces: []string{"port1", "port2"}, ZoneName: "zone-lan"}))
	if err == nil {
		t.Fatal("expected an error: port1 is an SD-WAN member")
	}
}
