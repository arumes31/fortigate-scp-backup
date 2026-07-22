package fgt_confconv

import (
	"strings"
	"testing"
)

func freshSDWANConfig() *FGConfig {
	return &FGConfig{
		Interfaces: map[string]*InterfaceEntry{
			"wan1": {Name: "wan1", IP: "203.0.113.10 255.255.255.0", Role: "wan"},
			"wan2": {Name: "wan2", IP: "203.0.113.20 255.255.255.0", Role: "wan"},
			"lan1": {Name: "lan1", IP: "10.0.0.1 255.255.255.0", Role: "lan"},
		},
		Zones:      map[string]*ZoneEntry{},
		SDWANZones: map[string]*SDWANZone{},
		Policies: []*PolicyEntry{
			{ID: 1, SrcIntf: []string{"lan1"}, DstIntf: []string{"wan1", "wan2"}},
		},
		StaticRoutes: []*RouteEntry{
			{Seq: 1, Device: "wan1", Gateway: "203.0.113.1"},
			{Seq: 2, Device: "wan2", Gateway: "203.0.113.2"},
			{Seq: 3, Device: "wan1", Dst: "198.51.100.0 255.255.255.0", Gateway: "203.0.113.1"},
		},
	}
}

func TestSDWANRecipe_HappyPath(t *testing.T) {
	cfg := freshSDWANConfig()
	r := sdwanRecipe{}

	cli, warnings, err := r.Run(cfg, mustJSON(t, SDWANOptions{Members: []string{"wan1", "wan2"}}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(cfg.SDWANMembers) != 2 {
		t.Fatalf("sdwan members = %d, want 2", len(cfg.SDWANMembers))
	}
	if cfg.SDWANMembers[0].Gateway != "203.0.113.1" {
		t.Errorf("member 1 gateway = %q, want inherited from its old default route", cfg.SDWANMembers[0].Gateway)
	}
	if _, ok := cfg.SDWANZones[defaultSDWANZone]; !ok {
		t.Error("default sdwan zone not created")
	}

	// Both default routes must be disabled, replaced by exactly one
	// consolidated route on the zone.
	if !cfg.StaticRoutes[0].Disabled || !cfg.StaticRoutes[1].Disabled {
		t.Error("both original default routes must be disabled")
	}
	var zoneRoutes int
	for _, rt := range cfg.StaticRoutes {
		if rt.Device == defaultSDWANZone && !rt.Disabled {
			zoneRoutes++
		}
	}
	if zoneRoutes != 1 {
		t.Errorf("consolidated zone routes = %d, want 1", zoneRoutes)
	}

	// The non-default route (seq 3) must be left alone but flagged.
	if cfg.StaticRoutes[2].Disabled {
		t.Error("the non-default route must not be auto-disabled")
	}
	var sawRouteWarning bool
	for _, w := range warnings {
		if strings.Contains(w.Detail, "198.51.100.0") {
			sawRouteWarning = true
		}
	}
	if !sawRouteWarning {
		t.Errorf("expected a warning about the untouched non-default route, got %v", warnings)
	}

	// Policy must be repointed from wan1/wan2 to the zone, deduplicated.
	p := cfg.Policies[0]
	if len(p.DstIntf) != 1 || p.DstIntf[0] != defaultSDWANZone {
		t.Errorf("policy dstintf = %v, want [%s]", p.DstIntf, defaultSDWANZone)
	}

	joined := blockLines(cli)
	for _, want := range []string{
		"config system sdwan", `set interface "wan1"`, `set zone "virtual-wan-link"`,
		`set device "virtual-wan-link"`, "set status disable",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cli missing %q:\n%s", want, joined)
		}
	}
}

func TestSDWANRecipe_RejectsAlreadyMember(t *testing.T) {
	cfg := freshSDWANConfig()
	cfg.SDWANMembers = []*SDWANMember{{Seq: 1, Interface: "wan1", Zone: defaultSDWANZone}}
	r := sdwanRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, SDWANOptions{Members: []string{"wan1", "wan2"}}))
	if err == nil {
		t.Fatal("expected an error: wan1 is already an SD-WAN member")
	}
}

func TestSDWANRecipe_RequiresAtLeastTwoMembers(t *testing.T) {
	cfg := freshSDWANConfig()
	r := sdwanRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, SDWANOptions{Members: []string{"wan1"}}))
	if err == nil {
		t.Fatal("expected an error: fewer than 2 members")
	}
}

func TestSDWANRecipe_DHCPMemberWithNoRouteWarnsInsteadOfErroring(t *testing.T) {
	cfg := freshSDWANConfig()
	cfg.StaticRoutes = nil // no default routes at all -- e.g. both WAN links are DHCP
	r := sdwanRecipe{}
	_, warnings, err := r.Run(cfg, mustJSON(t, SDWANOptions{Members: []string{"wan1", "wan2"}}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var gwWarnings int
	for _, w := range warnings {
		if strings.Contains(w.Detail, "no gateway could be determined") {
			gwWarnings++
		}
	}
	if gwWarnings != 2 {
		t.Errorf("expected 2 missing-gateway warnings, got %d (%v)", gwWarnings, warnings)
	}
}
