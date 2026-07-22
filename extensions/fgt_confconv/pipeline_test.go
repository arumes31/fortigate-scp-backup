package fgt_confconv

import (
	"strings"
	"testing"
)

func freshPipelineConfig() *FGConfig {
	return &FGConfig{
		Interfaces: map[string]*InterfaceEntry{
			"wan1":  {Name: "wan1", IP: "203.0.113.10 255.255.255.0", Role: "wan"},
			"wan2":  {Name: "wan2", IP: "203.0.113.20 255.255.255.0", Role: "wan"},
			"lan1":  {Name: "lan1", IP: "10.0.0.1 255.255.255.0", Role: "lan"},
			"port1": {Name: "port1", IP: "10.1.0.1 255.255.255.0"},
			"port2": {Name: "port2", IP: "10.2.0.1 255.255.255.0"},
		},
		Zones:      map[string]*ZoneEntry{},
		SDWANZones: map[string]*SDWANZone{},
		Policies: []*PolicyEntry{
			{ID: 1, SrcIntf: []string{"lan1"}, DstIntf: []string{"wan1", "wan2"}},
		},
		StaticRoutes: []*RouteEntry{
			{Seq: 1, Device: "wan1", Gateway: "203.0.113.1"},
			{Seq: 2, Device: "wan2", Gateway: "203.0.113.2"},
		},
	}
}

func TestRunPipeline_ChainsWANToSDWANThenRoutesToRules(t *testing.T) {
	cfg := freshPipelineConfig()

	// Submitted in reverse of canonical order -- the pipeline must still run
	// wan-to-sdwan first so routes-to-rules sees the members it creates.
	selections := []RecipeSelection{
		{Key: RecipeKeySDWANRules, Options: mustJSON(t, SDWANRulesOptions{Strategy: "manual"})},
		{Key: RecipeKeySDWAN, Options: mustJSON(t, SDWANOptions{Members: []string{"wan1", "wan2"}})},
	}

	result, err := RunPipeline(cfg, selections)
	if err != nil {
		t.Fatalf("RunPipeline() error = %v", err)
	}

	if len(result.AppliedOrder) != 2 || result.AppliedOrder[0] != RecipeKeySDWAN || result.AppliedOrder[1] != RecipeKeySDWANRules {
		t.Fatalf("applied order = %v, want [%s, %s]", result.AppliedOrder, RecipeKeySDWAN, RecipeKeySDWANRules)
	}

	// routes-to-rules must have found the 2 members wan-to-sdwan just made
	// and emitted a rule referencing them -- not failed for lack of members.
	if !strings.Contains(result.Combined, "config service") {
		t.Errorf("combined script missing an SD-WAN service rule:\n%s", result.Combined)
	}
	if !strings.Contains(result.Combined, "set priority-members 1 2") {
		t.Errorf("combined script missing the manual priority-members line:\n%s", result.Combined)
	}
}

func TestRunPipeline_RoutesToRulesAloneFailsApplicable(t *testing.T) {
	cfg := freshPipelineConfig() // no SD-WAN members exist yet
	_, err := RunPipeline(cfg, []RecipeSelection{
		{Key: RecipeKeySDWANRules, Options: mustJSON(t, SDWANRulesOptions{Strategy: "manual"})},
	})
	if err == nil {
		t.Fatal("expected an error: no SD-WAN members exist")
	}
	pe, ok := err.(*PipelineError)
	if !ok {
		t.Fatalf("expected a *PipelineError, got %T: %v", err, err)
	}
	if pe.Recipe != RecipeKeySDWANRules {
		t.Errorf("PipelineError.Recipe = %q, want %q", pe.Recipe, RecipeKeySDWANRules)
	}
}

func TestRunPipeline_RejectsInterfaceClaimedByTwoRecipes(t *testing.T) {
	cfg := freshPipelineConfig()
	cfg.Interfaces["port1"].IP = "" // clear so it's eligible as a bare FortiLink member port
	selections := []RecipeSelection{
		{Key: RecipeKeyFortiLink, Options: mustJSON(t, FortiLinkOptions{
			MemberPorts: []string{"port1", "port2"}, FortilinkName: "fortilink1",
		})},
		{Key: RecipeKeyZone, Options: mustJSON(t, ZoneOptions{
			Interfaces: []string{"port1", "lan1"}, ZoneName: "zone-lan",
		})},
	}
	_, err := RunPipeline(cfg, selections)
	if err == nil {
		t.Fatal("expected a conflict error: port1 claimed by both recipes")
	}
	if !strings.Contains(err.Error(), "port1") {
		t.Errorf("error should name the conflicting interface, got: %v", err)
	}
	// Nothing should have been mutated -- the conflict check runs before any
	// recipe executes.
	if _, ok := cfg.Interfaces["fortilink1"]; ok {
		t.Error("fortilink1 must not have been created after a rejected pipeline")
	}
}

func TestRunPipeline_UnknownRecipeKey(t *testing.T) {
	cfg := freshPipelineConfig()
	_, err := RunPipeline(cfg, []RecipeSelection{{Key: "not-a-real-recipe", Options: []byte(`{}`)}})
	if err == nil {
		t.Fatal("expected an error for an unknown recipe key")
	}
}

func TestRunPipeline_SingleRecipeStillWorks(t *testing.T) {
	cfg := freshPipelineConfig()
	result, err := RunPipeline(cfg, []RecipeSelection{
		{Key: RecipeKeyZone, Options: mustJSON(t, ZoneOptions{Interfaces: []string{"port1", "port2"}, ZoneName: "zone-lan"})},
	})
	if err != nil {
		t.Fatalf("RunPipeline() error = %v", err)
	}
	if len(result.AppliedOrder) != 1 || result.AppliedOrder[0] != RecipeKeyZone {
		t.Errorf("applied order = %v", result.AppliedOrder)
	}
}
