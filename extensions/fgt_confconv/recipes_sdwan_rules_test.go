package fgt_confconv

import (
	"strings"
	"testing"
)

func freshSDWANRulesConfig() *FGConfig {
	return &FGConfig{
		Interfaces: map[string]*InterfaceEntry{},
		Zones:      map[string]*ZoneEntry{},
		SDWANZones: map[string]*SDWANZone{defaultSDWANZone: {Name: defaultSDWANZone}},
		SDWANMembers: []*SDWANMember{
			{Seq: 1, Interface: "wan1", Gateway: "203.0.113.1", Zone: defaultSDWANZone},
			{Seq: 2, Interface: "wan2", Gateway: "203.0.113.2", Zone: defaultSDWANZone},
		},
		StaticRoutes: []*RouteEntry{
			{Seq: 5, Device: defaultSDWANZone},
		},
	}
}

func TestSDWANRulesRecipe_Applicable(t *testing.T) {
	cfg := &FGConfig{}
	r := sdwanRulesRecipe{}
	if ok, reason := r.Applicable(cfg); ok || reason == "" {
		t.Errorf("expected not-applicable with a reason for an empty config, got ok=%v reason=%q", ok, reason)
	}

	cfg2 := freshSDWANRulesConfig()
	if ok, _ := r.Applicable(cfg2); !ok {
		t.Error("expected applicable with 2 SD-WAN members present")
	}
}

func TestSDWANRulesRecipe_AddsPlaceholderHealthCheckWhenNoneExists(t *testing.T) {
	cfg := freshSDWANRulesConfig()
	r := sdwanRulesRecipe{}
	cli, warnings, err := r.Run(cfg, mustJSON(t, SDWANRulesOptions{Strategy: "best-quality"}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(cfg.SDWANHealthChecks) != 1 || cfg.SDWANHealthChecks[0] != placeholderHealthCheck {
		t.Errorf("health checks = %v", cfg.SDWANHealthChecks)
	}
	var sawPlaceholderWarning bool
	for _, w := range warnings {
		if strings.Contains(w.Detail, "placeholder") {
			sawPlaceholderWarning = true
		}
	}
	if !sawPlaceholderWarning {
		t.Errorf("expected a placeholder health-check warning, got %v", warnings)
	}
	if !strings.Contains(blockLines(cli), placeholderHealthCheck) {
		t.Errorf("cli missing placeholder health-check:\n%s", blockLines(cli))
	}
}

func TestSDWANRulesRecipe_UsesExistingHealthCheckWithoutWarning(t *testing.T) {
	cfg := freshSDWANRulesConfig()
	cfg.SDWANHealthChecks = []string{"ping-ISP"}
	r := sdwanRulesRecipe{}
	cli, warnings, err := r.Run(cfg, mustJSON(t, SDWANRulesOptions{Strategy: "best-quality"}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w.Detail, "placeholder") {
			t.Errorf("should not warn about a placeholder when a real health-check exists: %v", warnings)
		}
	}
	if !strings.Contains(blockLines(cli), `set health-check "ping-ISP"`) {
		t.Errorf("cli should reference the existing health-check:\n%s", blockLines(cli))
	}
}

func TestSDWANRulesRecipe_ManualStrategyUsesPriorityMembers(t *testing.T) {
	cfg := freshSDWANRulesConfig()
	cfg.SDWANHealthChecks = []string{"ping-ISP"}
	r := sdwanRulesRecipe{}
	cli, _, err := r.Run(cfg, mustJSON(t, SDWANRulesOptions{Strategy: "manual"}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	joined := blockLines(cli)
	if !strings.Contains(joined, "set priority-members 1 2") {
		t.Errorf("manual strategy should list member seqs unquoted:\n%s", joined)
	}
	if !strings.Contains(joined, "set mode manual") {
		t.Errorf("cli missing mode manual:\n%s", joined)
	}

	// The route it superseded must be disabled, never deleted.
	if !cfg.StaticRoutes[0].Disabled {
		t.Error("superseded route must be disabled")
	}
	if !strings.Contains(joined, "set status disable") {
		t.Errorf("cli missing the route-disable block:\n%s", joined)
	}
}

func TestSDWANRulesRecipe_RejectsUnknownStrategy(t *testing.T) {
	cfg := freshSDWANRulesConfig()
	r := sdwanRulesRecipe{}
	_, _, err := r.Run(cfg, mustJSON(t, SDWANRulesOptions{Strategy: "load-balance"}))
	if err == nil {
		t.Fatal("expected an error for an unsupported v1 strategy")
	}
}

func TestSDWANRulesRecipe_NoQualifyingRouteWarnsInsteadOfErroring(t *testing.T) {
	cfg := freshSDWANRulesConfig()
	cfg.StaticRoutes = nil
	cfg.SDWANHealthChecks = []string{"ping-ISP"}
	r := sdwanRulesRecipe{}
	_, warnings, err := r.Run(cfg, mustJSON(t, SDWANRulesOptions{Strategy: "manual"}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var sawNoRouteWarning bool
	for _, w := range warnings {
		if strings.Contains(w.Detail, "nothing to upgrade") {
			sawNoRouteWarning = true
		}
	}
	if !sawNoRouteWarning {
		t.Errorf("expected a 'nothing to upgrade' warning, got %v", warnings)
	}
}
