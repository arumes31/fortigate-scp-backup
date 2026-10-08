package fgt_confconv

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDiffConfigsReportsOnlyRealModelMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*FGConfig)
		want   ConfigChange
	}{
		{
			name: "interface created",
			mutate: func(cfg *FGConfig) {
				cfg.Interfaces["fortilink1"] = &InterfaceEntry{Name: "fortilink1", Type: "aggregate", Fortilink: true}
			},
			want: ConfigChange{Kind: "interface", Name: "fortilink1", Action: "create", Summary: "Created interface."},
		},
		{
			name: "zone updated",
			mutate: func(cfg *FGConfig) {
				cfg.Zones["trusted"] = &ZoneEntry{Name: "trusted", Interfaces: []string{"lan1"}}
			},
			want: ConfigChange{Kind: "zone", Name: "trusted", Action: "create", Summary: "Created zone."},
		},
		{
			name: "policy updated",
			mutate: func(cfg *FGConfig) {
				cfg.Policies[0].SrcIntf = []string{"trusted"}
			},
			want: ConfigChange{Kind: "policy", Name: "1", Action: "update", Summary: "Changed fields: source interfaces."},
		},
		{
			name: "route disabled",
			mutate: func(cfg *FGConfig) {
				cfg.StaticRoutes[0].Disabled = true
			},
			want: ConfigChange{Kind: "static route", Name: "1", Action: "disable", Summary: "Disabled superseded static route."},
		},
		{
			name: "SD-WAN member created",
			mutate: func(cfg *FGConfig) {
				cfg.SDWANMembers = append(cfg.SDWANMembers, &SDWANMember{Seq: 7, Interface: "wan1", Gateway: "203.0.113.1", Zone: "virtual-wan-link"})
			},
			want: ConfigChange{Kind: "SD-WAN member", Name: "7", Action: "create", Summary: "Created SD-WAN member."},
		},
		{
			name: "SD-WAN zone created",
			mutate: func(cfg *FGConfig) {
				cfg.SDWANZones["virtual-wan-link"] = &SDWANZone{Name: "virtual-wan-link"}
			},
			want: ConfigChange{Kind: "SD-WAN zone", Name: "virtual-wan-link", Action: "create", Summary: "Created SD-WAN zone."},
		},
		{
			name: "health check created",
			mutate: func(cfg *FGConfig) {
				cfg.SDWANHealthChecks = append(cfg.SDWANHealthChecks, "quality-check")
			},
			want: ConfigChange{Kind: "SD-WAN health check", Name: "quality-check", Action: "create", Summary: "Created SD-WAN health check."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := freshPipelineConfig()
			after := before.Clone()
			tt.mutate(after)

			changes, total, truncated := DiffConfigs(before, after)
			if truncated || total != 1 || len(changes) != 1 {
				t.Fatalf("DiffConfigs() = (%+v, %d, %v), want one complete change", changes, total, truncated)
			}
			if changes[0] != tt.want {
				t.Errorf("change = %+v, want %+v", changes[0], tt.want)
			}
		})
	}
}

func TestDiffConfigsIsStableBoundedAndDoesNotExposeFieldValues(t *testing.T) {
	before := freshPipelineConfig()
	after := before.Clone()
	after.Interfaces["wan1"].IP = "do-not-return-this-value"
	for i := 0; i < maxConfigChanges+25; i++ {
		name := fmt.Sprintf("synthetic-%04d", i)
		after.Interfaces[name] = &InterfaceEntry{Name: name}
	}

	first, total, truncated := DiffConfigs(before, after)
	second, secondTotal, secondTruncated := DiffConfigs(before, after)
	if !truncated || !secondTruncated {
		t.Fatal("large diffs must report truncation")
	}
	if total != maxConfigChanges+26 || secondTotal != total {
		t.Fatalf("total changes = %d/%d, want %d", total, secondTotal, maxConfigChanges+26)
	}
	if len(first) != maxConfigChanges {
		t.Fatalf("returned changes = %d, want %d", len(first), maxConfigChanges)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated diffs are not deterministic")
	}
	for _, change := range first {
		if strings.Contains(change.Summary, "do-not-return-this-value") {
			t.Fatalf("change summary leaked a field value: %+v", change)
		}
	}
}

func TestRunPipelineReportsExplicitNoChangeState(t *testing.T) {
	cfg := freshPipelineConfig()
	cfg.SDWANZones[defaultSDWANZone] = &SDWANZone{Name: defaultSDWANZone}
	cfg.SDWANMembers = []*SDWANMember{
		{Seq: 1, Interface: "wan1", Zone: defaultSDWANZone},
		{Seq: 2, Interface: "wan2", Zone: defaultSDWANZone},
	}
	cfg.StaticRoutes = nil

	result, err := RunPipeline(cfg, []RecipeSelection{{
		Key: RecipeKeySDWANRules, Options: mustJSON(t, SDWANRulesOptions{Strategy: "manual"}),
	}})
	if err != nil {
		t.Fatalf("RunPipeline() error = %v", err)
	}
	if result.ChangeCount != 0 || result.ChangesTruncated || len(result.Changes) != 0 {
		t.Fatalf("no-change result = count %d, truncated %v, changes %+v", result.ChangeCount, result.ChangesTruncated, result.Changes)
	}
}

func TestRunPipelineDiffOrderSnapshot(t *testing.T) {
	cfg := freshPipelineConfig()
	result, err := RunPipeline(cfg, []RecipeSelection{{
		Key: RecipeKeyZone,
		Options: mustJSON(t, ZoneOptions{
			Interfaces: []string{"lan1", "port1"}, ZoneName: "trusted",
		}),
	}})
	if err != nil {
		t.Fatalf("RunPipeline() error = %v", err)
	}

	var got []string
	for _, change := range result.Changes {
		got = append(got, strings.Join([]string{change.Kind, change.Name, change.Action, change.Summary}, "|"))
	}
	want := []string{
		"zone|trusted|create|Created zone.",
		"policy|1|update|Changed fields: source interfaces.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered changes = %#v, want %#v", got, want)
	}
}
