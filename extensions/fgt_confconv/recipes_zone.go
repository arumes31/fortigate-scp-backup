package fgt_confconv

import (
	"encoding/json"
	"fmt"
)

// ZoneOptions configures the "Interface-based -> zone-based policies" recipe.
type ZoneOptions struct {
	Interfaces    []string `json:"interfaces"`
	ZoneName      string   `json:"zone_name"`
	UseExisting   bool     `json:"use_existing"`
	IntrazoneDeny bool     `json:"intrazone_deny"`
}

const RecipeKeyZone = "iface-to-zone"

type zoneRecipe struct{}

var _ Recipe = zoneRecipe{}

func (zoneRecipe) Key() string   { return RecipeKeyZone }
func (zoneRecipe) Label() string { return "Interface-based -> zone-based policies" }

func (zoneRecipe) Applicable(cfg *FGConfig) (bool, string) { return true, "" }

func (r zoneRecipe) Run(cfg *FGConfig, rawOpts json.RawMessage) ([]CLIBlock, []Warning, error) {
	var opts ZoneOptions
	if err := json.Unmarshal(rawOpts, &opts); err != nil {
		return nil, nil, fmt.Errorf("invalid options: %w", err)
	}
	if len(opts.Interfaces) < 2 {
		return nil, nil, fmt.Errorf("at least 2 interfaces are required to form a zone")
	}
	if opts.ZoneName == "" {
		return nil, nil, fmt.Errorf("a zone name is required")
	}

	for _, name := range opts.Interfaces {
		if _, ok := cfg.Interfaces[name]; !ok {
			return nil, nil, fmt.Errorf("interface %q not found in this configuration", name)
		}
		if isSDWANMember(cfg, name) {
			return nil, nil, fmt.Errorf("interface %q is an SD-WAN member and cannot also join a zone", name)
		}
		if z := zoneContaining(cfg, name); z != "" && z != opts.ZoneName {
			return nil, nil, fmt.Errorf("interface %q already belongs to zone %q", name, z)
		}
	}

	zone, exists := cfg.Zones[opts.ZoneName]
	if opts.UseExisting {
		if !exists {
			return nil, nil, fmt.Errorf("zone %q does not exist", opts.ZoneName)
		}
	} else if exists {
		return nil, nil, fmt.Errorf("zone %q already exists -- use the existing-zone option or pick a different name", opts.ZoneName)
	} else {
		zone = &ZoneEntry{Name: opts.ZoneName, IntrazoneDeny: opts.IntrazoneDeny}
		cfg.Zones[opts.ZoneName] = zone
	}
	zone.Interfaces = dedupStr(append(append([]string(nil), zone.Interfaces...), opts.Interfaces...))

	var cli []CLIBlock
	var warnings []Warning

	cli = append(cli, CLIBlock{
		Recipe: r.Key(),
		Label:  fmt.Sprintf("Zone %q", opts.ZoneName),
		Lines: []string{
			"config system zone",
			fmt.Sprintf("    edit %q", opts.ZoneName),
			fmt.Sprintf("        set interface %s", quoteJoin(zone.Interfaces)),
			fmt.Sprintf("        set intrazone-deny %s", enableDisable(zone.IntrazoneDeny)),
			"    next",
			"end",
		},
	})

	touched := map[int]bool{}
	for _, name := range opts.Interfaces {
		for _, id := range replaceInterfaceInPolicies(cfg, name, opts.ZoneName) {
			touched[id] = true
		}
		for _, hit := range ScanReferences(cfg, name) {
			warnings = append(warnings, Warning{
				Recipe: r.Key(), Section: hit.Section, Line: hit.Line,
				Detail: fmt.Sprintf("%q is still referenced in %s (%s) after joining zone %q", name, hit.Section, hit.Edit, opts.ZoneName),
			})
		}
	}
	if len(touched) > 0 {
		var lines []string
		for id := range touched {
			if p := policyByID(cfg, id); p != nil {
				lines = append(lines, cliPolicyIntfBlock(p)...)
			}
		}
		cli = append(cli, CLIBlock{Recipe: r.Key(), Label: "Repoint policies at the zone", Lines: lines})
	}

	return cli, warnings, nil
}

func enableDisable(b bool) string {
	if b {
		return "enable"
	}
	return "disable"
}
