package fgt_confconv

import (
	"encoding/json"
	"fmt"
)

// SDWANOptions configures the "WAN interface(s) -> SD-WAN" recipe.
type SDWANOptions struct {
	Members     []string `json:"members"`
	ZoneName    string   `json:"zone_name"`
	UseExisting bool     `json:"use_existing"`
}

const RecipeKeySDWAN = "wan-to-sdwan"

const defaultSDWANZone = "virtual-wan-link"

type sdwanRecipe struct{}

var _ Recipe = sdwanRecipe{}

func (sdwanRecipe) Key() string   { return RecipeKeySDWAN }
func (sdwanRecipe) Label() string { return "WAN interface(s) -> SD-WAN" }

func (sdwanRecipe) Applicable(cfg *FGConfig) (bool, string) { return true, "" }

func (r sdwanRecipe) Run(cfg *FGConfig, rawOpts json.RawMessage) ([]CLIBlock, []Warning, error) {
	var opts SDWANOptions
	if err := json.Unmarshal(rawOpts, &opts); err != nil {
		return nil, nil, fmt.Errorf("invalid options: %w", err)
	}
	if len(opts.Members) < 2 {
		return nil, nil, fmt.Errorf("at least 2 WAN interfaces are required to form an SD-WAN")
	}
	zoneName := opts.ZoneName
	if zoneName == "" {
		zoneName = defaultSDWANZone
	}

	for _, m := range opts.Members {
		if _, ok := cfg.Interfaces[m]; !ok {
			return nil, nil, fmt.Errorf("interface %q not found in this configuration", m)
		}
		if isSDWANMember(cfg, m) {
			return nil, nil, fmt.Errorf("interface %q is already an SD-WAN member", m)
		}
		if z := zoneContaining(cfg, m); z != "" {
			return nil, nil, fmt.Errorf("interface %q already belongs to zone %q -- remove it from the zone first", m, z)
		}
	}

	_, zoneExists := cfg.SDWANZones[zoneName]
	if opts.UseExisting {
		if !zoneExists {
			return nil, nil, fmt.Errorf("SD-WAN zone %q does not exist", zoneName)
		}
	} else if zoneExists {
		return nil, nil, fmt.Errorf("SD-WAN zone %q already exists -- use the existing-zone option or pick a different name", zoneName)
	} else {
		cfg.SDWANZones[zoneName] = &SDWANZone{Name: zoneName}
	}

	var cli []CLIBlock
	var warnings []Warning

	nextSeq := 0
	for _, m := range cfg.SDWANMembers {
		if m.Seq > nextSeq {
			nextSeq = m.Seq
		}
	}

	sdwanLines := []string{"config system sdwan", "    set status enable"}
	if !zoneExists {
		sdwanLines = append(sdwanLines, "    config zone", fmt.Sprintf("        edit %q", zoneName), "        next", "    end")
	}
	sdwanLines = append(sdwanLines, "    config members")
	for _, m := range opts.Members {
		nextSeq++
		gw := memberGateway(cfg, m)
		member := &SDWANMember{Seq: nextSeq, Interface: m, Gateway: gw, Zone: zoneName}
		cfg.SDWANMembers = append(cfg.SDWANMembers, member)

		sdwanLines = append(sdwanLines, fmt.Sprintf("        edit %d", nextSeq),
			fmt.Sprintf("            set interface %q", m),
			fmt.Sprintf("            set zone %q", zoneName))
		if gw != "" {
			sdwanLines = append(sdwanLines, fmt.Sprintf("            set gateway %s", gw))
		} else {
			warnings = append(warnings, Warning{
				Recipe: r.Key(),
				Detail: fmt.Sprintf("no gateway could be determined for %q -- add one to the SD-WAN member manually if it is not DHCP-assigned", m),
			})
		}
		sdwanLines = append(sdwanLines, "        next")
	}
	sdwanLines = append(sdwanLines, "    end", "end")
	cli = append(cli, CLIBlock{Recipe: r.Key(), Label: fmt.Sprintf("SD-WAN zone %q + members", zoneName), Lines: sdwanLines})

	// Consolidate default static routes on the picked members into one route
	// on the zone; disable (never delete) every route it supersedes.
	var routeCLI []string
	var supersededGW string
	for _, m := range opts.Members {
		for _, rt := range cfg.StaticRoutes {
			if rt.Disabled || rt.Device != m || rt.Dst != "" {
				continue
			}
			if supersededGW == "" {
				supersededGW = rt.Gateway
			}
			rt.Disabled = true
			routeCLI = append(routeCLI, "config router static",
				fmt.Sprintf("    edit %d", rt.Seq),
				"        set status disable",
				"    next", "end")
		}
		// Non-default routes referencing a picked member are a judgment
		// call (repointing them to the whole zone changes which member can
		// carry that traffic) -- flag instead of guessing.
		for _, rt := range cfg.StaticRoutes {
			if !rt.Disabled && rt.Device == m && rt.Dst != "" {
				warnings = append(warnings, Warning{
					Recipe: r.Key(), Section: "router static",
					Detail: fmt.Sprintf("static route to %s via %q (seq %d) was left as-is -- review whether it should move to the SD-WAN zone", rt.Dst, m, rt.Seq),
				})
			}
		}
	}
	if len(routeCLI) > 0 {
		nextRouteSeq := 0
		for _, rt := range cfg.StaticRoutes {
			if rt.Seq > nextRouteSeq {
				nextRouteSeq = rt.Seq
			}
		}
		nextRouteSeq++
		newRoute := &RouteEntry{Seq: nextRouteSeq, Device: zoneName}
		cfg.StaticRoutes = append(cfg.StaticRoutes, newRoute)
		routeCLI = append(routeCLI, "config router static",
			fmt.Sprintf("    edit %d", nextRouteSeq),
			fmt.Sprintf("        set device %q", zoneName),
			"        set dst 0.0.0.0 0.0.0.0")
		if supersededGW != "" {
			routeCLI = append(routeCLI, fmt.Sprintf("        set gateway %s", supersededGW))
		}
		routeCLI = append(routeCLI, "    next", "end")
		cli = append(cli, CLIBlock{Recipe: r.Key(), Label: "Consolidate default routes onto the SD-WAN zone", Lines: routeCLI})
	}

	// Repoint policies from the individual interfaces to the zone.
	touched := map[int]bool{}
	for _, m := range opts.Members {
		for _, id := range replaceInterfaceInPolicies(cfg, m, zoneName) {
			touched[id] = true
		}
		for _, hit := range ScanReferences(cfg, m) {
			warnings = append(warnings, Warning{
				Recipe: r.Key(), Section: hit.Section, Line: hit.Line,
				Detail: fmt.Sprintf("%q is still referenced in %s (%s) after becoming an SD-WAN member", m, hit.Section, hit.Edit),
			})
		}
	}
	if len(touched) > 0 {
		var lines []string
		for id := range touched {
			p := policyByID(cfg, id)
			if p == nil {
				continue
			}
			lines = append(lines, cliPolicyIntfBlock(p)...)
		}
		cli = append(cli, CLIBlock{Recipe: r.Key(), Label: "Repoint policies at the SD-WAN zone", Lines: lines})
	}

	return cli, warnings, nil
}

// memberGateway looks up the gateway from an existing default static route
// on iface, if any -- so a WAN link that already had `set device wanX /
// set gateway Y` keeps the same next-hop once it becomes an SD-WAN member.
func memberGateway(cfg *FGConfig, iface string) string {
	for _, rt := range cfg.StaticRoutes {
		if !rt.Disabled && rt.Device == iface && rt.Dst == "" && rt.Gateway != "" {
			return rt.Gateway
		}
	}
	return ""
}
