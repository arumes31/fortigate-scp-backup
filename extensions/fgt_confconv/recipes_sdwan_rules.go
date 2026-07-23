package fgt_confconv

import (
	"encoding/json"
	"fmt"
)

// SDWANRulesOptions configures the "SD-WAN static routes -> SD-WAN rules"
// recipe.
type SDWANRulesOptions struct {
	Strategy string `json:"strategy"` // "manual" | "best-quality"
}

const RecipeKeySDWANRules = "sdwan-routes-to-rules"

const placeholderHealthCheck = "confconv-placeholder"

type sdwanRulesRecipe struct{}

var _ Recipe = sdwanRulesRecipe{}

func (sdwanRulesRecipe) Key() string   { return RecipeKeySDWANRules }
func (sdwanRulesRecipe) Label() string { return "SD-WAN static routes -> SD-WAN rules" }

func (sdwanRulesRecipe) Applicable(cfg *FGConfig) (bool, string) {
	if !cfg.Version.SupportsSDWANSyntax() {
		return false, fmt.Sprintf("SD-WAN recipes need FortiOS 7.4+ (this backup is %s) -- the FortiLink and zone recipes still work on older trains", cfg.Version)
	}
	if len(cfg.SDWANMembers) < 2 {
		return false, "no SD-WAN members in this configuration -- run WAN→SD-WAN first, or check that the backup actually has an SD-WAN set up"
	}
	return true, ""
}

func (r sdwanRulesRecipe) Run(cfg *FGConfig, rawOpts json.RawMessage) ([]CLIBlock, []Warning, error) {
	var opts SDWANRulesOptions
	if err := json.Unmarshal(rawOpts, &opts); err != nil {
		return nil, nil, fmt.Errorf("invalid options: %w", err)
	}
	if opts.Strategy != "manual" && opts.Strategy != "best-quality" {
		return nil, nil, fmt.Errorf("strategy must be %q or %q, got %q", "manual", "best-quality", opts.Strategy)
	}

	var cli []CLIBlock
	var warnings []Warning

	// A health-check is only consulted by best-quality rules; manual rules
	// steer on priority-members alone, so skip the placeholder (and its
	// config mutation) entirely for the manual strategy.
	healthCheck := ""
	if opts.Strategy == "best-quality" {
		if len(cfg.SDWANHealthChecks) > 0 {
			healthCheck = cfg.SDWANHealthChecks[0]
		} else {
			healthCheck = placeholderHealthCheck
			cfg.SDWANHealthChecks = append(cfg.SDWANHealthChecks, healthCheck)
			cli = append(cli, CLIBlock{
				Recipe: r.Key(),
				Label:  "Placeholder SD-WAN health-check",
				Lines: []string{
					"config system sdwan",
					"    config health-check",
					fmt.Sprintf("        edit %q", healthCheck),
					`        set server "8.8.8.8"`,
					"        set members 0",
					"    next",
					"    end",
					"end",
				},
			})
			warnings = append(warnings, Warning{
				Recipe: r.Key(),
				Detail: "no SD-WAN health-check existed, so a placeholder pinging 8.8.8.8 was added -- replace it with a real monitored endpoint before relying on quality-based rules",
			})
		}
	}

	// Only zones that actually have >=1 member get a rule -- a zone with no
	// members can't carry traffic, so a rule for it would be meaningless.
	zoneMembers := map[string][]*SDWANMember{}
	for _, m := range cfg.SDWANMembers {
		zone := m.Zone
		if zone == "" {
			zone = defaultSDWANZone
		}
		zoneMembers[zone] = append(zoneMembers[zone], m)
	}

	nextSeq := 0
	for _, rt := range cfg.StaticRoutes {
		if rt.Seq > nextSeq {
			nextSeq = rt.Seq
		}
	}

	var ruleCount int
	for _, rt := range cfg.StaticRoutes {
		if rt.Disabled {
			continue
		}
		members, ok := zoneMembers[rt.Device]
		if !ok || len(members) == 0 {
			continue
		}
		rt.Disabled = true
		cli = append(cli, CLIBlock{
			Recipe: r.Key(),
			Label:  fmt.Sprintf("Disable superseded static route (seq %d)", rt.Seq),
			Lines: []string{
				"config router static",
				fmt.Sprintf("    edit %d", rt.Seq),
				"        set status disable",
				"    next",
				"end",
			},
		})

		ruleCount++
		dst := rt.Dst
		lines := []string{
			"config system sdwan",
			"    config service",
			fmt.Sprintf("        edit %d", nextSeq+ruleCount),
			fmt.Sprintf("            set name \"ConfConv-Rule-%d\"", nextSeq+ruleCount),
			fmt.Sprintf("            set mode %s", opts.Strategy),
		}
		if dst == "" {
			lines = append(lines, `            set dst "all"`)
		} else {
			lines = append(lines, fmt.Sprintf("            set dst %q", dst))
		}
		lines = append(lines, `            set src "all"`)
		if opts.Strategy == "manual" {
			seqs := ""
			for i, m := range members {
				if i > 0 {
					seqs += " "
				}
				seqs += fmt.Sprintf("%d", m.Seq)
			}
			lines = append(lines, fmt.Sprintf("            set priority-members %s", seqs))
		} else {
			lines = append(lines, fmt.Sprintf("            set health-check %q", healthCheck))
		}
		lines = append(lines, "        next", "    end", "end")

		cli = append(cli, CLIBlock{
			Recipe: r.Key(),
			Label:  fmt.Sprintf("SD-WAN rule for zone %q (was route seq %d)", rt.Device, rt.Seq),
			Lines:  lines,
		})
	}

	if ruleCount == 0 {
		warnings = append(warnings, Warning{
			Recipe: r.Key(),
			Detail: "no active static route pointed at an SD-WAN zone -- nothing to upgrade into a rule",
		})
	}

	return cli, warnings, nil
}
