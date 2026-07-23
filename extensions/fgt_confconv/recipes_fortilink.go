package fgt_confconv

import (
	"encoding/json"
	"fmt"
	"sort"
)

// VLANMove carries an existing interface's L3 config (ip/allowaccess/role)
// onto a VLAN stacked on the new FortiLink interface. The interface keeps
// its name -- only its type/parent/vlanid change -- so nothing that already
// references it by name needs rewriting.
type VLANMove struct {
	Interface string `json:"interface"`
	VLANID    int    `json:"vlan_id"`
}

// FortiLinkOptions configures the "Interface(s) -> FortiLink" recipe.
type FortiLinkOptions struct {
	MemberPorts   []string   `json:"member_ports"`
	FortilinkName string     `json:"fortilink_name"`
	UseExisting   bool       `json:"use_existing"`
	VLANMoves     []VLANMove `json:"vlan_moves"`
	// BulkVLANParents lists interfaces whose every stacked VLAN should be moved
	// onto the FortiLink -- each expanded into a VLANMove keeping its existing
	// name and tag. Handy when an aggregate/port carries dozens of VLANs.
	BulkVLANParents []string `json:"bulk_vlan_parents"`
}

const RecipeKeyFortiLink = "iface-to-fortilink"

type fortiLinkRecipe struct{}

var _ Recipe = fortiLinkRecipe{}

func (fortiLinkRecipe) Key() string   { return RecipeKeyFortiLink }
func (fortiLinkRecipe) Label() string { return "Interface(s) -> FortiLink" }

func (fortiLinkRecipe) Applicable(cfg *FGConfig) (bool, string) { return true, "" }

func (r fortiLinkRecipe) Run(cfg *FGConfig, rawOpts json.RawMessage) ([]CLIBlock, []Warning, error) {
	var opts FortiLinkOptions
	if err := json.Unmarshal(rawOpts, &opts); err != nil {
		return nil, nil, fmt.Errorf("invalid options: %w", err)
	}
	if len(opts.MemberPorts) == 0 {
		return nil, nil, fmt.Errorf("at least one member port is required")
	}
	if opts.FortilinkName == "" {
		return nil, nil, fmt.Errorf("a FortiLink interface name is required")
	}

	var warnings []Warning

	// Expand "move every VLAN on this interface" selections into concrete VLAN
	// moves, each keeping its existing name and tag. Explicit moves win, so a
	// VLAN named both ways is only moved once. Sorted for stable CLI output.
	if len(opts.BulkVLANParents) > 0 {
		listed := make(map[string]bool, len(opts.VLANMoves))
		for _, m := range opts.VLANMoves {
			listed[m.Interface] = true
		}
		for _, parent := range opts.BulkVLANParents {
			if _, ok := cfg.Interfaces[parent]; !ok {
				return nil, nil, fmt.Errorf("bulk VLAN source %q not found in this configuration", parent)
			}
			var found []VLANMove
			for name, iface := range cfg.Interfaces {
				if iface.Type == "vlan" && iface.Parent == parent && iface.VLANID > 0 && !listed[name] {
					found = append(found, VLANMove{Interface: name, VLANID: iface.VLANID})
					listed[name] = true
				}
			}
			sort.Slice(found, func(i, j int) bool { return found[i].Interface < found[j].Interface })
			opts.VLANMoves = append(opts.VLANMoves, found...)
			if len(found) == 0 {
				warnings = append(warnings, Warning{
					Recipe: r.Key(),
					Detail: fmt.Sprintf("no VLANs are stacked on %q, so \"move all VLANs\" had nothing to move for it", parent),
				})
			}
		}
	}

	moveTargets := make(map[string]bool, len(opts.VLANMoves))
	for _, m := range opts.VLANMoves {
		moveTargets[m.Interface] = true
	}

	for _, p := range opts.MemberPorts {
		if moveTargets[p] {
			return nil, nil, fmt.Errorf("%q cannot be both a FortiLink member port and a VLAN move target", p)
		}
		iface, ok := cfg.Interfaces[p]
		if !ok {
			return nil, nil, fmt.Errorf("member port %q not found in this configuration", p)
		}
		if iface.IP != "" && iface.IP != "0.0.0.0 0.0.0.0" {
			return nil, nil, fmt.Errorf("member port %q has an IP configured (%s) -- add it as a VLAN move instead of a bare member port", p, iface.IP)
		}
		if refs := referencingPolicies(cfg, p); len(refs) > 0 {
			return nil, nil, fmt.Errorf("member port %q is referenced by polic(y/ies) %v -- add it as a VLAN move instead", p, refs)
		}
		if refs := referencingRoutes(cfg, p); len(refs) > 0 {
			return nil, nil, fmt.Errorf("member port %q is used as a static route device (seq %v) -- add it as a VLAN move instead", p, refs)
		}
		if z := zoneContaining(cfg, p); z != "" {
			return nil, nil, fmt.Errorf("member port %q already belongs to zone %q -- remove it from the zone first", p, z)
		}
	}

	var cli []CLIBlock

	// Pull member ports out of whatever switch they currently belong to.
	var pulled []string
	for _, p := range opts.MemberPorts {
		for name, iface := range cfg.Interfaces {
			if name == opts.FortilinkName || !containsStr(iface.Members, p) {
				continue
			}
			iface.Members = removeStr(iface.Members, p)
			if len(iface.Members) == 0 {
				warnings = append(warnings, Warning{
					Recipe: r.Key(), Section: "system interface",
					Detail: fmt.Sprintf("%q has no member ports left after moving %q onto the FortiLink -- review whether the now-empty switch/aggregate should be removed", name, p),
				})
			}
			pulled = append(pulled,
				"config system interface",
				fmt.Sprintf("    edit %q", name),
				fmt.Sprintf("        set member %s", quoteJoin(iface.Members)),
				"    next",
				"end",
			)
		}
	}
	if len(pulled) > 0 {
		cli = append(cli, CLIBlock{Recipe: r.Key(), Label: "Remove member ports from their current switch", Lines: pulled})
	}

	fl, exists := cfg.Interfaces[opts.FortilinkName]
	if opts.UseExisting {
		if !exists {
			return nil, nil, fmt.Errorf("FortiLink interface %q does not exist", opts.FortilinkName)
		}
		if !fl.Fortilink {
			return nil, nil, fmt.Errorf("interface %q is not a FortiLink interface (fortilink not enabled)", opts.FortilinkName)
		}
		fl.Members = dedupStr(append(append([]string(nil), fl.Members...), opts.MemberPorts...))
	} else {
		if exists {
			return nil, nil, fmt.Errorf("interface %q already exists -- pick a different name or use the existing-FortiLink option", opts.FortilinkName)
		}
		fl = &InterfaceEntry{
			Name:      opts.FortilinkName,
			Type:      "aggregate",
			Members:   append([]string(nil), opts.MemberPorts...),
			Fortilink: true,
		}
		cfg.Interfaces[opts.FortilinkName] = fl
	}
	cli = append(cli, CLIBlock{
		Recipe: r.Key(),
		Label:  fmt.Sprintf("FortiLink interface %q", opts.FortilinkName),
		Lines: []string{
			"config system interface",
			fmt.Sprintf("    edit %q", opts.FortilinkName),
			"        set type aggregate",
			fmt.Sprintf("        set member %s", quoteJoin(fl.Members)),
			"        set fortilink enable",
			"    next",
			"end",
		},
	})

	for _, mv := range opts.VLANMoves {
		iface, ok := cfg.Interfaces[mv.Interface]
		if !ok {
			return nil, nil, fmt.Errorf("VLAN move source %q not found in this configuration", mv.Interface)
		}
		if mv.VLANID <= 0 || mv.VLANID > 4094 {
			return nil, nil, fmt.Errorf("VLAN move for %q needs a VLAN ID between 1 and 4094, got %d", mv.Interface, mv.VLANID)
		}

		iface.Type = "vlan"
		iface.Parent = opts.FortilinkName
		iface.VLANID = mv.VLANID
		iface.Members = nil

		lines := []string{
			"config system interface",
			fmt.Sprintf("    edit %q", mv.Interface),
			fmt.Sprintf("        set interface %q", opts.FortilinkName),
			fmt.Sprintf("        set vlanid %d", mv.VLANID),
			"        set type vlan",
		}
		if iface.IP != "" {
			lines = append(lines, fmt.Sprintf("        set ip %s", iface.IP))
		}
		if iface.Allowaccess != "" {
			lines = append(lines, fmt.Sprintf("        set allowaccess %s", iface.Allowaccess))
		}
		if iface.Role != "" {
			lines = append(lines, fmt.Sprintf("        set role %s", iface.Role))
		}
		lines = append(lines, "    next", "end")
		cli = append(cli, CLIBlock{
			Recipe: r.Key(),
			Label:  fmt.Sprintf("Move %q onto FortiLink as VLAN %d", mv.Interface, mv.VLANID),
			Lines:  lines,
		})

		for _, hit := range ScanReferences(cfg, mv.Interface) {
			warnings = append(warnings, Warning{
				Recipe: r.Key(), Section: hit.Section, Line: hit.Line,
				Detail: fmt.Sprintf("%q keeps its name after moving onto the FortiLink as a VLAN, so this reference in %s (%s) stays valid -- no CLI change needed, just confirm it still behaves as intended", mv.Interface, hit.Section, hit.Edit),
			})
		}
	}

	for _, p := range opts.MemberPorts {
		for _, hit := range ScanReferences(cfg, p) {
			warnings = append(warnings, Warning{
				Recipe: r.Key(), Section: hit.Section, Line: hit.Line,
				Detail: fmt.Sprintf("%q is still referenced in %s (%s) after becoming a bare FortiLink member", p, hit.Section, hit.Edit),
			})
		}
	}

	return cli, warnings, nil
}
