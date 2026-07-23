package fgt_confconv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	// FortilinkIP is the FortiLink management subnet (e.g. "10.255.1.1
	// 255.255.255.0") set on a newly-created FortiLink so managed FortiSwitches
	// get DHCP addresses. Optional; ignored when adding to an existing FortiLink.
	FortilinkIP string `json:"fortilink_ip"`
	// DualHomed enables fortilink-split-interface -- set only when the aggregate
	// is split across two switches (MC-LAG). A plain LAG to one switch leaves it
	// disabled.
	DualHomed bool `json:"dual_homed"`
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

	// Track how each interface changes; the section is emitted whole at the end
	// so unchanged interfaces come through verbatim and the FortiLink lands
	// above the VLANs that reference it.
	emptied := map[string]bool{}       // switch left memberless -> deleted
	memberChanged := map[string]bool{} // switch whose member list we rewrote

	// Pull the chosen member ports out of whatever switch/aggregate they
	// currently belong to.
	for _, p := range opts.MemberPorts {
		for name, iface := range cfg.Interfaces {
			if name == opts.FortilinkName || !containsStr(iface.Members, p) {
				continue
			}
			iface.Members = removeStr(iface.Members, p)
			memberChanged[name] = true
		}
	}
	for name := range memberChanged {
		if len(cfg.Interfaces[name].Members) == 0 {
			delete(memberChanged, name)
			emptied[name] = true
			warnings = append(warnings, Warning{
				Recipe: r.Key(), Section: "system interface",
				Detail: fmt.Sprintf("%q has no member ports left after moving them onto the FortiLink and is deleted in the output -- re-point anything still using it", name),
			})
		}
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

	// The device generates the rest of a FortiLink setup itself once the switch
	// is authorized, so flag that path rather than emitting objects that would
	// clash with the auto-created ones.
	if !opts.UseExisting {
		detail := fmt.Sprintf("authorize the FortiSwitch on %q under \"config switch-controller managed-switch\" (or via the GUI) after applying -- FortiOS then auto-creates the FortiLink management address, policy, NAC, switch-group and link-monitor objects (device-generated, not part of this script)", opts.FortilinkName)
		if strings.TrimSpace(opts.FortilinkIP) == "" {
			detail += ". No FortiLink management subnet was set; add \"set ip <addr> <mask>\" unless FortiOS auto-assigns one your switches can DHCP from"
		}
		warnings = append(warnings, Warning{Recipe: r.Key(), Detail: detail})
	}

	vlanMoved := map[string]bool{}
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
		vlanMoved[mv.Interface] = true

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

	// Emit the whole `config system interface` section as one block: deletions
	// first, then every non-VLAN interface (member ports + the FortiLink), then
	// the VLANs -- so a parent always precedes the interfaces referencing it.
	order := cfg.InterfaceOrder
	if len(order) == 0 { // e.g. a model built by hand in tests
		for name := range cfg.Interfaces {
			order = append(order, name)
		}
		sort.Strings(order)
	}

	block := []string{"config system interface"}
	var deletes []string
	for name := range emptied {
		deletes = append(deletes, name)
	}
	sort.Strings(deletes)
	for _, name := range deletes {
		block = append(block, fmt.Sprintf("    delete %q", name))
	}

	var vlanNames []string
	for _, name := range order {
		iface := cfg.Interfaces[name]
		if iface == nil || emptied[name] {
			continue
		}
		if name == opts.FortilinkName && !opts.UseExisting {
			continue // the new FortiLink is placed explicitly, below
		}
		if iface.Type == "vlan" {
			vlanNames = append(vlanNames, name)
			continue
		}
		block = append(block, emitFortiLinkIface(iface, opts, memberChanged, vlanMoved, fl)...)
	}
	if !opts.UseExisting {
		block = append(block, newFortiLinkEdit(opts, fl)...)
	}
	for _, name := range vlanNames {
		block = append(block, emitFortiLinkIface(cfg.Interfaces[name], opts, memberChanged, vlanMoved, fl)...)
	}
	block = append(block, "end")

	cli := []CLIBlock{{
		Recipe: r.Key(),
		Label:  fmt.Sprintf("config system interface (full section, FortiLink %q)", opts.FortilinkName),
		Lines:  reindent(block),
	}}
	return cli, warnings, nil
}

// reindent normalises a config block to standard FortiGate indentation (four
// spaces per config/edit level). SCP backups come through unindented, and the
// recipe mixes verbatim source lines with generated ones, so this gives one
// consistent, readable block. FortiOS ignores the indentation on paste anyway.
func reindent(lines []string) []string {
	out := make([]string, 0, len(lines))
	depth := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			out = append(out, "")
			continue
		}
		if (t == "next" || t == "end") && depth > 0 {
			depth--
		}
		out = append(out, strings.Repeat("    ", depth)+t)
		if strings.HasPrefix(t, "config ") || strings.HasPrefix(t, "edit ") {
			depth++
		}
	}
	return out
}

// emitFortiLinkIface returns one interface's `edit ... next` lines for the
// consolidated section: verbatim when untouched, or with the single changed
// line rewritten (a switch's member list, or a moved VLAN's parent), preserving
// every other setting the parser does not model.
func emitFortiLinkIface(iface *InterfaceEntry, opts FortiLinkOptions, memberChanged, vlanMoved map[string]bool, fl *InterfaceEntry) []string {
	base := ifaceBlock(iface)
	switch {
	case iface.Name == opts.FortilinkName && opts.UseExisting:
		out, ok := replaceSetLine(base, "member", quoteJoin(fl.Members))
		if !ok {
			out = insertBeforeNext(base, "        set member "+quoteJoin(fl.Members))
		}
		return out
	case memberChanged[iface.Name]:
		out, _ := replaceSetLine(base, "member", quoteJoin(iface.Members))
		return out
	case vlanMoved[iface.Name]:
		out, ok := replaceSetLine(base, "interface", fmt.Sprintf("%q", opts.FortilinkName))
		if !ok {
			out = insertBeforeNext(base, fmt.Sprintf("        set interface %q", opts.FortilinkName))
		}
		return out
	default:
		return base
	}
}

// newFortiLinkEdit builds the `edit ... next` for a freshly-created FortiLink
// aggregate (fabric access, LLDP, split-interface, optional management IP).
func newFortiLinkEdit(opts FortiLinkOptions, fl *InterfaceEntry) []string {
	split := "disable"
	if opts.DualHomed {
		split = "enable"
	}
	lines := []string{
		fmt.Sprintf("    edit %q", opts.FortilinkName),
		"        set type aggregate",
		fmt.Sprintf("        set member %s", quoteJoin(fl.Members)),
		"        set fortilink enable",
		fmt.Sprintf("        set fortilink-split-interface %s", split),
		"        set allowaccess ping fabric",
		"        set lldp-reception enable",
		"        set lldp-transmission enable",
	}
	if ip := strings.TrimSpace(opts.FortilinkIP); ip != "" {
		lines = append(lines, fmt.Sprintf("        set ip %s", ip))
	}
	return append(lines, "    next")
}

// ifaceBlock returns the interface's verbatim `edit ... next` block, or rebuilds
// a minimal one from the modeled fields when no raw text was captured (chiefly
// hand-built configs in tests).
func ifaceBlock(iface *InterfaceEntry) []string {
	if len(iface.Raw) > 0 {
		return iface.Raw
	}
	lines := []string{fmt.Sprintf("    edit %q", iface.Name)}
	if iface.Type != "" {
		lines = append(lines, fmt.Sprintf("        set type %s", iface.Type))
	}
	if iface.VLANID > 0 {
		lines = append(lines, fmt.Sprintf("        set vlanid %d", iface.VLANID))
	}
	if iface.Parent != "" {
		lines = append(lines, fmt.Sprintf("        set interface %q", iface.Parent))
	}
	if len(iface.Members) > 0 {
		lines = append(lines, fmt.Sprintf("        set member %s", quoteJoin(iface.Members)))
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
	if iface.Fortilink {
		lines = append(lines, "        set fortilink enable")
	}
	for _, l := range iface.Lines {
		lines = append(lines, "        "+l)
	}
	return append(lines, "    next")
}

// replaceSetLine rewrites the first top-level `set <key> ...` line in an
// interface block (nested blocks never carry `set member`/`set interface`, so
// the first match is the interface-level one), preserving indentation.
func replaceSetLine(block []string, key, newValue string) ([]string, bool) {
	prefix := "set " + key + " "
	out := make([]string, len(block))
	copy(out, block)
	for i, l := range out {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			indent := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
			out[i] = indent + "set " + key + " " + newValue
			return out, true
		}
	}
	return out, false
}

// insertBeforeNext inserts a line just before the block's closing `next`.
func insertBeforeNext(block []string, newLine string) []string {
	for i := len(block) - 1; i >= 0; i-- {
		if strings.TrimSpace(block[i]) == "next" {
			out := make([]string, 0, len(block)+1)
			out = append(out, block[:i]...)
			out = append(out, newLine)
			out = append(out, block[i:]...)
			return out
		}
	}
	return append(block, newLine)
}
