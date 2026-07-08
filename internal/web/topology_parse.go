package web

import (
	"regexp"
	"strconv"
	"strings"
)

// This file extracts the structured topology model (interfaces, routes,
// policies, managed switches, switch groups) from a configuration and derives
// the switch-to-switch interlinks shown on the topology page.

// parseConfigData extracts structured details for topology mapping. It runs
// on the structural block scanner, so nested blocks (`config ipv6` inside an
// interface, `config igmp-snooping` inside a switch, VDOM wrapping) cannot
// derail section parsing — the previous line-based parser lost every
// interface/switch that followed the first nested block.
func parseConfigData(doc *cfgDoc) ([]Interface, []StaticRoute, []Policy, []FortiSwitch, []SwitchGroup) {
	var interfaces []Interface
	for _, b := range doc.blocksUnder("config system interface") {
		it := Interface{Name: b.Name}
		if v, _, ok := doc.settingDirect(b, "ip"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				it.IP = f[0]
				if len(f) > 1 {
					it.Mask = f[1]
				}
			}
		}
		it.AllowAccess = doc.settingFields(b, "allowaccess")
		if v, _, ok := doc.settingDirect(b, "vlanid"); ok {
			it.VlanID, _ = strconv.Atoi(v)
		}
		if v, _, ok := doc.settingDirect(b, "interface"); ok {
			it.Interface = v
		}
		if v, _, ok := doc.settingDirect(b, "role"); ok {
			it.Role = strings.ToLower(v)
		}
		if v, _, ok := doc.settingDirect(b, "alias"); ok {
			it.Alias = v
		}
		it.Members = doc.settingFields(b, "member")
		interfaces = append(interfaces, it)
	}

	var routes []StaticRoute
	for _, b := range doc.blocksUnder("config router static") {
		r := StaticRoute{ID: b.Name}
		if v, _, ok := doc.settingDirect(b, "dst"); ok {
			r.Dst = v
		}
		if v, _, ok := doc.settingDirect(b, "gateway"); ok {
			r.Gateway = v
		}
		if v, _, ok := doc.settingDirect(b, "device"); ok {
			r.Device = v
		}
		routes = append(routes, r)
	}

	var policies []Policy
	for _, b := range doc.blocksUnder("config firewall policy") {
		id, _ := strconv.Atoi(b.Name)
		p := Policy{
			ID:      id,
			SrcIntf: doc.settingFields(b, "srcintf"),
			DstIntf: doc.settingFields(b, "dstintf"),
			SrcAddr: doc.settingFields(b, "srcaddr"),
			DstAddr: doc.settingFields(b, "dstaddr"),
			Service: doc.settingFields(b, "service"),
		}
		if v, _, ok := doc.settingDirect(b, "action"); ok {
			p.Action = v
		}
		policies = append(policies, p)
	}

	var switches []FortiSwitch
	for _, b := range doc.blocksUnder("config switch-controller managed-switch") {
		sw := FortiSwitch{SwitchID: b.Name}
		if v, _, ok := doc.settingDirect(b, "name"); ok {
			sw.Name = v
		}
		if v, _, ok := doc.settingDirect(b, "sn"); ok {
			sw.Serial = v
		}
		if v, _, ok := doc.settingDirect(b, "description"); ok {
			sw.Description = v
		}
		if v, _, ok := doc.settingDirect(b, "fsw-wan1-peer"); ok {
			sw.Fortilink = v
		}
		// Older exports key the switch entry by its serial number instead of
		// carrying a `set sn`.
		if sw.Serial == "" && len(sw.SwitchID) >= 12 && reFswSerial.MatchString(strings.ToUpper(sw.SwitchID)) {
			sw.Serial = sw.SwitchID
		}
		sw.Model = fswModelFromSerial(sw.Serial)

		for _, pb := range doc.blocksUnder(b.Path + " > config ports") {
			p := SwitchPort{Name: pb.Name}
			if v, _, ok := doc.settingDirect(pb, "vlan"); ok {
				p.Vlan = v
			}
			if v, _, ok := doc.settingDirect(pb, "description"); ok {
				p.Description = v
			}
			if v, _, ok := doc.settingDirect(pb, "mac-addr"); ok {
				p.Mac = strings.ToLower(v)
			}
			if v, _, ok := doc.settingDirect(pb, "lldp-profile"); ok {
				p.LldpProfile = v
			}
			if v, _, ok := doc.settingDirect(pb, "speed"); ok {
				p.Speed = v
			}
			p.AllowedVlans = doc.settingFields(pb, "allowed-vlans")
			if v, _, ok := doc.settingDirect(pb, "allowed-vlans-all"); ok && strings.EqualFold(v, "enable") {
				p.AllowedVlansAll = true
			}
			if v, _, ok := doc.settingDirect(pb, "type"); ok {
				p.Type = strings.ToLower(v)
			}
			p.Members = doc.settingFields(pb, "members")
			if v, _, ok := doc.settingDirect(pb, "mclag-icl"); ok && strings.EqualFold(v, "enable") {
				p.MclagIcl = true
			}
			if v, _, ok := doc.settingDirect(pb, "isl-peer-device-name"); ok {
				p.IslPeerDevice = v
			}
			if v, _, ok := doc.settingDirect(pb, "isl-peer-port-name"); ok {
				p.IslPeerPort = v
			}
			sw.Ports = append(sw.Ports, p)
		}
		switches = append(switches, sw)
	}

	var groups []SwitchGroup
	for _, b := range doc.blocksUnder("config switch-controller switch-group") {
		g := SwitchGroup{Name: b.Name}
		if v, _, ok := doc.settingDirect(b, "fortilink"); ok {
			g.Fortilink = v
		}
		g.Members = doc.settingFields(b, "members")
		groups = append(groups, g)
	}

	return interfaces, routes, policies, switches, groups
}

// reFswSerial matches FortiSwitch serial prefixes, e.g. "S524DN…" → model
// digits 524, model letter D, variant letters (P = PoE).
var reFswSerial = regexp.MustCompile(`^S(\d{3})([A-Z])([A-Z]*)`)

// fswModelFromSerial derives a display model from the serial number:
// "S524DN5020000043" → "FS-524D", "S424EPTF19001234" → "FS-424E-POE".
func fswModelFromSerial(serial string) string {
	m := reFswSerial.FindStringSubmatch(strings.ToUpper(serial))
	if m == nil {
		return ""
	}
	model := "FS-" + m[1] + m[2]
	if strings.HasPrefix(m[3], "P") {
		model += "-POE"
	}
	return model
}

// SwitchLink is one detected switch-to-switch interlink.
type SwitchLink struct {
	From      string   `json:"from"`
	FromPorts []string `json:"from_ports,omitempty"`
	To        string   `json:"to"`
	ToPorts   []string `json:"to_ports,omitempty"`
	Kind      string   `json:"kind"` // "mclag-icl" | "isl"
}

// switchDisplayName is the node name the topology tree uses for a switch.
func switchDisplayName(sw FortiSwitch) string {
	if sw.Name != "" {
		return sw.Name
	}
	return sw.SwitchID
}

// isIclPort reports whether a port carries the MC-LAG inter-chassis link:
// either flagged explicitly on a trunk or marked by the auto-assigned
// "…mclag-icl" LLDP profile.
func isIclPort(p SwitchPort) bool {
	return p.MclagIcl || strings.Contains(strings.ToLower(p.LldpProfile), "mclag-icl")
}

// buildSwitchLinks derives switch interlinks from the parsed switches.
// Config backups carry no live LLDP neighbor table, so two signals are used:
//
//  1. Persisted auto-ISL/ICL trunk entries (`set isl-peer-device-name` /
//     `set isl-peer-port-name`) — exact, including the peer port.
//  2. MC-LAG ICL port profiles: when exactly two switches carry ICL-profiled
//     ports, they form the MC-LAG peer pair and those ports are the ICL.
//
// Links reported by both sides are deduplicated (side order ignored).
func buildSwitchLinks(switches []FortiSwitch) []SwitchLink {
	var links []SwitchLink
	seen := map[string]bool{}
	add := func(l SwitchLink) {
		a := l.From + "|" + strings.Join(l.FromPorts, ",")
		b := l.To + "|" + strings.Join(l.ToPorts, ",")
		if b < a {
			a, b = b, a
		}
		key := l.Kind + "|" + a + "|" + b
		if seen[key] {
			return
		}
		seen[key] = true
		links = append(links, l)
	}

	for _, sw := range switches {
		for _, p := range sw.Ports {
			if p.IslPeerDevice == "" {
				continue
			}
			ports := p.Members
			if len(ports) == 0 {
				ports = []string{p.Name}
			}
			var toPorts []string
			if p.IslPeerPort != "" {
				toPorts = []string{p.IslPeerPort}
			}
			kind := "isl"
			if isIclPort(p) {
				kind = "mclag-icl"
			}
			add(SwitchLink{From: switchDisplayName(sw), FromPorts: ports, To: p.IslPeerDevice, ToPorts: toPorts, Kind: kind})
		}
	}

	type iclSide struct {
		name  string
		ports []string
	}
	var sides []iclSide
	for _, sw := range switches {
		var ports []string
		seenPort := map[string]bool{}
		addPort := func(name string) {
			if name == "" || seenPort[name] {
				return
			}
			seenPort[name] = true
			ports = append(ports, name)
		}
		for _, p := range sw.Ports {
			if !isIclPort(p) || p.IslPeerDevice != "" {
				continue
			}
			// ICL trunks without persisted peer info still mark the pair; their
			// physical ports are the members (the member ports often carry the
			// ICL LLDP profile too — deduplicated via addPort).
			if p.Type == "trunk" && len(p.Members) > 0 {
				for _, m := range p.Members {
					addPort(m)
				}
				continue
			}
			addPort(p.Name)
		}
		if len(ports) > 0 {
			sides = append(sides, iclSide{name: switchDisplayName(sw), ports: ports})
		}
	}
	if len(sides) == 2 {
		add(SwitchLink{From: sides[0].name, FromPorts: sides[0].ports, To: sides[1].name, ToPorts: sides[1].ports, Kind: "mclag-icl"})
	}
	return links
}
