package web

import (
	"regexp"
	"strconv"
	"strings"
)

// This file extracts the structured topology model (interfaces, routes,
// policies, managed switches, switch groups, zones, DHCP, SD-WAN, VPN, HA and
// wireless) from a configuration and derives the switch-to-switch interlinks
// shown on the topology page.

// Zone mirrors `config system zone`.
type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces,omitempty"`
}

// DhcpServer is one `config system dhcp server` entry.
type DhcpServer struct {
	ID        string   `json:"id"`
	Interface string   `json:"interface"`
	Gateway   string   `json:"gateway,omitempty"`
	Netmask   string   `json:"netmask,omitempty"`
	Ranges    []string `json:"ranges,omitempty"` // "start – end"
}

// SdwanMember is one `config system sdwan > config members` entry.
type SdwanMember struct {
	Seq       string `json:"seq"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway,omitempty"`
	Zone      string `json:"zone,omitempty"` // "" = default virtual-wan-link
}

// SdwanHealthCheck is one SD-WAN health check with its probed servers and the
// member sequence numbers it applies to.
type SdwanHealthCheck struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers,omitempty"`
	Members []string `json:"members,omitempty"`
}

// Sdwan is the parsed `config system sdwan` section (nil when absent).
type Sdwan struct {
	Status       string             `json:"status,omitempty"`
	Zones        []string           `json:"zones,omitempty"`
	Members      []SdwanMember      `json:"members,omitempty"`
	HealthChecks []SdwanHealthCheck `json:"health_checks,omitempty"`
}

// VpnTunnel is one `config vpn ipsec phase1-interface` entry.
type VpnTunnel struct {
	Name       string `json:"name"`
	Interface  string `json:"interface,omitempty"` // egress interface
	RemoteGw   string `json:"remote_gw,omitempty"`
	IkeVersion string `json:"ike_version,omitempty"`
}

// HAInfo is the parsed `config system ha` section (nil when absent or
// standalone).
type HAInfo struct {
	Mode      string   `json:"mode"`
	GroupName string   `json:"group_name,omitempty"`
	Hbdev     []string `json:"hbdev,omitempty"`   // heartbeat interfaces
	Monitor   []string `json:"monitor,omitempty"` // monitored interfaces
}

// FortiAP is one managed access point (`config wireless-controller wtp`).
type FortiAP struct {
	WtpID    string   `json:"wtp_id"` // serial
	Name     string   `json:"name,omitempty"`
	Profile  string   `json:"profile,omitempty"`
	Platform string   `json:"platform,omitempty"` // e.g. "231F"
	SSIDs    []string `json:"ssids,omitempty"`    // vap entry names via the profile
}

// WifiSSID is one `config wireless-controller vap` entry.
type WifiSSID struct {
	Name     string `json:"name"` // vap entry name (referenced by profiles)
	SSID     string `json:"ssid"` // broadcast name
	VlanID   int    `json:"vlan_id,omitempty"`
	Security string `json:"security,omitempty"`
}

// parsedConfig is everything parseConfigData extracts for the topology.
type parsedConfig struct {
	Interfaces   []Interface
	Routes       []StaticRoute
	Policies     []Policy
	Switches     []FortiSwitch
	SwitchGroups []SwitchGroup
	IslCustom    []IslBinding
	Zones        []Zone
	DhcpServers  []DhcpServer
	Sdwan        *Sdwan
	Vpns         []VpnTunnel
	HA           *HAInfo
	APs          []FortiAP
	SSIDs        []WifiSSID
}

// parseConfigData extracts structured details for topology mapping. It runs
// on the structural block scanner, so nested blocks (`config ipv6` inside an
// interface, `config igmp-snooping` inside a switch, VDOM wrapping) cannot
// derail section parsing — the previous line-based parser lost every
// interface/switch that followed the first nested block.
func parseConfigData(doc *cfgDoc) *parsedConfig {
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
		if v, _, ok := doc.settingDirect(b, "status"); ok {
			it.Status = strings.ToLower(v)
		}
		if v, _, ok := doc.settingDirect(b, "switch-controller-feature"); ok {
			it.SwitchFeature = strings.ToLower(v)
		}
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
			if v, _, ok := doc.settingDirect(pb, "status"); ok {
				p.Status = strings.ToLower(v)
			}
			if v, _, ok := doc.settingDirect(pb, "port-security-policy"); ok {
				p.SecurityPolicy = v
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

	// Auto-ISL trunk custom entries: FortiOS names auto-ISL trunks after the
	// PEER switch's serial fragment (e.g. "8EN0000000003-0" → peer serial
	// S108EN0000000003) and switch-binding records which switch the trunk
	// lives ON — a deterministic switch↔switch edge straight from the backup.
	var islCustom []IslBinding
	for _, b := range doc.blocksUnder("config switch-controller auto-config custom") {
		for _, sb := range doc.blocksUnder(b.Path + " > config switch-binding") {
			islCustom = append(islCustom, IslBinding{Trunk: b.Name, Switch: sb.Name})
		}
	}

	var zones []Zone
	for _, b := range doc.blocksUnder("config system zone") {
		zones = append(zones, Zone{Name: b.Name, Interfaces: doc.settingFields(b, "interface")})
	}

	var dhcp []DhcpServer
	for _, b := range doc.blocksUnder("config system dhcp server") {
		d := DhcpServer{ID: b.Name}
		if v, _, ok := doc.settingDirect(b, "interface"); ok {
			d.Interface = v
		}
		if v, _, ok := doc.settingDirect(b, "default-gateway"); ok {
			d.Gateway = v
		}
		if v, _, ok := doc.settingDirect(b, "netmask"); ok {
			d.Netmask = v
		}
		for _, rb := range doc.blocksUnder(b.Path + " > config ip-range") {
			start, _, _ := doc.settingDirect(rb, "start-ip")
			end, _, _ := doc.settingDirect(rb, "end-ip")
			if start != "" || end != "" {
				d.Ranges = append(d.Ranges, start+" – "+end)
			}
		}
		if d.Interface != "" {
			dhcp = append(dhcp, d)
		}
	}

	var sdwan *Sdwan
	if b, ok := doc.block("config system sdwan"); ok {
		sd := &Sdwan{}
		if v, _, sok := doc.settingDirect(b, "status"); sok {
			sd.Status = strings.ToLower(v)
		}
		for _, zb := range doc.blocksUnder(b.Path + " > config zone") {
			sd.Zones = append(sd.Zones, zb.Name)
		}
		for _, mb := range doc.blocksUnder(b.Path + " > config members") {
			m := SdwanMember{Seq: mb.Name}
			if v, _, mok := doc.settingDirect(mb, "interface"); mok {
				m.Interface = v
			}
			if v, _, mok := doc.settingDirect(mb, "gateway"); mok {
				m.Gateway = v
			}
			if v, _, mok := doc.settingDirect(mb, "zone"); mok {
				m.Zone = v
			}
			if m.Interface != "" {
				sd.Members = append(sd.Members, m)
			}
		}
		for _, hb := range doc.blocksUnder(b.Path + " > config health-check") {
			sd.HealthChecks = append(sd.HealthChecks, SdwanHealthCheck{
				Name:    hb.Name,
				Servers: doc.settingFields(hb, "server"),
				Members: doc.settingFields(hb, "members"),
			})
		}
		if len(sd.Members) > 0 || len(sd.Zones) > 0 {
			sdwan = sd
		}
	}

	var vpns []VpnTunnel
	for _, b := range doc.blocksUnder("config vpn ipsec phase1-interface") {
		t := VpnTunnel{Name: b.Name}
		if v, _, ok := doc.settingDirect(b, "interface"); ok {
			t.Interface = v
		}
		if v, _, ok := doc.settingDirect(b, "remote-gw"); ok {
			t.RemoteGw = v
		}
		if v, _, ok := doc.settingDirect(b, "ike-version"); ok {
			t.IkeVersion = v
		}
		vpns = append(vpns, t)
	}

	var ha *HAInfo
	if b, ok := doc.block("config system ha"); ok {
		if mode, _, mok := doc.settingDirect(b, "mode"); mok && !strings.EqualFold(mode, "standalone") {
			h := &HAInfo{Mode: strings.ToLower(mode)}
			if v, _, hok := doc.settingDirect(b, "group-name"); hok {
				h.GroupName = v
			}
			// hbdev alternates interface names and priorities: keep the names.
			for _, f := range doc.settingFields(b, "hbdev") {
				if _, err := strconv.Atoi(f); err != nil {
					h.Hbdev = append(h.Hbdev, f)
				}
			}
			h.Monitor = doc.settingFields(b, "monitor")
			ha = h
		}
	}

	var ssids []WifiSSID
	for _, b := range doc.blocksUnder("config wireless-controller vap") {
		s := WifiSSID{Name: b.Name}
		if v, _, ok := doc.settingDirect(b, "ssid"); ok {
			s.SSID = v
		}
		if v, _, ok := doc.settingDirect(b, "vlanid"); ok {
			s.VlanID, _ = strconv.Atoi(v)
		}
		if v, _, ok := doc.settingDirect(b, "security"); ok {
			s.Security = strings.ToLower(v)
		}
		ssids = append(ssids, s)
	}

	// WTP profiles: platform type and the union of the radios' vap lists
	// (`set vaps` lives in nested `config radio-N` blocks).
	type profileInfo struct {
		platform string
		vaps     []string
	}
	profiles := map[string]profileInfo{}
	for _, b := range doc.blocksUnder("config wireless-controller wtp-profile") {
		pi := profileInfo{}
		seenVap := map[string]bool{}
		for _, line := range doc.findAllInBlock(b, "set type ") {
			pi.platform = strings.Trim(strings.TrimSpace(line[len("set type "):]), `"'`)
			break
		}
		for _, line := range doc.findAllInBlock(b, "set vaps ") {
			for _, v := range splitCfgValues(line[len("set vaps "):]) {
				if !seenVap[v] {
					seenVap[v] = true
					pi.vaps = append(pi.vaps, v)
				}
			}
		}
		profiles[b.Name] = pi
	}

	var aps []FortiAP
	for _, b := range doc.blocksUnder("config wireless-controller wtp") {
		ap := FortiAP{WtpID: b.Name}
		if v, _, ok := doc.settingDirect(b, "name"); ok {
			ap.Name = v
		}
		if v, _, ok := doc.settingDirect(b, "wtp-profile"); ok {
			ap.Profile = v
		}
		if pi, ok := profiles[ap.Profile]; ok {
			ap.Platform = pi.platform
			ap.SSIDs = pi.vaps
		}
		aps = append(aps, ap)
	}

	return &parsedConfig{
		Interfaces:   interfaces,
		Routes:       routes,
		Policies:     policies,
		Switches:     switches,
		SwitchGroups: groups,
		IslCustom:    islCustom,
		Zones:        zones,
		DhcpServers:  dhcp,
		Sdwan:        sdwan,
		Vpns:         vpns,
		HA:           ha,
		APs:          aps,
		SSIDs:        ssids,
	}
}

// reFswSerial matches FortiSwitch serial prefixes, e.g. "S524DN…" → model
// digits 524, model letter D, variant letters (P = PoE).
var reFswSerial = regexp.MustCompile(`^S(\d{3})([A-Z])([A-Z]*)`)

// fswModelFromSerial derives a display model from the serial number:
// "S524DN0000000001" → "FS-524D", "S424EP0000001234" → "FS-424E-POE".
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

// reTrunkSuffix strips the trailing "-N" trunk index from an auto-ISL trunk
// name, leaving the peer-serial fragment ("8EN0000000003-0" → "8EN0000000003").
var reTrunkSuffix = regexp.MustCompile(`-\d+$`)

// switchByRef finds a switch by any of its identities (name / edit key /
// serial), or by serial SUFFIX when ref is an auto-ISL trunk fragment (FortiOS
// truncates the peer serial when naming the trunk).
func switchByRef(switches []FortiSwitch, ref string) *FortiSwitch {
	if ref == "" {
		return nil
	}
	for i := range switches {
		if switches[i].Name == ref || switches[i].SwitchID == ref || switches[i].Serial == ref {
			return &switches[i]
		}
	}
	frag := strings.ToUpper(reTrunkSuffix.ReplaceAllString(ref, ""))
	if len(frag) >= 8 {
		for i := range switches {
			if strings.HasSuffix(strings.ToUpper(switches[i].Serial), frag) {
				return &switches[i]
			}
		}
	}
	return nil
}

// buildSwitchLinks derives switch interlinks from the parsed switches.
// Config backups carry no live LLDP neighbor table, so three signals are used:
//
//  1. Persisted auto-ISL/ICL trunk entries (`set isl-peer-device-name` /
//     `set isl-peer-port-name`) — exact, including the peer port.
//  2. Auto-config custom trunk bindings (`config switch-controller auto-config
//     custom`): the trunk name carries the PEER's serial fragment and the
//     switch-binding names the switch the trunk lives on.
//  3. MC-LAG ICL port profiles: two switches carrying ICL-profiled ports form
//     an MC-LAG peer pair and those ports are the ICL. With more than two
//     ICL switches (several MC-LAG pairs in one fabric) the peers are paired
//     within their switch-group — MC-LAG peers always share one.
//
// Links reported by both sides are deduplicated (side order ignored).
func buildSwitchLinks(switches []FortiSwitch, groups []SwitchGroup, islCustom []IslBinding) []SwitchLink {
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

	// Signal 2 first: exact edges recorded by the config itself.
	for _, ib := range islCustom {
		owner := switchByRef(switches, ib.Switch)
		peer := switchByRef(switches, ib.Trunk)
		if owner == nil || peer == nil || owner == peer {
			continue
		}
		add(SwitchLink{
			From: switchDisplayName(*owner), FromPorts: []string{ib.Trunk},
			To: switchDisplayName(*peer), Kind: "isl",
		})
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
		keys  map[string]bool // switch-id / serial / name, for group-member matching
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
			keys := map[string]bool{}
			for _, k := range []string{sw.SwitchID, sw.Serial, sw.Name} {
				if k != "" {
					keys[k] = true
				}
			}
			sides = append(sides, iclSide{name: switchDisplayName(sw), keys: keys, ports: ports})
		}
	}
	pairICL := func(a, b iclSide) {
		add(SwitchLink{From: a.name, FromPorts: a.ports, To: b.name, ToPorts: b.ports, Kind: "mclag-icl"})
	}
	switch {
	case len(sides) == 2:
		pairICL(sides[0], sides[1])
	case len(sides) > 2:
		// Several ICL-carrying switches — e.g. two MC-LAG pairs in one fabric.
		// MC-LAG peers always share a switch-group, so pair within each group
		// that contains exactly two ICL sides (a global "exactly 2" would
		// otherwise yield no links at all).
		for _, g := range groups {
			var grouped []iclSide
			for _, s := range sides {
				for _, m := range g.Members {
					if s.keys[m] {
						grouped = append(grouped, s)
						break
					}
				}
			}
			if len(grouped) == 2 {
				pairICL(grouped[0], grouped[1])
			}
		}
	}
	return links
}
