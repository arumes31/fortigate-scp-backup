package graylogdevicedata

import (
	"regexp"
	"strconv"
	"strings"
)

// This file parses the FortiGate CLI diagnostics used for the live port overlay.
// Commands (verified against FortiOS 7.6 with a read-only admin — note the
// two-level ones need a sub-action before the switch name):
//
//	switch-info status                  → managed-switch inventory (name ↔ serial)
//	switch-info port-stats <sw>         → link up/down, SW-admin, speed/duplex, error counters
//	switch-info stp <sw>                → per-port role/state + guard flags + interlink trunk rows
//	switch-info port-properties <sw>    → connector/media (RJ45/SFP+/QSFP) + PoE capability
//	switch-info poe summary <sw>        → per-port PoE state / draw / class
//	switch-info modules summary <sw>    → SFP/QSFP transceiver present/type
//	switch-info mac-table               → MAC → VLAN → physical port (device pinning)
//	switch-info 802.1X <sw>             → per-port 802.1X authorization state
//
// Everything is free-text, so the parsers are line-oriented and tolerant: they
// key on the stable tokens and ignore anything that does not match.

func atoiSafe(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

func atofSafe(s string) float64 { f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return f }

func atoi64(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

// fmtSpeed turns a Mb/s figure into a compact label (1000 → "1G").
func fmtSpeed(mbps string) string {
	switch mbps {
	case "10":
		return "10M"
	case "100":
		return "100M"
	case "1000":
		return "1G"
	case "2500":
		return "2.5G"
	case "5000":
		return "5G"
	case "10000":
		return "10G"
	case "25000":
		return "25G"
	case "40000":
		return "40G"
	case "100000":
		return "100G"
	default:
		return mbps + "M"
	}
}

// diagSwitch is one managed switch from `switch-info status`.
type diagSwitch struct {
	Name   string
	Serial string
}

var (
	reInvSwitch = regexp.MustCompile(`(?m)^Managed Switch\s*:\s*(\S+)`)
	reInvSerial = regexp.MustCompile(`(?m)^Serial-Number:\s*(\S+)`)
	reInvHost   = regexp.MustCompile(`(?m)^Hostname:\s*(\S+)`)
)

// parseSwitchInventory returns the managed switches, each with the friendly name
// (Hostname, the identifier the config/faceplate use) and serial.
func parseSwitchInventory(out string) []diagSwitch {
	locs := reInvSwitch.FindAllStringSubmatchIndex(out, -1)
	res := make([]diagSwitch, 0, len(locs))
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		sw := diagSwitch{Name: out[loc[2]:loc[3]]}
		if m := reInvSerial.FindStringSubmatch(block); m != nil {
			sw.Serial = m[1]
		}
		if m := reInvHost.FindStringSubmatch(block); m != nil {
			sw.Name = m[1] // Hostname is the canonical friendly name
		}
		if sw.Name != "" {
			res = append(res, sw)
		}
	}
	return res
}

// diagPortStat is the live per-port state from `switch-info port-stats <sw>`.
type diagPortStat struct {
	Up       bool   // line protocol up
	AdminUp  bool   // SW Admin up (false = administratively shut)
	Speed    string // negotiated "1G/full" on up ports
	Health   string // nonzero fault counters, e.g. "err:2 col:9"; "" = clean
	Half     bool   // negotiated half-duplex (a fault on a modern link)
	SpeedM   int    // negotiated speed in Mbps (0 = unknown/down)
	Errors   int    // cumulative rx+tx error counter (for the error-rate delta)
	Discards int    // cumulative rx+tx drop counter
}

var (
	rePortLink   = regexp.MustCompile(`Port\((\S+?)\) is HW Admin (?:up|down), SW Admin (up|down), line protocol is (up|down)`)
	rePortDuplex = regexp.MustCompile(`\b(full|half)-duplex,\s*(\d+)\s*Mb/s`)
	rePortInOut  = regexp.MustCompile(`(?m)^\s*(?:input|output)\s*:.*?(\d+)\s+errors,\s*(\d+)\s+drops,\s*(\d+)\s+oversizes`)
	rePortMisc   = regexp.MustCompile(`(\d+)\s+fragments,\s*(\d+)\s+undersizes,\s*(\d+)\s+collisions,\s*(\d+)\s+jabbers`)
)

// joinHealth builds a compact "label:count" summary of the nonzero fault
// counters (drops deliberately excluded — normal flood on uplinks, not a fault).
func joinHealth(err, ovr, frag, undr, col, jab int) string {
	var p []string
	add := func(label string, n int) {
		if n > 0 {
			p = append(p, label+":"+strconv.Itoa(n))
		}
	}
	add("err", err)
	add("ovr", ovr)
	add("frag", frag)
	add("undr", undr)
	add("col", col)
	add("jab", jab)
	return strings.Join(p, " ")
}

// parsePortStats returns the live state of every physical port: link, SW-admin,
// negotiated speed/duplex (up ports only — down ports report a stale
// half-duplex line), and a fault-counter health summary.
func parsePortStats(out string) map[string]diagPortStat {
	type acc struct {
		diagPortStat
		err, ovr, frag, undr, col, jab, drp int
	}
	m := map[string]*acc{}
	cur := ""
	for _, ln := range strings.Split(out, "\n") {
		if h := rePortLink.FindStringSubmatch(ln); h != nil {
			cur = h[1]
			m[cur] = &acc{diagPortStat: diagPortStat{AdminUp: h[2] == "up", Up: h[3] == "up"}}
			continue
		}
		a := m[cur]
		if a == nil {
			continue
		}
		if a.Up {
			if d := rePortDuplex.FindStringSubmatch(ln); d != nil {
				a.Speed = fmtSpeed(d[2]) + "/" + d[1]
				a.Half = d[1] == "half"
				a.SpeedM = atoiSafe(d[2])
			}
		}
		if io := rePortInOut.FindStringSubmatch(ln); io != nil {
			a.err += atoiSafe(io[1])
			a.drp += atoiSafe(io[2])
			a.ovr += atoiSafe(io[3])
		}
		if mm := rePortMisc.FindStringSubmatch(ln); mm != nil {
			a.frag += atoiSafe(mm[1])
			a.undr += atoiSafe(mm[2])
			a.col += atoiSafe(mm[3])
			a.jab += atoiSafe(mm[4])
		}
	}
	res := make(map[string]diagPortStat, len(m))
	for port, a := range m {
		a.Health = joinHealth(a.err, a.ovr, a.frag, a.undr, a.col, a.jab)
		a.Errors = a.err + a.ovr + a.frag + a.undr + a.col + a.jab
		a.Discards = a.drp
		res[port] = a.diagPortStat
	}
	return res
}

// diagStpPort is one physical port's STP role/state/guard from `switch-info stp`.
type diagStpPort struct {
	Port  string
	Role  string // designated | root | alternate | backup | disabled | master
	State string // forwarding | discarding | learning | blocking | listening
	Guard string // bpdu-guard/root-guard/loop-guard when the Flags column shows BG/RG/LP
}

// diagEdge is one interlink trunk observed in the STP table. Role orients the
// edge (root = uplink); State marks a blocked redundant link (discarding).
type diagEdge struct {
	Trunk string
	Role  string
	State string
}

var (
	// FortiSwitch prints the STP alternate role as "ALTERNATIVE"; accept both and
	// normalize to "alternate" (the value the frontend's blocked logic checks).
	reStpRole  = regexp.MustCompile(`(?i)^(designated|root|alternat(?:e|ive)|backup|disabled|master)$`)
	reStpState = regexp.MustCompile(`(?i)^(forwarding|discarding|learning|blocking|listening)$`)
)

// parseStp parses the STP table into per-physical-port role/state/guard and the
// interlink trunk rows. A row is accepted only when it carries BOTH a role and a
// state keyword. Physical ports (portN) feed the overlay; trunk-named rows (not
// portN, excluding the FGT-facing "internal") feed interlink detection.
func parseStp(out string) (map[string]diagStpPort, []diagEdge) {
	ports := map[string]diagStpPort{}
	var edges []diagEdge
	seenEdge := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		role, state, guard := "", "", ""
		for _, tok := range f[1:] {
			switch {
			case role == "" && reStpRole.MatchString(tok):
				role = strings.ToLower(tok)
				if role == "alternative" {
					role = "alternate"
				}
			case state == "" && reStpState.MatchString(tok):
				state = strings.ToLower(tok)
			}
			switch strings.ToUpper(tok) {
			case "BG":
				guard = "bpdu-guard"
			case "RG":
				guard = "root-guard"
			case "LP":
				guard = "loop-guard"
			}
		}
		if role == "" || state == "" {
			continue // not a port/trunk data row
		}
		name := f[0]
		switch {
		case rePhysPort.MatchString(name):
			if _, ok := ports[name]; !ok {
				ports[name] = diagStpPort{Port: name, Role: role, State: state, Guard: guard}
			}
		case name != "internal" && !seenEdge[name]:
			seenEdge[name] = true
			edges = append(edges, diagEdge{Trunk: name, Role: role, State: state})
		}
	}
	return ports, edges
}

// diagPortProp is one port's physical properties from `switch-info port-properties`.
type diagPortProp struct {
	Media      string // RJ45 / SFP+ / QSFP
	PoeCapable bool
	HasSFP     bool
	MaxSpeedM  int // top negotiable speed in Mbps (from the Speed capability line)
}

var (
	rePPPort  = regexp.MustCompile(`(?m)^Port:\s*(\S+)`)
	rePPConn  = regexp.MustCompile(`(?m)^\s*Connector\s*:[^\S\n]*(\S+)`)
	rePPPoe   = regexp.MustCompile(`(?m)^\s*PoE\s*:[^\S\n]*(\S+)`) // matches only when a PoE value is present
	rePPSpeed = regexp.MustCompile(`(?m)^\s*Speed\s*:[^\S\n]*(\S+)`)
	rePPSpTok = regexp.MustCompile(`(\d+)([MG])`) // "1Gauto", "100Mfull" → value+unit
)

// maxSpeedMbps returns the highest speed (Mbps) in a capability string like
// "10Mhalf/100Mfull/1Gauto/auto" (→ 1000).
func maxSpeedMbps(s string) int {
	max := 0
	for _, m := range rePPSpTok.FindAllStringSubmatch(s, -1) {
		v := atoiSafe(m[1])
		if m[2] == "G" {
			v *= 1000
		}
		if v > max {
			max = v
		}
	}
	return max
}

// parsePortProperties maps each port to its connector/media, PoE capability and
// top negotiable speed.
func parsePortProperties(out string) map[string]diagPortProp {
	res := map[string]diagPortProp{}
	locs := rePPPort.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		var pp diagPortProp
		if m := rePPConn.FindStringSubmatch(block); m != nil {
			pp.Media = m[1]
		}
		if m := rePPPoe.FindStringSubmatch(block); m != nil {
			pp.PoeCapable = true
		}
		if m := rePPSpeed.FindStringSubmatch(block); m != nil {
			pp.MaxSpeedM = maxSpeedMbps(m[1])
		}
		pp.HasSFP = strings.Contains(pp.Media, "SFP") || strings.Contains(pp.Media, "QSFP")
		res[out[loc[2]:loc[3]]] = pp
	}
	return res
}

// rePoeRow matches a `poe summary` table row:
// "port10  Enabled  Delivering Power  30.0  6.40  Low  4".
var rePoeRow = regexp.MustCompile(`(?m)^\s*(port\d+)\s+(?:Enabled|Disabled)\s+(.+?)\s+([\d.]+)\s+([\d.]+)\s+\S+\s+(\d+)\b`)

// poeStateCode compresses the PoE State column.
func poeStateCode(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "deliver"):
		return "deliver"
	case strings.Contains(s, "search"):
		return "search"
	case strings.Contains(s, "fault") || strings.Contains(s, "error"):
		return "fault"
	default:
		return "off"
	}
}

// parsePoeSummary maps each PoE port to a compact "state:draw/max W:class" string
// (or "off"/"fault"), from `switch-info poe summary <sw>`.
func parsePoeSummary(out string) map[string]string {
	res := map[string]string{}
	for _, m := range rePoeRow.FindAllStringSubmatch(out, -1) {
		if poeStateCode(m[2]) == "deliver" { // only a delivering port has meaningful draw/class
			res[m[1]] = "deliver:" + m[4] + "/" + m[3] + "W:cls" + m[5]
		} else {
			res[m[1]] = poeStateCode(m[2])
		}
	}
	return res
}

// reModRow matches a `modules summary` row:
// "port25  INSERT  SFP/SFP+  N  25G-Base-CR  OK  Vendor ...".
var reModRow = regexp.MustCompile(`(?m)^\s*(port\d+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)`)

// parseModulesSummary maps each SFP/QSFP port to its transceiver type when a
// module is inserted, or "empty" for an empty cage.
func parseModulesSummary(out string) map[string]string {
	res := map[string]string{}
	for _, m := range reModRow.FindAllStringSubmatch(out, -1) {
		if strings.Contains(strings.ToUpper(m[2]), "INSERT") {
			res[m[1]] = m[3] // transceiver type, e.g. "10G-Base-CR"
		} else {
			res[m[1]] = "empty"
		}
	}
	return res
}

// reMacViolRow matches a `mac-limit-violations all` row within a switch block:
// "<portN> <vlan> <mac> <timestamp…> <action>". Only port + VLAN + MAC are
// pinned precisely; the trailing timestamp/action text is captured whole (its
// exact spacing is device/version specific).
var reMacViolRow = regexp.MustCompile(`(?m)^\s*(port\d+)\s+(\d+)\s+([0-9a-fA-F:]{17})\s+(.*\S)?\s*$`)

// parseMacLimitViolations parses `switch-info mac-limit-violations all` into the
// current port-security violations, one block per switch ("Managed Switch :").
func parseMacLimitViolations(out string) []MacViolation {
	var res []MacViolation
	locs := reInvSwitch.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		name := out[loc[2]:loc[3]]
		block := out[loc[0]:end]
		for _, m := range reMacViolRow.FindAllStringSubmatch(block, -1) {
			res = append(res, MacViolation{
				Switch: name, Port: m[1], Vlan: m[2],
				Mac:    strings.ToLower(m[3]),
				Action: strings.TrimSpace(m[4]),
			})
		}
	}
	return res
}

// reMacTableRow matches a `mac-table` access-port entry (Trunk: rows are transit
// and deliberately skipped; only `Port: portN` rows are true access ports).
var reMacTableRow = regexp.MustCompile(`(?m)^\s*MAC:\s*([0-9a-fA-F:]{17})\s+VLAN:\s*(\d+)\s+Port:\s*(port\d+)`)

// parseMacTable returns the access-port MAC sightings from `switch-info mac-table`
// (no-arg form, one block per switch delimited by "Managed Switch :").
func parseMacTable(out string) []MacPort {
	var res []MacPort
	locs := reInvSwitch.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		name := out[loc[2]:loc[3]]
		block := out[loc[0]:end]
		for _, m := range reMacTableRow.FindAllStringSubmatch(block, -1) {
			res = append(res, MacPort{
				Mac:        strings.ToLower(m[1]),
				Vlan:       m[2],
				Port:       m[3],
				SwitchName: name,
			})
		}
	}
	return res
}

var (
	// Port headers are indented in the real output ("   port2 :"), so allow
	// leading whitespace — anchoring at column 0 matched nothing.
	reDot1xPortHdr = regexp.MustCompile(`(?m)^\s*(port\d+)\s*:`)
	reDot1xState   = regexp.MustCompile(`Port State:\s*(authorized|unauthorized)`)
	reDot1xVlan    = regexp.MustCompile(`Dynamic Authorized Vlan\s*:\s*(\d+)`)
	reDot1xMac     = regexp.MustCompile(`(?m)^\s*([0-9a-fA-F:]{17})\s+Type=`)
	reDot1xUser    = regexp.MustCompile(`user="([^"]*)"`)
	reDot1xGroup   = regexp.MustCompile(`security_grp="([^"]*)"`)
)

// parseDot1x maps each 802.1X port to its authorization state, from a per-switch
// `switch-info 802.1X <sw>` block.
func parseDot1x(out string) map[string]string {
	res := map[string]string{}
	locs := reDot1xPortHdr.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		if m := reDot1xState.FindStringSubmatch(block); m != nil {
			res[out[loc[2]:loc[3]]] = m[1]
		}
	}
	return res
}

// dot1xSession is one authenticated 802.1X client: the session MAC plus the
// RADIUS-supplied identity (AD machine/user, group) and the dynamic VLAN.
type dot1xSession struct {
	Mac   string
	User  string
	Group string
	Vlan  string
}

// parseDot1xSessions returns the authenticated sessions (keyed by client MAC)
// from a per-switch 802.1X block — a new attribution axis the logs cannot give.
func parseDot1xSessions(out string) []dot1xSession {
	var res []dot1xSession
	locs := reDot1xPortHdr.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		m := reDot1xMac.FindStringSubmatch(block)
		if m == nil {
			continue // no authenticated session on this port
		}
		s := dot1xSession{Mac: strings.ToLower(m[1])}
		if u := reDot1xUser.FindStringSubmatch(block); u != nil {
			s.User = u[1]
		}
		if g := reDot1xGroup.FindStringSubmatch(block); g != nil {
			s.Group = g[1]
		}
		if v := reDot1xVlan.FindStringSubmatch(block); v != nil && v[1] != "0" {
			s.Vlan = v[1]
		}
		res = append(res, s)
	}
	return res
}

// arpEntry is one MAC↔IP binding from `get system arp` (the IP the switch
// mac-table lacks). Iface is the FortiGate interface (usually a VLAN name).
type arpEntry struct {
	Mac   string
	IP    string
	Iface string
}

var reArpRow = regexp.MustCompile(`(?m)^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([0-9a-fA-F:]{17})\s+(\S+)`)

// parseArp returns the MAC↔IP bindings from `get system arp`.
func parseArp(out string) []arpEntry {
	var res []arpEntry
	for _, m := range reArpRow.FindAllStringSubmatch(out, -1) {
		res = append(res, arpEntry{IP: m[1], Mac: strings.ToLower(m[2]), Iface: m[3]})
	}
	return res
}

var (
	reLldpNeighbor = regexp.MustCompile(`(?m)^Neighbor learned on port (port\d+)`)
	reLldpChassis  = regexp.MustCompile(`Chassis ID:\s*(\S+)`)
)

// parseLldp maps each port to its LLDP neighbor's system/chassis name (e.g. the
// connected host or downstream switch), from `switch-info lldp neighbors-detail`.
func parseLldp(out string) map[string]string {
	res := map[string]string{}
	locs := reLldpNeighbor.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		if m := reLldpChassis.FindStringSubmatch(block); m != nil {
			res[out[loc[2]:loc[3]]] = m[1]
		}
	}
	return res
}

// expandPortRange turns a FortiSwitch port range like "29-30" or "23-24,27"
// into ["port29","port30",...]. Non-numeric fragments are skipped.
func expandPortRange(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi := atoiSafe(a), atoiSafe(b)
			for i := lo; i <= hi && i-lo < 64; i++ {
				out = append(out, "port"+strconv.Itoa(i))
			}
		} else if part != "" && atoiSafe(part) > 0 {
			out = append(out, "port"+part)
		}
	}
	return out
}

// mclagIcl is the MC-LAG inter-chassis-link detail from `mclag icl <sw>`: the
// ICL trunk, its physical member ports, the peer's serial, and health (split-brain
// state + dropped keepalives) — the authoritative core↔core pairing.
type mclagIcl struct {
	Trunk         string
	Ports         []string
	PeerSerial    string
	SplitBrain    string
	KeepaliveDrop int
}

var (
	reIclTrunk = regexp.MustCompile(`(?m)^(_FlInK\S*_ICL\d*_?)\s*$`)
	reIclPorts = regexp.MustCompile(`icl-ports\s+(\S+)`)
	reIclPeer  = regexp.MustCompile(`peer-serial-number\s+(\S+)`)
	reIclSplit = regexp.MustCompile(`split-brain\s+(\S+)`)
	reIclDrop  = regexp.MustCompile(`received keepalive drop packets\s+(\d+)`)
)

// parseMclagIcl parses `switch-info mclag icl <sw>`; nil when the switch has no ICL.
func parseMclagIcl(out string) *mclagIcl {
	t := reIclTrunk.FindStringSubmatch(out)
	if t == nil {
		return nil
	}
	m := &mclagIcl{Trunk: t[1]}
	if x := reIclPorts.FindStringSubmatch(out); x != nil {
		m.Ports = expandPortRange(x[1])
	}
	if x := reIclPeer.FindStringSubmatch(out); x != nil {
		m.PeerSerial = x[1]
	}
	if x := reIclSplit.FindStringSubmatch(out); x != nil {
		m.SplitBrain = x[1]
	}
	if x := reIclDrop.FindStringSubmatch(out); x != nil {
		m.KeepaliveDrop = atoiSafe(x[1])
	}
	return m
}

var reFanRow = regexp.MustCompile(`(?m)^(FAN\d+)\s+(\S+)`)

// parseFan summarizes `switch-info fan <sw>`: "OK" when every fan is OK, else a
// "FAULT: …" string naming the failed modules; "" when the switch has no fans.
func parseFan(out string) string {
	fans := reFanRow.FindAllStringSubmatch(out, -1)
	if len(fans) == 0 {
		return ""
	}
	var bad []string
	for _, f := range fans {
		if !strings.HasPrefix(strings.ToUpper(f[2]), "OK") {
			bad = append(bad, f[1]+" "+f[2])
		}
	}
	if len(bad) > 0 {
		return "FAULT: " + strings.Join(bad, ", ")
	}
	return "OK"
}

var reQosDrop = regexp.MustCompile(`(?m)^\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*$`)

// parseQosCongestion sums the per-queue drop counters from `qos-stats <sw>` — a
// cumulative-since-boot congestion indicator for the switch.
func parseQosCongestion(out string) int {
	total := 0
	for _, m := range reQosDrop.FindAllStringSubmatch(out, -1) {
		total += atoiSafe(m[1])
	}
	return total
}

var (
	reRouteConnected = regexp.MustCompile(`is directly connected,\s*(\S+)`)
	reRouteViaTunnel = regexp.MustCompile(`via\s+(\S+)\s+tunnel\s`)
	reRouteViaIface  = regexp.MustCompile(`via\s+\d+\.\d+\.\d+\.\d+,\s*([^,\s]+),`)
)

// parseRoutes folds `get router info routing-table all` into per-egress route
// counts (interface or VPN tunnel name) plus whether that egress carries the
// live default route — the actual installed forwarding, not the config. Only
// names + counts are extracted (no gateway IPs), and the tunnel/interface names
// are the same ones the config-derived topology already shows.
func parseRoutes(out string) []LiveRoute {
	counts := map[string]int{}
	def := map[string]bool{}
	inDefault := false
	for _, ln := range strings.Split(out, "\n") {
		trimmed := strings.TrimLeft(ln, " \t")
		isCont := ln != trimmed && strings.HasPrefix(trimmed, "[") // ECMP continuation line
		if !isCont {
			inDefault = strings.Contains(ln, "0.0.0.0/0")
		}
		dev := ""
		if m := reRouteConnected.FindStringSubmatch(ln); m != nil {
			dev = m[1]
		} else if m := reRouteViaTunnel.FindStringSubmatch(ln); m != nil {
			dev = m[1]
		} else if m := reRouteViaIface.FindStringSubmatch(ln); m != nil {
			dev = m[1]
		}
		if dev == "" {
			continue
		}
		counts[dev]++
		if inDefault {
			def[dev] = true
		}
	}
	out2 := make([]LiveRoute, 0, len(counts))
	for d, c := range counts {
		out2 = append(out2, LiveRoute{Device: d, Routes: c, Default: def[d]})
	}
	return out2
}

var reStpTcn = regexp.MustCompile(`TCN Events\s+Triggered\s+(\d+)`)

// parseStpTcn returns the highest spanning-tree topology-change count from the
// `stp` header (cumulative since boot) — a rough "is the topology churning here"
// indicator. Reuses the stp output already collected.
func parseStpTcn(out string) int {
	max := 0
	for _, m := range reStpTcn.FindAllStringSubmatch(out, -1) {
		if n := atoiSafe(m[1]); n > max {
			max = n
		}
	}
	return max
}

var (
	rePoeBudget = regexp.MustCompile(`Unit Power Budget:\s*([\d.]+)`)
	rePoeConsum = regexp.MustCompile(`Unit Power Consumption:\s*([\d.]+)`)
)

// parsePoeBudget extracts the switch-level PoE consumption/budget (watts) from
// the `poe summary` header already collected.
func parsePoeBudget(out string) (used, total float64) {
	if m := rePoeConsum.FindStringSubmatch(out); m != nil {
		used = atofSafe(m[1])
	}
	if m := rePoeBudget.FindStringSubmatch(out); m != nil {
		total = atofSafe(m[1])
	}
	return
}

// SdwanHealth is one SD-WAN member's aggregated live SLA (worst case across all
// health-checks): state, packet-loss %, latency and jitter (ms). The member is
// keyed by its egress interface/tunnel — the same names the topology shows.
type SdwanHealth struct {
	Member  string  `json:"member"`
	State   string  `json:"state,omitempty"`
	Loss    float64 `json:"loss,omitempty"`
	Latency float64 `json:"latency,omitempty"`
	Jitter  float64 `json:"jitter,omitempty"`
}

var reSdwanSeq = regexp.MustCompile(`Seq\(\d+\s+(\S+)\): state\((\w+)\), packet-loss\(([\d.]+)%\), latency\(([\d.]+)\), jitter\(([\d.]+)\)`)

// parseSdwanHealth folds `diagnose sys sdwan health-check` into a per-member
// worst-case SLA — the live WAN quality the config alone cannot show.
func parseSdwanHealth(out string) []SdwanHealth {
	agg := map[string]*SdwanHealth{}
	var order []string
	for _, m := range reSdwanSeq.FindAllStringSubmatch(out, -1) {
		iface := m[1]
		h := agg[iface]
		if h == nil {
			h = &SdwanHealth{Member: iface, State: strings.ToLower(m[2])}
			agg[iface] = h
			order = append(order, iface)
		}
		if strings.EqualFold(m[2], "dead") {
			h.State = "dead"
		}
		if l := atofSafe(m[3]); l > h.Loss {
			h.Loss = l
		}
		if l := atofSafe(m[4]); l > h.Latency {
			h.Latency = l
		}
		if l := atofSafe(m[5]); l > h.Jitter {
			h.Jitter = l
		}
	}
	out2 := make([]SdwanHealth, 0, len(order))
	for _, i := range order {
		out2 = append(out2, *agg[i])
	}
	return out2
}

// ifaceCounter is one FortiGate interface's byte/error counters from
// `diagnose netlink interface list`, used to derive throughput via a delta.
type ifaceCounter struct {
	Iface string
	RxB   int64
	TxB   int64
	RxE   int64
	TxE   int64
}

var (
	reNlIf   = regexp.MustCompile(`(?m)^if=(\S+)`)
	reNlStat = regexp.MustCompile(`rxb=(\d+)\s+txb=(\d+)\s+rxe=(\d+)\s+txe=(\d+)`)
)

// parseNetlinkIfaces returns per-interface byte/error counters from
// `diagnose netlink interface list`.
func parseNetlinkIfaces(out string) []ifaceCounter {
	var res []ifaceCounter
	locs := reNlIf.FindAllStringSubmatchIndex(out, -1)
	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		c := ifaceCounter{Iface: out[loc[2]:loc[3]]}
		if m := reNlStat.FindStringSubmatch(block); m != nil {
			c.RxB, c.TxB, c.RxE, c.TxE = atoi64(m[1]), atoi64(m[2]), atoi64(m[3]), atoi64(m[4])
			res = append(res, c)
		}
	}
	return res
}

// fwHealth is the FortiGate node's live health from `get system performance
// status` + `diagnose sys ha status`.
type fwHealth struct {
	CPU      string // "5%"
	Mem      string // "35%"
	Sessions string
	Uptime   string // "21d 7h"
	HA       string // "FGT…-N2 Primary · FGT…-N1 Secondary (work)"
}

var (
	rePerfIdle = regexp.MustCompile(`CPU states:.*?(\d+)% idle`)
	rePerfMem  = regexp.MustCompile(`Memory:.*?used \((\d+(?:\.\d+)?)%\)`)
	rePerfSess = regexp.MustCompile(`Average sessions:\s*(\d+) sessions in 1 minute`)
	rePerfUp   = regexp.MustCompile(`Uptime:\s*(\d+) days?,\s*(\d+) hours?`)
	reHaMember = regexp.MustCompile(`(?m)^(\S+):\s+(Primary|Secondary),.*hostname=(\S+)`)
	reHaState  = regexp.MustCompile(`vcluster \d+,\s*state=(\w+)`)
)

// parseFwHealth extracts the firewall-node health summary.
func parseFwHealth(perfOut, haOut string) fwHealth {
	var h fwHealth
	if m := rePerfIdle.FindStringSubmatch(perfOut); m != nil {
		if idle := atoiSafe(m[1]); idle <= 100 {
			h.CPU = strconv.Itoa(100-idle) + "%"
		}
	}
	if m := rePerfMem.FindStringSubmatch(perfOut); m != nil {
		h.Mem = m[1] + "%"
	}
	if m := rePerfSess.FindStringSubmatch(perfOut); m != nil {
		h.Sessions = m[1]
	}
	if m := rePerfUp.FindStringSubmatch(perfOut); m != nil {
		h.Uptime = m[1] + "d " + m[2] + "h"
	}
	var members []string
	for _, m := range reHaMember.FindAllStringSubmatch(haOut, -1) {
		members = append(members, m[3]+" "+m[2]) // hostname + role
	}
	if len(members) > 0 {
		state := ""
		if s := reHaState.FindStringSubmatch(haOut); s != nil {
			state = " (" + s[1] + ")"
		}
		h.HA = strings.Join(members, " · ") + state
	}
	return h
}

// summary renders the health as a one-line string for storage/display.
func (h fwHealth) summary() string {
	var p []string
	if h.CPU != "" {
		p = append(p, "CPU "+h.CPU)
	}
	if h.Mem != "" {
		p = append(p, "Mem "+h.Mem)
	}
	if h.Sessions != "" {
		p = append(p, h.Sessions+" sessions")
	}
	if h.Uptime != "" {
		p = append(p, "up "+h.Uptime)
	}
	s := strings.Join(p, " · ")
	if h.HA != "" {
		if s != "" {
			s += " | "
		}
		s += "HA: " + h.HA
	}
	return s
}

// buildDiagPorts merges every per-switch diagnostic into StpPort rows plus the
// switch's interlink edges. Link/admin/speed/health come from port-stats;
// role/state from STP (attached only to link-up ports, so a down port is never
// shown "blocked"); guard from the STP Flags regardless of link (a BPDU-guard
// block err-disables the port). Media/PoE/optic/802.1X/LLDP enrich when present.
func buildDiagPorts(sw diagSwitch, portStatsOut, stpOut, portPropsOut, poeOut, modulesOut, dot1xOut, lldpOut string) ([]StpPort, []SwitchEdge) {
	stats := parsePortStats(portStatsOut)
	stpPorts, stpEdges := parseStp(stpOut)
	props := parsePortProperties(portPropsOut)
	poe := parsePoeSummary(poeOut)
	optics := parseModulesSummary(modulesOut)
	dot1x := parseDot1x(dot1xOut)
	lldp := parseLldp(lldpOut)

	seen := map[string]bool{}
	var out []StpPort
	add := func(port string) {
		if seen[port] || !rePhysPort.MatchString(port) {
			return
		}
		seen[port] = true
		sp := StpPort{SwitchName: sw.Name, Serial: sw.Serial, Port: port}
		ps, hasPS := stats[port]
		st, hasStp := stpPorts[port]
		up := false
		if hasPS {
			up = ps.Up
			if ps.AdminUp {
				sp.Admin = "up"
			} else {
				sp.Admin = "down"
			}
			sp.Speed = ps.Speed
			sp.Health = ps.Health
		} else if hasStp {
			up = st.Role != "disabled"
		}
		if up {
			sp.Link = "up"
			if hasStp {
				sp.Role = st.Role
				sp.State = st.State
			}
		} else {
			sp.Link = "down" // leave role/state empty: a down port is not "blocked"
		}
		if hasStp {
			sp.Guard = st.Guard // guard applies regardless of link
		}
		if pp, ok := props[port]; ok {
			sp.Media = pp.Media
		}
		if v, ok := poe[port]; ok {
			sp.Poe = v
		}
		if v, ok := optics[port]; ok {
			sp.Optic = v
		}
		if v, ok := dot1x[port]; ok {
			sp.Dot1x = v
		}
		if v, ok := lldp[port]; ok {
			sp.Neighbor = v
		}
		// Physical-layer fault: half-duplex on a modern link (a duplex mismatch or
		// a failing autoneg). Folded into Health so the faceplate's fault ring +
		// detail surface it. A negotiated speed below the port's own capability is
		// deliberately NOT flagged — a 1G-capable port legitimately negotiates
		// 100M with a 100M peer, so local capability alone cannot prove a fault.
		if hasPS && up && ps.Half {
			if sp.Health != "" {
				sp.Health += " "
			}
			sp.Health += "half-duplex"
		}
		out = append(out, sp)
	}
	for port := range stats {
		add(port)
	}
	for port := range stpPorts {
		add(port)
	}
	for port := range props {
		add(port)
	}
	for port := range poe {
		add(port)
	}
	for port := range optics {
		add(port)
	}
	for port := range dot1x {
		add(port)
	}
	for port := range lldp {
		add(port)
	}

	edges := make([]SwitchEdge, 0, len(stpEdges))
	for _, e := range stpEdges {
		edges = append(edges, SwitchEdge{SwitchSN: sw.Serial, SwitchName: sw.Name, Trunk: e.Trunk, Role: e.Role, State: e.State})
	}
	return out, edges
}

// parseWtpStatus parses `get wireless-controller wtp-status` into per-AP location
// records. Each managed FortiAP block ("WTP: <name> …") carries its serial
// (wtp-id), name, board MAC and CAPWAP IP; the AP's embedded LLDP report names
// the FortiSwitch it is wired to (sys name) and the switch port (port id) — the
// AP↔port pin nothing else exposes, since an AP has no wired device row. LLDP is
// on by default in FortiAP profiles, so this is populated on a standard fabric.
// The first "sys name"/"port id" per block is the wired uplink neighbor.
func parseWtpStatus(out string) []ApLocation {
	var res []ApLocation
	var cur *ApLocation
	flush := func() {
		if cur != nil && cur.Serial != "" {
			res = append(res, *cur)
		}
		cur = nil
	}
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "WTP:") {
			flush()
			cur = &ApLocation{}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.ToLower(k))
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "wtp-id":
			cur.Serial = v
		case "name":
			if cur.Name == "" {
				cur.Name = v
			}
		case "board-mac":
			cur.BoardMac = strings.ToLower(v)
		case "local-ip-addr":
			cur.IP = v
		case "sys name": // LLDP neighbor: the wired upstream FortiSwitch
			if cur.Switch == "" {
				cur.Switch = v
			}
		case "port id": // LLDP neighbor: the switch port the AP is wired to
			if cur.Port == "" {
				cur.Port = strings.Fields(v)[0] // first token strips any "(ifname)" suffix
			}
		}
	}
	flush()
	return res
}
