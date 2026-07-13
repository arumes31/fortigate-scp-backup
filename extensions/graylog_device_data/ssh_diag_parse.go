package graylogdevicedata

import (
	"regexp"
	"strings"
)

// This file parses the FortiGate CLI diagnostics used for the live port overlay.
// The three commands (verified against FortiOS 7.6 with a read-only admin) are:
//
//	diagnose switch-controller switch-info status         → managed-switch inventory (name ↔ serial)
//	diagnose switch-controller switch-info port-stats <sw> → per-port link up/down ("line protocol is up")
//	diagnose switch-controller switch-info stp <sw>        → per-port STP role/state + interlink trunk rows
//
// Everything is free-text, so the parsers are line-oriented and tolerant: they
// key on the stable tokens (port name + up/down, port name + role/state keywords)
// and ignore anything that does not match, exactly like the Graylog log parsers.

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
// (Hostname, the identifier the config/faceplate use) and serial. The blocks are
// delimited by the "Managed Switch :" header line.
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

// rePortLink matches the per-port status line, e.g.
// "Port(port1) is HW Admin up, SW Admin up, line protocol is up".
var rePortLink = regexp.MustCompile(`Port\((\S+?)\) is HW Admin (?:up|down), SW Admin (?:up|down), line protocol is (up|down)`)

// parsePortStats maps each physical port to its live link state (true = up),
// from `switch-info port-stats <switch>`.
func parsePortStats(out string) map[string]bool {
	res := map[string]bool{}
	for _, m := range rePortLink.FindAllStringSubmatch(out, -1) {
		res[m[1]] = m[2] == "up"
	}
	return res
}

// diagStpPort is one physical port's STP role/state from `switch-info stp`.
type diagStpPort struct {
	Port  string
	Role  string // designated | root | alternate | backup | disabled | master (lowercased)
	State string // forwarding | discarding | learning | blocking | listening
}

// diagEdge is one interlink trunk observed in the STP table — the switch-to-switch
// wiring FortiSwitch names after the peer (auto-ISL "…serialfragment-0", MC-LAG
// "_FlInK…_MLAG…_" / ICL "…_ICL…_"). Role orients the edge (root = uplink).
type diagEdge struct {
	Trunk string
	Role  string
}

var (
	reStpRole  = regexp.MustCompile(`(?i)^(designated|root|alternate|backup|disabled|master)$`)
	reStpState = regexp.MustCompile(`(?i)^(forwarding|discarding|learning|blocking|listening)$`)
)

// parseStp parses the STP table into per-physical-port role/state and the
// interlink trunk rows. A row is accepted only when it carries BOTH a role and a
// state keyword, which cleanly rejects headers, the bridge-info lines and the
// flag legend. Physical ports (portN) feed the STP overlay; trunk-named rows
// (not portN, excluding the FGT-facing "internal") feed interlink detection.
// Instance tables repeat rows, so the first sighting per name wins.
func parseStp(out string) (map[string]diagStpPort, []diagEdge) {
	ports := map[string]diagStpPort{}
	var edges []diagEdge
	seenEdge := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		role, state := "", ""
		for _, tok := range f[1:] {
			switch {
			case role == "" && reStpRole.MatchString(tok):
				role = strings.ToLower(tok)
			case state == "" && reStpState.MatchString(tok):
				state = strings.ToLower(tok)
			}
		}
		if role == "" || state == "" {
			continue // not a port/trunk data row
		}
		name := f[0]
		switch {
		case rePhysPort.MatchString(name):
			if _, ok := ports[name]; !ok {
				ports[name] = diagStpPort{Port: name, Role: role, State: state}
			}
		case name != "internal" && !seenEdge[name]:
			seenEdge[name] = true
			edges = append(edges, diagEdge{Trunk: name, Role: role})
		}
	}
	return ports, edges
}

// buildDiagPorts merges the port-stats link state and STP role/state for one
// switch into StpPort rows (authoritative live state) plus its interlink edges.
// Link comes from port-stats; role/state are attached only for ports that are
// link-up, so a down port never inherits the "disabled/discarding" STP values
// that would otherwise make the faceplate mark it as blocked rather than down.
func buildDiagPorts(sw diagSwitch, portStatsOut, stpOut string) ([]StpPort, []SwitchEdge) {
	links := parsePortStats(portStatsOut)
	stpPorts, stpEdges := parseStp(stpOut)

	seen := map[string]bool{}
	var out []StpPort
	add := func(port string) {
		if seen[port] {
			return
		}
		seen[port] = true
		sp := StpPort{SwitchName: sw.Name, Serial: sw.Serial, Port: port}
		up, hasLink := links[port]
		st, hasStp := stpPorts[port]
		if !hasLink && hasStp { // no port-stats: infer from STP (disabled = no link)
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
		out = append(out, sp)
	}
	for port := range links {
		add(port)
	}
	for port := range stpPorts {
		add(port)
	}

	edges := make([]SwitchEdge, 0, len(stpEdges))
	for _, e := range stpEdges {
		edges = append(edges, SwitchEdge{SwitchSN: sw.Serial, SwitchName: sw.Name, Trunk: e.Trunk, Role: e.Role})
	}
	return out, edges
}
