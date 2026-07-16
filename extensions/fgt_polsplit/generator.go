package fgt_polsplit

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// groupInlineMax is the largest member count listed directly in a policy's
// srcaddr/dstaddr; above it an addrgrp is generated instead.
const groupInlineMax = 3

var nameSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizeName(s string) string {
	s = nameSanitizeRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "PS"
	}
	return s
}

// policyNameSanitizeRe keeps the characters the path-based policy naming
// convention needs — "VL1>VLXX (RDP+2)" — while still excluding quotes and
// control characters (FortiGate policy names allow spaces, parens and >).
var policyNameSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9 ._()>+-]+`)

func sanitizePolicyName(s string) string {
	s = policyNameSanitizeRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_ ")
	if s == "" {
		s = "PS"
	}
	return s
}

// ticketSanitizeRe restricts the free-text change-ticket ID embedded into
// generated `set comments` lines.
var ticketSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9 ._#:/-]+`)

func sanitizeTicket(s string) string {
	s = ticketSanitizeRe.ReplaceAllString(strings.TrimSpace(s), "_")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// namer allocates FortiGate object names that collide neither with existing
// config objects nor with each other (FortiGate names are case-insensitive in
// practice, so the taken-set is lowercased).
type namer struct {
	taken map[string]bool
}

func newNamer(existing map[string]bool) *namer {
	t := make(map[string]bool, len(existing))
	for k := range existing {
		t[k] = true
	}
	return &namer{taken: t}
}

func (n *namer) alloc(base string, maxLen int) string {
	return n.allocSanitized(sanitizeName(base), maxLen)
}

// allocSanitized allocates a collision-free name from an already-sanitized
// base (policy names use the more permissive sanitizePolicyName).
func (n *namer) allocSanitized(base string, maxLen int) string {
	if len(base) > maxLen {
		base = base[:maxLen]
	}
	name := base
	for i := 2; n.taken[strings.ToLower(name)]; i++ {
		suffix := fmt.Sprintf("_%d", i)
		trimmed := base
		if len(trimmed)+len(suffix) > maxLen {
			trimmed = trimmed[:maxLen-len(suffix)]
		}
		name = trimmed + suffix
	}
	n.taken[strings.ToLower(name)] = true
	return name
}

// GenResult is one strategy's generated configuration.
type GenResult struct {
	Config     string
	NewObjects []NewObject
	Warnings   []string
}

// fgtQuote quotes a name for FortiGate CLI, escaping embedded backslashes and
// double quotes. Generated names are sanitized anyway, but reused names from
// the parsed backup may contain anything.
func fgtQuote(name string) string {
	name = strings.ReplaceAll(name, `\`, `\\`)
	name = strings.ReplaceAll(name, `"`, `\"`)
	return `"` + name + `"`
}

func quoteList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fgtQuote(n)
	}
	return strings.Join(quoted, " ")
}

func maskFromBits(bits int) string {
	return net.IP(net.CIDRMask(bits, 32)).String()
}

// svcDisplay is the human-facing name of a service spec ("HTTPS", "tcp/8443").
func svcDisplay(s ServiceSpec) string {
	if s.LogName != "" {
		return s.LogName
	}
	return s.Key
}

// GenOptions bundles the operator-tunable generation settings.
type GenOptions struct {
	Prefix string // new-object name prefix (default PS<policyid>)
	Ticket string // change-ticket ID embedded in comments
	// EmitDeny appends an explicit deny+log policy covering the original's
	// scope directly above the (disabled) original, so fallthrough traffic is
	// loudly visible instead of silently dying with the disabled policy.
	EmitDeny bool
}

// Generate turns one strategy's recommended policies into FortiGate CLI. It
// reuses existing address/service objects and groups on exact match, creates
// the missing ones under the given prefix, allocates free policy IDs from the
// backup's ID space and emits the sections in dependency order, followed by
// `move` statements (new policies must sit above the original) and a block
// disabling the original policy. A non-empty ticket is embedded in every
// generated policy's comments.
func Generate(orig *OrigPolicy, parsed *ParsedBackup, policies []RecPolicy, opts GenOptions) GenResult {
	res := GenResult{}
	if len(policies) == 0 {
		return res
	}
	ticket := opts.Ticket
	prefix := sanitizeName(opts.Prefix)
	if prefix == "" || prefix == "PS" {
		prefix = fmt.Sprintf("PS%d", orig.ID)
	}
	nm := newNamer(parsed.TakenNames)

	var addrDefs, grpDefs, svcDefs []string

	// --- address objects -------------------------------------------------
	addrName := map[string]string{} // entity value → object name
	resolveEntity := func(ent Entity) string {
		if name, ok := addrName[ent.Value]; ok {
			return name
		}
		if ent.Value == "all" {
			// The built-in "all" object (WAN-as-all collapse) always exists.
			addrName["all"] = "all"
			return "all"
		}
		var name string
		if ent.IsNet {
			if names := parsed.AddrByCIDR[ent.Value]; len(names) > 0 {
				name = names[0]
			} else {
				ipBits := strings.SplitN(ent.Value, "/", 2)
				name = nm.alloc(fmt.Sprintf("%s_n_%s-%s", prefix, ipBits[0], ipBits[1]), 79)
				addrDefs = append(addrDefs,
					fmt.Sprintf("    edit %q\n        set subnet %s %s\n    next", name, ipBits[0], maskFromBits(atoiSafe(ipBits[1]))))
				res.NewObjects = append(res.NewObjects, NewObject{Kind: "address", Name: name, Value: ent.Value})
			}
		} else {
			if names := parsed.AddrByCIDR[ent.Value+"/32"]; len(names) > 0 {
				name = names[0]
			} else {
				name = nm.alloc(fmt.Sprintf("%s_h_%s", prefix, ent.Value), 79)
				addrDefs = append(addrDefs,
					fmt.Sprintf("    edit %q\n        set subnet %s 255.255.255.255\n    next", name, ent.Value))
				res.NewObjects = append(res.NewObjects, NewObject{Kind: "address", Name: name, Value: ent.Value + "/32"})
			}
		}
		addrName[ent.Value] = name
		return name
	}

	// --- service objects --------------------------------------------------
	svcName := map[string]string{} // canonical key → object/service name
	resolveService := func(s ServiceSpec) string {
		if name, ok := svcName[s.Key]; ok {
			return name
		}
		var name string
		if s.LogName != "" {
			if existing, ok := parsed.SvcNames[strings.ToLower(s.LogName)]; ok {
				for _, nameByKey := range parsed.SvcByKey[s.Key] {
					if nameByKey == existing {
						name = existing
						break
					}
				}
			}
		}
		if name == "" {
			if names := parsed.SvcByKey[s.Key]; len(names) > 0 {
				name = names[0]
			}
		}
		if name == "" {
			var def, disp string
			switch s.Proto {
			case "tcpudp":
				// Merged tcp+udp same-port pair (e.g. DNS-style services).
				name = nm.alloc(fmt.Sprintf("%s_tcpudp%d", prefix, s.Port), 79)
				def = fmt.Sprintf("        set tcp-portrange %d\n        set udp-portrange %d", s.Port, s.Port)
				disp = s.Key
			case "tcp", "udp", "sctp":
				if s.PortEnd > s.Port && s.Port > 0 {
					// Consolidated adjacent-port range (tcp/8080-8082).
					name = nm.alloc(fmt.Sprintf("%s_%s%d_%d", prefix, s.Proto, s.Port, s.PortEnd), 79)
					def = fmt.Sprintf("        set %s-portrange %d-%d", s.Proto, s.Port, s.PortEnd)
					disp = s.Key
					break
				}
				if s.Port <= 0 || s.Port > 65535 {
					// Logs carried no usable dstport for this protocol;
					// `set tcp-portrange 0` would be rejected by FortiOS.
					name = nm.alloc(fmt.Sprintf("%s_%s_any", prefix, s.Proto), 79)
					def = fmt.Sprintf("        set %s-portrange 1-65535", s.Proto)
					disp = s.Proto + "/any"
					break
				}
				name = nm.alloc(fmt.Sprintf("%s_%s%d", prefix, s.Proto, s.Port), 79)
				def = fmt.Sprintf("        set %s-portrange %d", s.Proto, s.Port)
				disp = s.Key
			case "icmp":
				name = nm.alloc(prefix+"_icmp", 79)
				def = "        set protocol ICMP"
				disp = "icmp"
			case "icmp6":
				name = nm.alloc(prefix+"_icmp6", 79)
				def = "        set protocol ICMP6"
				disp = "icmp6"
			default: // ip-<n>
				n := strings.TrimPrefix(s.Proto, "ip-")
				name = nm.alloc(fmt.Sprintf("%s_ip%s", prefix, n), 79)
				def = fmt.Sprintf("        set protocol IP\n        set protocol-number %s", n)
				disp = "ip/" + n
			}
			svcDefs = append(svcDefs, fmt.Sprintf("    edit %q\n%s\n    next", name, def))
			res.NewObjects = append(res.NewObjects, NewObject{Kind: "service", Name: name, Value: disp})
		}
		svcName[s.Key] = name
		return name
	}

	// --- per-policy sides, groups, IDs -------------------------------------
	nextID := 1
	if len(parsed.UsedPolicyIDs) > 0 {
		nextID = parsed.UsedPolicyIDs[len(parsed.UsedPolicyIDs)-1] + 1
	}
	grpBySig := map[string]string{} // member signature → group name, dedupes identical groups
	resolveSide := func(ents []Entity, polName, side string) []string {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, resolveEntity(e))
		}
		sort.Strings(names)
		// An existing address group with exactly this member set is the same
		// scope — reference it instead of inlining or creating a new group.
		if len(names) > 1 {
			if g, ok := parsed.AddrGrpBySig[groupSig(names)]; ok {
				return []string{g}
			}
		}
		if len(names) <= groupInlineMax {
			return names
		}
		sig := fmt.Sprintf("%d:", len(names))
		for _, n := range names {
			sig += fmt.Sprintf("%d:%s", len(n), n)
		}
		if g, ok := grpBySig[sig]; ok {
			return []string{g}
		}
		g := nm.alloc(fmt.Sprintf("%s_%s_%s", prefix, sanitizeName(polName), side), 79)
		grpBySig[sig] = g
		grpDefs = append(grpDefs, fmt.Sprintf("    edit %q\n        set member %s\n    next", g, quoteList(names)))
		res.NewObjects = append(res.NewObjects, NewObject{Kind: "addrgrp", Name: g,
			Value: fmt.Sprintf("%d members: %s", len(names), strings.Join(names, ", "))})
		return []string{g}
	}

	// Seeded with the backup's existing policy names: FortiGate rejects
	// duplicate policy names per VDOM, so a re-run of the advisor (or an
	// existing PS42-HTTPS) must not re-allocate the same name.
	polNamer := newNamer(parsed.PolicyNames)
	var polDefs, moves []string
	for i := range policies {
		p := &policies[i]
		p.ID = nextID
		nextID++
		p.Name = polNamer.allocSanitized(sanitizePolicyName(policyBaseName(orig, *p)), 35)

		src := resolveSide(p.Src, p.Name, "src")
		dst := resolveSide(p.Dst, p.Name, "dst")
		svcs := make([]string, 0, len(p.Services))
		for _, s := range p.Services {
			svcs = append(svcs, resolveService(s))
		}
		sort.Strings(svcs)
		// An existing service group with exactly these members is the same
		// scope — reference the group instead of the member list.
		if len(svcs) > 1 {
			if g, ok := parsed.SvcGrpBySig[groupSig(svcs)]; ok {
				svcs = []string{g}
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "    edit %d\n", p.ID)
		fmt.Fprintf(&b, "        set name %q\n", p.Name)
		for _, line := range orig.CloneLines {
			b.WriteString("        " + line + "\n")
		}
		fmt.Fprintf(&b, "        set srcaddr %s\n", quoteList(src))
		fmt.Fprintf(&b, "        set dstaddr %s\n", quoteList(dst))
		fmt.Fprintf(&b, "        set service %s\n", quoteList(svcs))
		b.WriteString("        set logtraffic all\n")
		comment := fmt.Sprintf("Split from policy %d (FortiSafe polsplit)", orig.ID)
		if t := sanitizeTicket(ticket); t != "" {
			comment += " [" + t + "]"
		}
		fmt.Fprintf(&b, "        set comments %q\n", comment)
		b.WriteString("    next")
		polDefs = append(polDefs, b.String())

		moves = append(moves, fmt.Sprintf("    move %d before %d", p.ID, orig.ID))
	}

	// --- optional explicit fallthrough deny ---------------------------------
	// Covers the original's exact scope with action deny + logging; its move
	// runs LAST, so it lands directly above the disabled original and below
	// every split — fallthrough traffic logs loudly instead of dying silently.
	if opts.EmitDeny {
		denyID := nextID // last allocated ID; nothing follows in this batch
		denyName := polNamer.allocSanitized(sanitizePolicyName(
			fmt.Sprintf("%s>%s (DENY-REST)", ifaceLabel(orig.SrcIntf), ifaceLabel(orig.DstIntf))), 35)
		orDefault := func(vals []string, def string) []string {
			if len(vals) == 0 {
				return []string{def}
			}
			return vals
		}
		var b strings.Builder
		fmt.Fprintf(&b, "    edit %d\n", denyID)
		fmt.Fprintf(&b, "        set name %q\n", denyName)
		for _, line := range orig.CloneLines {
			// Only the scope-defining clone lines: action/NAT/UTM must not be
			// carried into a deny policy.
			if strings.HasPrefix(line, "set srcintf ") || strings.HasPrefix(line, "set dstintf ") ||
				strings.HasPrefix(line, "set schedule ") {
				b.WriteString("        " + line + "\n")
			}
		}
		fmt.Fprintf(&b, "        set srcaddr %s\n", quoteList(orDefault(orig.SrcAddr, "all")))
		fmt.Fprintf(&b, "        set dstaddr %s\n", quoteList(orDefault(orig.DstAddr, "all")))
		fmt.Fprintf(&b, "        set service %s\n", quoteList(orDefault(orig.Services, "ALL")))
		b.WriteString("        set action deny\n")
		b.WriteString("        set logtraffic all\n")
		comment := fmt.Sprintf("Fallthrough deny for policy %d — catches traffic the splits missed (FortiSafe polsplit)", orig.ID)
		if t := sanitizeTicket(ticket); t != "" {
			comment += " [" + t + "]"
		}
		fmt.Fprintf(&b, "        set comments %q\n", comment)
		b.WriteString("    next")
		polDefs = append(polDefs, b.String())
		moves = append(moves, fmt.Sprintf("    move %d before %d", denyID, orig.ID))
	}

	// --- assemble sections in dependency order ------------------------------
	var out strings.Builder
	section := func(header string, defs []string) {
		if len(defs) == 0 {
			return
		}
		out.WriteString("config " + header + "\n")
		out.WriteString(strings.Join(defs, "\n"))
		out.WriteString("\nend\n\n")
	}
	section("firewall address", addrDefs)
	section("firewall addrgrp", grpDefs)
	section("firewall service custom", svcDefs)
	section("firewall policy", polDefs)
	section("firewall policy", moves)

	// Disable (don't delete) the original once the splits are verified.
	fmt.Fprintf(&out, "config firewall policy\n    edit %d\n        set status disable\n    next\nend\n", orig.ID)

	cfg := strings.TrimRight(out.String(), "\n") + "\n"
	if orig.VDOM != "" {
		// Multi-VDOM unit: the CLI must enter the policy's VDOM first, or the
		// paste fails at the global context (or lands in the wrong VDOM).
		cfg = "config vdom\nedit " + orig.VDOM + "\n\n" + cfg + "\nend\n"
	}
	res.Config = cfg
	if orig.Action != "accept" {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("original policy action is %q — split policies clone it; review whether splitting is what you want", displayAction(orig.Action)))
	}
	return res
}

func displayAction(a string) string {
	if a == "" {
		return "deny (default)"
	}
	return a
}

// policyBaseName builds the path-based policy name convention:
// "SRCINTF>DSTINTF (SERVICE)" — e.g. "VL1>VL51 (RDP)", "PORT1>PORT2 (SSH)".
// Multiple interfaces sharing a common prefix collapse to prefix+XX
// ("VL1>VLXX (RDP)"); additional services get a +N marker.
func policyBaseName(orig *OrigPolicy, p RecPolicy) string {
	label := "ANY"
	switch {
	case hasTag(p, "active-directory"):
		label = "AD"
	case len(p.Services) > 0:
		label = svcDisplay(p.Services[0])
		if len(p.Services) > 1 {
			label += fmt.Sprintf("+%d", len(p.Services)-1)
		}
	}
	return fmt.Sprintf("%s>%s (%s)", ifaceLabel(orig.SrcIntf), ifaceLabel(orig.DstIntf), label)
}

func hasTag(p RecPolicy, tag string) bool {
	for _, t := range p.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// ifaceLabel renders one side of the policy path: a single interface keeps
// its (uppercased) name; multiple interfaces sharing the same non-numeric
// prefix collapse to prefix+"XX" (VL2+VL3 → VLXX); mixed prefixes become
// "MULTI".
func ifaceLabel(intfs []string) string {
	switch len(intfs) {
	case 0:
		return "ANY"
	case 1:
		return strings.ToUpper(intfs[0])
	}
	prefix := nonDigitPrefix(intfs[0])
	for _, s := range intfs[1:] {
		if !strings.EqualFold(nonDigitPrefix(s), prefix) {
			return "MULTI"
		}
	}
	if prefix == "" {
		return "MULTI"
	}
	return strings.ToUpper(prefix) + "XX"
}

// nonDigitPrefix returns the part of an interface name before its first digit
// ("VL100" → "VL", "port1" → "port").
func nonDigitPrefix(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return s[:i]
		}
	}
	return s
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
