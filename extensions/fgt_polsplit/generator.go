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
	base = sanitizeName(base)
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

// Generate turns one strategy's recommended policies into FortiGate CLI. It
// reuses existing address/service objects on exact match, creates the missing
// ones under the given prefix, allocates free policy IDs from the backup's ID
// space and emits the sections in dependency order, followed by `move`
// statements (new policies must sit above the original) and a block disabling
// the original policy.
func Generate(orig *OrigPolicy, parsed *ParsedBackup, policies []RecPolicy, prefix, strategyKey string) GenResult {
	res := GenResult{}
	if len(policies) == 0 {
		return res
	}
	prefix = sanitizeName(prefix)
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
			case "tcp", "udp", "sctp":
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
		if len(names) <= groupInlineMax {
			return names
		}
		sig := strings.Join(names, "|")
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
		p.Name = polNamer.alloc(policyBaseName(prefix, *p, strategyKey), 35)

		src := resolveSide(p.Src, p.Name, "src")
		dst := resolveSide(p.Dst, p.Name, "dst")
		svcs := make([]string, 0, len(p.Services))
		for _, s := range p.Services {
			svcs = append(svcs, resolveService(s))
		}
		sort.Strings(svcs)

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
		fmt.Fprintf(&b, "        set comments %q\n", fmt.Sprintf("Split from policy %d (FortiSafe polsplit)", orig.ID))
		b.WriteString("    next")
		polDefs = append(polDefs, b.String())

		moves = append(moves, fmt.Sprintf("    move %d before %d", p.ID, orig.ID))
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

// policyBaseName builds a readable policy name: prefix + the strategy's
// grouping dimension (service or destination), with a +N marker when the
// policy merged several of them.
func policyBaseName(prefix string, p RecPolicy, strategyKey string) string {
	label := ""
	if strategyKey == "per_destination" && len(p.Dst) > 0 {
		label = p.Dst[0].Value
		if len(p.Dst) > 1 {
			label += fmt.Sprintf("+%d", len(p.Dst)-1)
		}
	} else if len(p.Services) > 0 {
		label = svcDisplay(p.Services[0])
		if len(p.Services) > 1 {
			label += fmt.Sprintf("+%d", len(p.Services)-1)
		}
	}
	return prefix + "-" + label
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
