package fgt_polsplit

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// clonePolicyKeys are the `set` keys copied verbatim from the original policy
// into every split policy: interfaces, action/schedule, NAT and UTM/shaping
// settings. Deliberately absent: name/uuid/srcaddr/dstaddr/service (replaced
// per recommendation), logtraffic* (forced to `all` on splits), status and
// comments (set explicitly).
var clonePolicyKeys = map[string]bool{
	"srcintf": true, "dstintf": true,
	"action": true, "schedule": true, "schedule-timeout": true,
	"nat": true, "ippool": true, "poolname": true, "fixedport": true,
	"nat64": true, "nat46": true, "match-vip": true,
	"utm-status": true, "profile-type": true, "profile-group": true,
	"ssl-ssh-profile": true, "av-profile": true, "webfilter-profile": true,
	"dnsfilter-profile": true, "emailfilter-profile": true, "spamfilter-profile": true,
	"dlp-profile": true, "dlp-sensor": true, "file-filter-profile": true,
	"application-list": true, "ips-sensor": true, "voip-profile": true,
	"sctp-filter-profile": true, "icap-profile": true, "waf-profile": true,
	"profile-protocol-options": true, "inspection-mode": true,
	"users": true, "groups": true, "fsso-groups": true,
	"traffic-shaper": true, "traffic-shaper-reverse": true, "per-ip-shaper": true,
	"tcp-mss-sender": true, "tcp-mss-receiver": true, "session-ttl": true,
	"auto-asic-offload": true, "np-acceleration": true,
	"vlan-cos-fwd": true, "vlan-cos-rev": true,
}

// splitConfigValues splits a FortiGate `set` value list into its members,
// honouring double quotes: `"VL100" "eworx GUEST" always` → [VL100, eworx GUEST, always].
func splitConfigValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			if inQuote {
				out = append(out, cur.String())
				cur.Reset()
			}
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		case c == '\\' && inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// addrEntry / svcEntry accumulate one object while its section is open.
type addrEntry struct {
	name    string
	typ     string // "" (ipmask) | iprange | fqdn | dynamic | …
	subnet  string // "ip mask"
	startIP string
	endIP   string
}

type svcEntry struct {
	name     string
	protocol string // "" (TCP/UDP/SCTP default) | IP | ICMP | ICMP6
	icmpType string
	protoNum string
	ranges   map[string][]string // proto → port-range tokens ("443", "80-90", "443:1024-65535")
}

type policyEntry struct {
	id    int
	vdom  string
	pol   OrigPolicy
	lines []string
}

// frame is one level of the `config … end` nesting stack.
type frame struct {
	section string
	edit    string
}

// ParseBackup scans a decrypted FortiGate configuration and extracts the
// requested policy plus the object inventory needed to build split
// recommendations. It is VDOM-aware: sections inside `config vdom / edit X`
// are attributed to VDOM X, and the used-policy-ID list is restricted to the
// VDOM where the requested policy matched (first match wins on ambiguity).
func ParseBackup(content string, policyID int) *ParsedBackup {
	pb := &ParsedBackup{
		AddrByCIDR: map[string][]string{},
		SvcByKey:   map[string][]string{},
		SvcNames:   map[string]string{},
		TakenNames: map[string]bool{},
	}

	var stack []frame
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return &stack[len(stack)-1]
	}
	currentVDOM := func() string {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].section == "vdom" {
				return stack[i].edit
			}
		}
		return ""
	}

	var addr *addrEntry
	var svc *svcEntry
	var pol *policyEntry
	policyIDsByVDOM := map[string][]int{}
	var matched []*policyEntry

	finishAddr := func() {
		if addr == nil {
			return
		}
		pb.TakenNames[strings.ToLower(addr.name)] = true
		if cidr := addr.cidr(); cidr != "" {
			pb.AddrByCIDR[cidr] = append(pb.AddrByCIDR[cidr], addr.name)
		}
		addr = nil
	}
	finishSvc := func() {
		if svc == nil {
			return
		}
		pb.TakenNames[strings.ToLower(svc.name)] = true
		pb.SvcNames[strings.ToLower(svc.name)] = svc.name
		if key := svc.singleKey(); key != "" {
			pb.SvcByKey[key] = append(pb.SvcByKey[key], svc.name)
		}
		svc = nil
	}
	finishPol := func() {
		if pol == nil {
			return
		}
		policyIDsByVDOM[pol.vdom] = append(policyIDsByVDOM[pol.vdom], pol.id)
		if pol.id == policyID {
			p := pol.pol
			p.ID = pol.id
			p.VDOM = pol.vdom
			p.CloneLines = pol.lines
			matched = append(matched, &policyEntry{id: pol.id, vdom: pol.vdom, pol: p})
		}
		pol = nil
	}
	// finishSection finalizes the open entry belonging to one section. Keeping
	// this section-scoped matters: a nested sub-table inside an object (e.g.
	// `config tagging` inside an address) must not finalize the outer entry.
	finishSection := func(section string) {
		switch section {
		case "firewall address":
			finishAddr()
		case "firewall service custom":
			finishSvc()
		case "firewall policy":
			finishPol()
		}
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		switch {
		case strings.HasPrefix(line, "config "):
			stack = append(stack, frame{section: strings.TrimSpace(strings.TrimPrefix(line, "config "))})
		case line == "end":
			if f := top(); f != nil {
				finishSection(f.section) // covers an entry closed by `end` without `next`
				stack = stack[:len(stack)-1]
			}
		case line == "next":
			if f := top(); f != nil {
				finishSection(f.section)
				f.edit = ""
			}
		case strings.HasPrefix(line, "edit "):
			f := top()
			if f == nil {
				continue
			}
			finishSection(f.section)
			name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "edit ")), `"`)
			f.edit = name
			switch f.section {
			case "firewall address":
				addr = &addrEntry{name: name}
			case "firewall service custom":
				svc = &svcEntry{name: name, ranges: map[string][]string{}}
			case "firewall addrgrp", "firewall service group":
				pb.TakenNames[strings.ToLower(name)] = true
				if f.section == "firewall service group" {
					pb.SvcNames[strings.ToLower(name)] = name
				}
			case "firewall policy":
				if id, err := strconv.Atoi(name); err == nil {
					pol = &policyEntry{id: id, vdom: currentVDOM()}
				}
			}
		case strings.HasPrefix(line, "set "):
			f := top()
			if f == nil || f.edit == "" {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(line, "set "))
			sp := strings.IndexByte(rest, ' ')
			if sp <= 0 {
				continue
			}
			key, val := rest[:sp], strings.TrimSpace(rest[sp+1:])
			switch {
			case addr != nil && f.section == "firewall address":
				switch key {
				case "type":
					addr.typ = val
				case "subnet":
					addr.subnet = val
				case "start-ip":
					addr.startIP = val
				case "end-ip":
					addr.endIP = val
				}
			case svc != nil && f.section == "firewall service custom":
				switch key {
				case "protocol":
					svc.protocol = val
				case "protocol-number":
					svc.protoNum = val
				case "icmptype":
					svc.icmpType = val
				case "tcp-portrange", "udp-portrange", "sctp-portrange":
					proto := strings.TrimSuffix(key, "-portrange")
					svc.ranges[proto] = append(svc.ranges[proto], splitConfigValues(val)...)
				}
			case pol != nil && f.section == "firewall policy":
				if clonePolicyKeys[key] {
					pol.lines = append(pol.lines, line)
				}
				switch key {
				case "name":
					pol.pol.Name = strings.Trim(val, `"`)
				case "srcintf":
					pol.pol.SrcIntf = splitConfigValues(val)
				case "dstintf":
					pol.pol.DstIntf = splitConfigValues(val)
				case "srcaddr":
					pol.pol.SrcAddr = splitConfigValues(val)
				case "dstaddr":
					pol.pol.DstAddr = splitConfigValues(val)
				case "service":
					pol.pol.Services = splitConfigValues(val)
				case "action":
					pol.pol.Action = val
				case "schedule":
					pol.pol.Schedule = strings.Trim(val, `"`)
				case "nat":
					pol.pol.NAT = val
				case "status":
					pol.pol.Status = val
				case "comments":
					pol.pol.Comments = strings.Trim(val, `"`)
				}
			}
		}
	}
	// Truncated config (no trailing end): finalize whatever is still open.
	finishAddr()
	finishSvc()
	finishPol()

	for _, m := range matched {
		pb.PolicyVDOMs = append(pb.PolicyVDOMs, m.vdom)
	}
	if len(matched) > 0 {
		p := matched[0].pol
		pb.Policy = &p
		pb.UsedPolicyIDs = policyIDsByVDOM[matched[0].vdom]
		sort.Ints(pb.UsedPolicyIDs)
	}
	for k := range pb.AddrByCIDR {
		sort.Strings(pb.AddrByCIDR[k])
	}
	for k := range pb.SvcByKey {
		sort.Strings(pb.SvcByKey[k])
	}
	return pb
}

// cidr returns the exact host/subnet CIDR an address object covers, or "" when
// the object is not representable that way (FQDN, dynamic, multi-host ranges).
func (a *addrEntry) cidr() string {
	switch a.typ {
	case "", "ipmask":
		fields := strings.Fields(a.subnet)
		if len(fields) != 2 {
			return ""
		}
		ip := net.ParseIP(fields[0])
		mask := net.ParseIP(fields[1])
		if ip == nil || mask == nil {
			return ""
		}
		m4 := mask.To4()
		if m4 == nil {
			return ""
		}
		ones, bits := net.IPMask(m4).Size()
		if bits != 32 {
			return ""
		}
		return fmt.Sprintf("%s/%d", ip.Mask(net.IPMask(m4)).String(), ones)
	case "iprange":
		if a.startIP != "" && a.startIP == a.endIP {
			if ip := net.ParseIP(a.startIP); ip != nil && ip.To4() != nil {
				return a.startIP + "/32"
			}
		}
	}
	return ""
}

// singleKey returns the canonical service key ("tcp/443", "icmp") when the
// object matches exactly one protocol/port, so it can substitute for observed
// traffic without widening scope. Ranges, port lists and source-port
// restrictions return "".
func (s *svcEntry) singleKey() string {
	switch strings.ToUpper(s.protocol) {
	case "ICMP":
		if s.icmpType == "" {
			return "icmp"
		}
		return ""
	case "ICMP6":
		if s.icmpType == "" {
			return "icmp6"
		}
		return ""
	case "IP":
		if s.protoNum != "" {
			return "ip-" + s.protoNum
		}
		return ""
	}
	var key string
	total := 0
	for proto, tokens := range s.ranges {
		for _, tok := range tokens {
			total++
			if total > 1 {
				return ""
			}
			dst := tok
			if i := strings.IndexByte(dst, ':'); i >= 0 {
				return "" // source-port restricted
			}
			if strings.Contains(dst, "-") {
				lohi := strings.SplitN(dst, "-", 2)
				if len(lohi) != 2 || lohi[0] != lohi[1] {
					return ""
				}
				dst = lohi[0]
			}
			if p, err := strconv.Atoi(dst); err == nil && p > 0 {
				key = fmt.Sprintf("%s/%d", proto, p)
			}
		}
	}
	return key
}
