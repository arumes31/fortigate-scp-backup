package fortiosconfig

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type inventory struct {
	addresses, addressGroups, services, serviceGroups, vipGroups, zones map[string]*node
	interfaces                                                          map[string]*node
	vipNames                                                            map[string]bool
	work                                                                *workBudget
	policies, vips                                                      []*node
	central                                                             bool
	unsupportedMode                                                     bool
}

func newInventory() *inventory {
	return &inventory{addresses: map[string]*node{}, addressGroups: map[string]*node{}, services: map[string]*node{}, serviceGroups: map[string]*node{}, vipGroups: map[string]*node{}, zones: map[string]*node{}, interfaces: map[string]*node{}, vipNames: map[string]bool{}, work: newWorkBudget(context.Background())}
}

type selector struct {
	countries    []string
	all, unknown bool
}

func (inv *inventory) sources(names []string) selector {
	var result selector
	if len(names) == 0 {
		result.unknown = true
	}
	seen := map[string]bool{}
	done := map[string]bool{}
	budget := inv.resolverBudget()
	var visit func(string, int)
	visit = func(name string, depth int) {
		if !budget.take() {
			result.unknown = true
			return
		}
		if depth > 64 || seen[name] {
			result.unknown = true
			return
		}
		if done[name] {
			return
		}
		if name == "all" {
			result.all = true
			return
		}
		seen[name] = true
		defer delete(seen, name)
		defer func() { done[name] = true }()
		if g := inv.addressGroups[name]; g != nil {
			if g.get("exclude") == "enable" {
				result.unknown = true
			}
			if len(g.values["member"]) == 0 {
				result.unknown = true
			}
			for _, member := range g.values["member"] {
				if inv.work.err != nil {
					return
				}
				visit(member, depth+1)
			}
			return
		}
		obj := inv.addresses[name]
		if obj == nil {
			result.unknown = true
			return
		}
		switch obj.value("type", "ipmask") {
		case "geography":
			if obj.get("country") == "" {
				result.unknown = true
			} else {
				result.countries = append(result.countries, obj.get("country"))
			}
		case "ipmask":
			if prefix, ok := addressPrefix(obj); !ok {
				result.unknown = true
			} else if prefix.Bits() == 0 {
				result.all = true
			}
		case "iprange":
			lo, errL := netip.ParseAddr(obj.get("start-ip"))
			hi, errH := netip.ParseAddr(obj.get("end-ip"))
			if errL != nil || errH != nil || lo.Is4() != hi.Is4() || lo.Compare(hi) > 0 {
				result.unknown = true
			} else if lo.String() == "0.0.0.0" && hi.String() == "255.255.255.255" {
				result.all = true
			}
		default:
			result.unknown = true
		}
	}
	for _, name := range names {
		if inv.work.err != nil {
			break
		}
		visit(name, 0)
	}
	result.countries = unique(result.countries)
	return result
}

func addressPrefix(n *node) (netip.Prefix, bool) {
	values := n.values["subnet"]
	if len(values) != 2 {
		return netip.Prefix{}, false
	}
	ip, err := netip.ParseAddr(values[0])
	mask, errM := netip.ParseAddr(values[1])
	if err != nil || errM != nil || !ip.Is4() || !mask.Is4() {
		return netip.Prefix{}, false
	}
	bits := 0
	zero := false
	for _, octet := range mask.As4() {
		for bit := 7; bit >= 0; bit-- {
			one := octet&(1<<bit) != 0
			if one {
				if zero {
					return netip.Prefix{}, false
				}
				bits++
			} else {
				zero = true
			}
		}
	}
	return netip.PrefixFrom(ip, bits).Masked(), true
}

// addressMatch returns (contains, uncertain). A positive known member in a
// union is sufficient; otherwise an unresolved member prevents a negative proof.
func (inv *inventory) addressMatch(names []string, ip netip.Addr) (bool, bool) {
	seen := map[string]bool{}
	memo := map[string]matchResult{}
	budget := inv.resolverBudget()
	var visit func(string, int) (bool, bool)
	visit = func(name string, depth int) (yes, uncertain bool) {
		if !budget.take() {
			return false, true
		}
		if known, ok := memo[name]; ok {
			return known.yes, known.unknown
		}
		if name == "all" {
			return true, false
		}
		if depth > 64 || seen[name] {
			return false, true
		}
		seen[name] = true
		defer delete(seen, name)
		defer func() { memo[name] = matchResult{yes, uncertain} }()
		if g := inv.addressGroups[name]; g != nil {
			if g.get("exclude") == "enable" {
				return false, true
			}
			u := false
			for _, m := range g.values["member"] {
				if inv.work.err != nil {
					return false, true
				}
				yes, unknown := visit(m, depth+1)
				if yes {
					return true, false
				}
				u = u || unknown
			}
			return false, u || len(g.values["member"]) == 0
		}
		n := inv.addresses[name]
		if n == nil {
			return false, true
		}
		switch n.value("type", "ipmask") {
		case "ipmask":
			p, ok := addressPrefix(n)
			return ok && p.Contains(ip), !ok
		case "iprange":
			lo, e1 := netip.ParseAddr(n.get("start-ip"))
			hi, e2 := netip.ParseAddr(n.get("end-ip"))
			if e1 != nil || e2 != nil || lo.Is4() != ip.Is4() || hi.Compare(lo) < 0 {
				return false, true
			}
			return ip.Compare(lo) >= 0 && ip.Compare(hi) <= 0, false
		default:
			return false, true
		}
	}
	unknown := len(names) == 0
	for _, name := range names {
		if inv.work.err != nil {
			return false, true
		}
		match, u := visit(name, 0)
		if match {
			return true, false
		}
		unknown = unknown || u
	}
	return false, unknown
}

func (inv *inventory) references(names []string, vip string) (bool, bool) {
	seen := map[string]bool{}
	memo := map[string]matchResult{}
	budget := inv.resolverBudget()
	var visit func(string, int) (bool, bool)
	visit = func(name string, depth int) (yes, uncertain bool) {
		if !budget.take() {
			return false, true
		}
		if known, ok := memo[name]; ok {
			return known.yes, known.unknown
		}
		if name == vip {
			return true, false
		}
		if depth > 64 || seen[name] {
			return false, true
		}
		seen[name] = true
		defer delete(seen, name)
		defer func() { memo[name] = matchResult{yes, uncertain} }()
		if g := inv.vipGroups[name]; g != nil {
			unknown := false
			for _, member := range g.values["member"] {
				if inv.work.err != nil {
					return false, true
				}
				yes, u := visit(member, depth+1)
				if yes {
					return true, false
				}
				unknown = unknown || u
			}
			return false, unknown
		}
		if name == "all" || inv.addresses[name] != nil || inv.addressGroups[name] != nil {
			return false, false
		}
		if inv.vipNames[name] {
			return false, false
		}
		return false, true
	}
	unknown := false
	for _, name := range names {
		if inv.work.err != nil {
			return false, true
		}
		yes, u := visit(name, 0)
		if yes {
			return true, false
		}
		unknown = unknown || u
	}
	return false, unknown
}

func (inv *inventory) interfaceSet(names []string) (map[string]bool, bool) {
	out := map[string]bool{}
	unknown := len(names) == 0
	for _, name := range names {
		if !inv.work.take() {
			return out, true
		}
		if name == "any" {
			out[name] = true
			continue
		}
		if zone := inv.zones[name]; zone != nil {
			if len(zone.values["interface"]) == 0 {
				unknown = true
			}
			for _, m := range zone.values["interface"] {
				if !inv.work.take() {
					return out, true
				}
				out[m] = true
			}
			continue
		}
		// Direct names can be compared even when a per-VDOM export omits the
		// global interface table. Routing/reachability is not inferred here.
		out[name] = true
	}
	return out, unknown
}

func (inv *inventory) interfaceCoverage(super, sub []string) string {
	a, au := inv.interfaceSet(super)
	b, bu := inv.interfaceSet(sub)
	if au || bu {
		return "unknown"
	}
	if a["any"] {
		return "full"
	}
	if b["any"] {
		return "partial"
	}
	matched := 0
	for name := range b {
		if a[name] {
			matched++
		}
	}
	if matched == len(b) {
		return "full"
	}
	if matched > 0 {
		return "partial"
	}
	return "none"
}

type interval struct{ lo, hi int }

// A one-to-one address mapping is not limited to the VIP's port-forwarding
// protocol. Its policy proof must cover all IP protocols, including non-TCP/UDP.
const allIPProtocols = "all-ip"

type serviceSet struct {
	ports        map[string][]interval
	ipProtocols  map[int]bool
	all, unknown bool
}

func newServiceSet() serviceSet {
	return serviceSet{ports: map[string][]interval{}, ipProtocols: map[int]bool{}}
}

func portRange(value string) (interval, bool) {
	if strings.Contains(value, ":") {
		return interval{}, false
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 || len(parts) == 0 {
		return interval{}, false
	}
	lo, e := strconv.Atoi(parts[0])
	if e != nil || lo < 1 || lo > 65535 {
		return interval{}, false
	}
	hi := lo
	if len(parts) == 2 {
		var err error
		hi, err = strconv.Atoi(parts[1])
		if err != nil || hi < lo || hi > 65535 {
			return interval{}, false
		}
	}
	return interval{lo, hi}, true
}

func (inv *inventory) servicesFor(names []string) serviceSet {
	result := newServiceSet()
	result.unknown = len(names) == 0
	seen := map[string]bool{}
	done := map[string]bool{}
	budget := inv.resolverBudget()
	builtins := map[string]map[string][]interval{
		"HTTP": {"tcp": {{80, 80}}}, "HTTPS": {"tcp": {{443, 443}}}, "SSH": {"tcp": {{22, 22}}},
		"FTP": {"tcp": {{21, 21}}}, "SMTP": {"tcp": {{25, 25}}}, "SMTPS": {"tcp": {{465, 465}}},
		"RDP": {"tcp": {{3389, 3389}}}, "DNS": {"tcp": {{53, 53}}, "udp": {{53, 53}}},
		"ALL_TCP": {"tcp": {{1, 65535}}}, "ALL_UDP": {"udp": {{1, 65535}}},
	}
	var visit func(string, int)
	visit = func(name string, depth int) {
		if !budget.take() {
			result.unknown = true
			return
		}
		if depth > 64 || seen[name] {
			result.unknown = true
			return
		}
		if done[name] {
			return
		}
		seen[name] = true
		defer delete(seen, name)
		defer func() { done[name] = true }()
		if g := inv.serviceGroups[name]; g != nil {
			if len(g.values["member"]) == 0 {
				result.unknown = true
			}
			for _, member := range g.values["member"] {
				if inv.work.err != nil {
					return
				}
				visit(member, depth+1)
			}
			return
		}
		if obj := inv.services[name]; obj != nil {
			// Destination-constrained services need NAT-stage address/FQDN
			// evaluation. Until then, they cannot prove service coverage. The
			// default wildcard and the complete IPv4 range are unrestricted.
			if values, present := obj.values["iprange"]; present && (len(values) != 1 || values[0] != "0.0.0.0" && values[0] != "0.0.0.0-255.255.255.255") {
				result.unknown = true
				return
			}
			if values, present := obj.values["fqdn"]; present && (len(values) != 1 || values[0] != "") {
				result.unknown = true
				return
			}
			switch obj.value("protocol", "TCP/UDP/SCTP") {
			case "IP":
				number, err := strconv.Atoi(obj.value("protocol-number", "0"))
				if err != nil || number < 0 || number > 254 {
					result.unknown = true
				} else if number == 0 {
					result.all = true
				} else {
					result.ipProtocols[number] = true
				}
				return
			case "TCP/UDP/SCTP":
			default:
				result.unknown = true
				return
			}
			count := 0
			for _, protocol := range []string{"tcp", "udp", "sctp"} {
				for _, value := range obj.values[protocol+"-portrange"] {
					if !budget.take() {
						result.unknown = true
						return
					}
					bounds, ok := portRange(value)
					if !ok {
						result.unknown = true
						continue
					}
					result.ports[protocol] = append(result.ports[protocol], bounds)
					count++
				}
			}
			if count == 0 {
				result.unknown = true
			}
			return
		}
		if name == "ALL" {
			result.all = true
			return
		}
		if ports, ok := builtins[name]; ok {
			for proto, ranges := range ports {
				result.ports[proto] = append(result.ports[proto], ranges...)
			}
			return
		}
		result.unknown = true
	}
	for _, name := range names {
		if inv.work.err != nil {
			break
		}
		visit(name, 0)
	}
	return result
}

// serviceCoverage returns full, partial, or none for a translated protocol/port
// scope. Narrow services cannot prove coverage of a whole-IP address mapping.
// Unknown service semantics are separate and must never count as a full match.
func serviceCoverage(s serviceSet, proto string, target interval) (string, bool) {
	if s.all {
		return "full", false
	}
	if proto == allIPProtocols {
		if len(s.ports) > 0 || len(s.ipProtocols) > 0 {
			return "partial", s.unknown
		}
		return "none", s.unknown
	}
	var number int
	switch proto {
	case "tcp":
		number = 6
	case "udp":
		number = 17
	case "sctp":
		number = 132
	}
	if s.ipProtocols[number] {
		return "full", s.unknown
	}
	ranges := append([]interval(nil), s.ports[proto]...)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	next := target.lo
	intersects := false
	for _, r := range ranges {
		if r.hi < target.lo || r.lo > target.hi {
			continue
		}
		intersects = true
		if r.lo <= next && r.hi >= next {
			next = r.hi + 1
		}
	}
	if next > target.hi {
		return "full", s.unknown
	}
	if intersects {
		return "partial", s.unknown
	}
	return "none", s.unknown
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
