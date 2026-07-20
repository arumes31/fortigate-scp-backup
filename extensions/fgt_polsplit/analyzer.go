package fgt_polsplit

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// AnalyzeOptions controls tuple normalization and subnet rollup.
type AnalyzeOptions struct {
	RollupSrc       bool
	RollupDst       bool
	RollupThreshold int // min observed hosts in one net to collapse (default 5)
	RollupMask      int // prefix bits of the rollup net (default 24)
	// WANAsAll collapses PUBLIC destination IPs to the built-in "all" object:
	// internet endpoints (CDNs, cloud) rotate constantly, so enumerating them
	// into address objects produces brittle policies — the restriction value
	// comes from the service dimension. Private destinations stay explicit.
	WANAsAll bool
	// FirewallIPs are the firewall's own interface addresses; flows targeting
	// them are local-in traffic and are excluded from recommendations.
	FirewallIPs map[string]bool
}

// privateNets classify addresses that must NOT be collapsed to the WAN "all"
// object: RFC1918 + CGNAT + link-local + loopback (genuinely private), plus
// the non-public-unicast ranges (this-network 0/8, multicast 224/4, reserved
// 240/4 incl. 255.255.255.255) and the special-purpose blocks (IETF protocol
// assignments 192.0.0.0/24, TEST-NET-1/2/3, benchmarking 198.18.0.0/15) — a
// degenerate dstip from a Graylog row must not be mistaken for a routable
// internet destination.
var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
		"0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
		"192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// isPrivateIPv4 reports whether ip is a non-public-internet IPv4 address
// (RFC1918/CGNAT/link-local/loopback or this-network/multicast/reserved).
// Only IPv4 is considered; IPv6 always returns false.
func isPrivateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

func (o AnalyzeOptions) normalized() AnalyzeOptions {
	if o.RollupThreshold < 2 {
		o.RollupThreshold = 5
	}
	if o.RollupMask < 8 || o.RollupMask > 30 {
		o.RollupMask = 24
	}
	return o
}

// Analysis is the normalized view of the observed traffic: tuples sorted by
// hits, per-side entity mapping after rollup, and the distinct services.
type Analysis struct {
	Tuples      []TrafficTuple
	IPv6Skipped int
	SrcEnts     map[string]Entity // srcip → entity (host or rolled-up net)
	DstEnts     map[string]Entity
	Services    map[string]ServiceSpec // canonical key → spec
	Warnings    []string
}

// svcKey returns the canonical service identity of a tuple. Port-carrying
// protocols without a usable port (dstport missing or unparseable in the
// logs) collapse to "<proto>/any" so the generator emits a 1-65535 range
// instead of an invalid port 0.
func svcKey(t TrafficTuple) string {
	switch t.Proto {
	case "tcp", "udp", "sctp":
		if t.PortEnd > t.Port && t.Port > 0 {
			return fmt.Sprintf("%s/%d-%d", t.Proto, t.Port, t.PortEnd)
		}
		if t.Port <= 0 || t.Port > 65535 {
			return t.Proto + "/any"
		}
		return fmt.Sprintf("%s/%d", t.Proto, t.Port)
	default:
		return t.Proto // icmp, icmp6, ip-<n>
	}
}

// Pair-pattern ladder thresholds: per (src,dst) pair, classify suspicious
// port spreads before they become hundreds of service objects.
const (
	scanMinPorts       = 24    // distinct tcp ports, all barely hit → port scan
	scanMaxHitsPerPort = 2     //
	rpcMinHighPorts    = 5     // tcp/135 + N dynamic high ports → RPC endpoint mapper
	ftpMinHighPorts    = 5     // tcp/21 + N high ports → passive FTP data channels
	ceilingPorts       = 100   // real traffic on this many ports → recommend a full range, not objects
	dynPortFloor       = 1024  // "high port" boundary
	rpcRangeLo         = 49152 // Windows default dynamic RPC range
)

// preprocessPairs collapses recognized per-pair port patterns: port scans are
// excluded, RPC endpoint-mapper spreads become one dynamic-range service,
// passive-FTP data channels fold into the FTP control tuple, and pairs with
// absurdly many genuinely-used ports collapse to a full tcp range instead of
// generating one object per port.
func preprocessPairs(tuples []TrafficTuple) ([]TrafficTuple, []string) {
	type pairKey struct{ src, dst string }
	pairs := map[pairKey][]int{}
	for i, t := range tuples {
		if t.Proto == "tcp" && t.Port > 0 && t.PortEnd == 0 {
			k := pairKey{t.SrcIP, t.DstIP}
			pairs[k] = append(pairs[k], i)
		}
	}
	keys := make([]pairKey, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].src != keys[j].src {
			return keys[i].src < keys[j].src
		}
		return keys[i].dst < keys[j].dst
	})

	drop := map[int]bool{}
	addHits := map[int]int64{} // fold dropped hits into a surviving tuple
	var synth []TrafficTuple
	scanPairs, rpcPairs, ftpPairs, ceilPairs := 0, 0, 0, 0

	for _, k := range keys {
		idxs := pairs[k]
		if len(idxs) < rpcMinHighPorts {
			continue
		}
		// All tuples of one pair share src/dst, so their IPv6 status is
		// uniform; synthesized tuples must inherit it or IPv6 traffic would
		// leak past the IPv4-only exclusion in Analyze.
		pairV6 := tuples[idxs[0]].IPv6
		ports := map[int]bool{}
		lowPorts := map[int]bool{} // distinct ports with only probe-level hits
		var lowIdxs []int
		var maxHits int64
		ctrl135, ctrl21 := -1, -1
		var highIdxs []int    // ports >= dynPortFloor (1024), used by FTP branch
		var rpcHighIdxs []int // ports >= rpcRangeLo (49152), used by RPC branch
		for _, i := range idxs {
			t := tuples[i]
			ports[t.Port] = true
			if t.Hits > maxHits {
				maxHits = t.Hits
			}
			if t.Hits <= scanMaxHitsPerPort {
				lowPorts[t.Port] = true
				lowIdxs = append(lowIdxs, i)
			}
			switch t.Port {
			case 135:
				ctrl135 = i
			case 21:
				ctrl21 = i
			}
			if t.Port >= dynPortFloor {
				highIdxs = append(highIdxs, i)
			}
			if t.Port >= rpcRangeLo {
				rpcHighIdxs = append(rpcHighIdxs, i)
			}
		}
		switch {
		case len(ports) >= scanMinPorts && maxHits <= scanMaxHitsPerPort:
			// Pure scan: every port barely hit → exclude the whole pair.
			for _, i := range idxs {
				drop[i] = true
			}
			scanPairs++
		case ctrl135 >= 0 && len(rpcHighIdxs) >= rpcMinHighPorts:
			var hits int64
			last := ""
			for _, i := range rpcHighIdxs {
				drop[i] = true
				hits += tuples[i].Hits
				if tuples[i].LastSeen > last {
					last = tuples[i].LastSeen
				}
			}
			synth = append(synth, TrafficTuple{SrcIP: k.src, DstIP: k.dst, Proto: "tcp",
				Port: rpcRangeLo, PortEnd: 65535, Service: "RPC-dynamic", Hits: hits, LastSeen: last, IPv6: pairV6})
			rpcPairs++
		case ctrl21 >= 0 && len(highIdxs) >= ftpMinHighPorts:
			for _, i := range highIdxs {
				drop[i] = true
				addHits[ctrl21] += tuples[i].Hits
			}
			ftpPairs++
		case len(lowPorts) >= scanMinPorts:
			// Mixed pair: genuinely busy port(s) plus a large barely-hit probe
			// tail. Drop only the tail — the established ports stay explicit;
			// the pair must NOT fall through to the ALL-TCP ceiling just
			// because one busy port defeated the pure-scan condition. Ordered
			// after RPC/FTP so their low-hit dynamic ports keep collapsing
			// into their recognized patterns.
			for _, i := range lowIdxs {
				drop[i] = true
			}
			scanPairs++
		case len(ports) >= ceilingPorts:
			var hits int64
			last := ""
			for _, i := range idxs {
				drop[i] = true
				hits += tuples[i].Hits
				if tuples[i].LastSeen > last {
					last = tuples[i].LastSeen
				}
			}
			synth = append(synth, TrafficTuple{SrcIP: k.src, DstIP: k.dst, Proto: "tcp",
				Port: 1, PortEnd: 65535, Service: "ALL-TCP", Hits: hits, LastSeen: last, IPv6: pairV6})
			ceilPairs++
		}
	}
	if len(drop) == 0 && len(synth) == 0 {
		return tuples, nil
	}

	out := make([]TrafficTuple, 0, len(tuples)+len(synth))
	for i, t := range tuples {
		if drop[i] {
			continue
		}
		t.Hits += addHits[i]
		out = append(out, t)
	}
	out = append(out, synth...)

	var w []string
	if scanPairs > 0 {
		w = append(w, fmt.Sprintf("%d src/dst pair(s) looked like port scans (many ports, ≤%d hits each) — excluded from recommendations", scanPairs, scanMaxHitsPerPort))
	}
	if rpcPairs > 0 {
		w = append(w, fmt.Sprintf("%d pair(s) matched the RPC endpoint-mapper pattern (tcp/135 + dynamic high ports) — collapsed to a %d-65535 range", rpcPairs, rpcRangeLo))
	}
	if ftpPairs > 0 {
		w = append(w, fmt.Sprintf("%d pair(s) matched passive FTP (tcp/21 + high data ports) — data channels folded into FTP; ensure the FTP session helper is enabled", ftpPairs))
	}
	if ceilPairs > 0 {
		w = append(w, fmt.Sprintf("%d pair(s) actively used ≥%d distinct tcp ports — collapsed to a full 1-65535 range; REVIEW: this traffic may belong behind a proxy, not a port list", ceilPairs, ceilingPorts))
	}
	return out, w
}

// Analyze normalizes tuples (drops IPv6 for now — generated config is
// IPv4-only), applies subnet rollup per side and collects the service specs.
func Analyze(tuples []TrafficTuple, opts AnalyzeOptions) *Analysis {
	opts = opts.normalized()
	a := &Analysis{
		SrcEnts:  map[string]Entity{},
		DstEnts:  map[string]Entity{},
		Services: map[string]ServiceSpec{},
	}

	// Collapse recognized per-pair port patterns (scans, RPC, passive FTP,
	// port-count ceiling) before any grouping sees them.
	tuples, ppWarnings := preprocessPairs(tuples)
	a.Warnings = append(a.Warnings, ppWarnings...)

	selfSkipped := 0
	for _, t := range tuples {
		if t.IPv6 {
			a.IPv6Skipped++
			continue
		}
		if net.ParseIP(t.SrcIP) == nil || net.ParseIP(t.DstIP) == nil {
			continue // aggregation artifacts ("(Empty Value)", garbage rows)
		}
		if opts.FirewallIPs != nil && opts.FirewallIPs[t.DstIP] {
			// Traffic TO the firewall itself is local-in, not forward traffic.
			selfSkipped++
			continue
		}
		a.Tuples = append(a.Tuples, t)
		key := svcKey(t)
		spec, ok := a.Services[key]
		if !ok {
			port, portEnd := t.Port, t.PortEnd
			if strings.HasSuffix(key, "/any") {
				port, portEnd = 0, 0 // unusable port collapsed; the spec must not carry it
			}
			spec = ServiceSpec{Key: key, Proto: t.Proto, Port: port, PortEnd: portEnd}
		}
		// Prefer a named service from the logs; first non-generic name wins.
		if spec.LogName == "" && t.Service != "" && !strings.Contains(t.Service, "/") {
			spec.LogName = t.Service
		}
		a.Services[key] = spec
	}
	sort.SliceStable(a.Tuples, func(i, j int) bool { return a.Tuples[i].Hits > a.Tuples[j].Hits })

	a.SrcEnts, _ = buildEntities(a.Tuples, true, opts.RollupSrc, opts)
	var forcedDst []string
	a.DstEnts, forcedDst = buildEntities(a.Tuples, false, opts.RollupDst, opts)

	// WAN-bound: public destinations collapse to the built-in "all" object —
	// the split's restriction value comes from the service dimension.
	if opts.WANAsAll {
		pub := 0
		for ip := range a.DstEnts {
			if p := net.ParseIP(ip); p != nil && p.To4() != nil && !isPrivateIPv4(p) {
				pub++
			}
		}
		if pub > 0 {
			for ip := range a.DstEnts {
				if p := net.ParseIP(ip); p != nil && p.To4() != nil && !isPrivateIPv4(p) {
					a.DstEnts[ip] = Entity{Value: "all", IsNet: true, Hosts: pub}
				}
			}
			a.Warnings = append(a.Warnings,
				fmt.Sprintf(`destination is internet-facing — %d public destination(s) collapsed to dstaddr "all" (internet IPs rotate; the services provide the restriction); %d private destination(s) kept explicit`,
					pub, len(a.DstEnts)-pub))
		}
	}

	if len(forcedDst) > 0 {
		a.Warnings = append(a.Warnings,
			fmt.Sprintf("destination subnet(s) %s exceeded %d observed hosts and were rolled up regardless of the rollup setting — enumerating them would produce unusable address groups",
				strings.Join(forcedDst, ", "), forceRollupHosts))
	}
	if selfSkipped > 0 {
		a.Warnings = append(a.Warnings,
			fmt.Sprintf("%d flow(s) target the firewall's own addresses (local-in traffic) — excluded; manage them with local-in policies, not forward policies", selfSkipped))
	}
	if a.IPv6Skipped > 0 {
		a.Warnings = append(a.Warnings,
			fmt.Sprintf("%d IPv6 tuple(s) observed but excluded — generated config is IPv4-only", a.IPv6Skipped))
	}
	return a
}

// forceRollupHosts: a destination net with this many observed hosts rolls up
// even when rollup is disabled — enumerating it would produce an unusable
// address group.
const forceRollupHosts = 64

// buildEntities maps every observed IP on one side to its entity: itself, or
// its /mask network when rollup is on and at least threshold distinct hosts of
// that network were observed on this side. On the destination side, nets with
// ≥forceRollupHosts observed hosts roll up regardless of the rollup setting;
// the affected CIDRs are returned so the caller can warn.
func buildEntities(tuples []TrafficTuple, srcSide, rollup bool, opts AnalyzeOptions) (map[string]Entity, []string) {
	ips := map[string]bool{}
	for _, t := range tuples {
		if srcSide {
			ips[t.SrcIP] = true
		} else {
			ips[t.DstIP] = true
		}
	}
	ents := map[string]Entity{}
	mask := net.CIDRMask(opts.RollupMask, 32)
	netHosts := map[string]int{}
	netOf := map[string]string{}
	for ip := range ips {
		p := net.ParseIP(ip).To4()
		if p == nil {
			ents[ip] = Entity{Value: ip, Hosts: 1}
			continue
		}
		cidr := fmt.Sprintf("%s/%d", p.Mask(mask).String(), opts.RollupMask)
		netOf[ip] = cidr
		netHosts[cidr]++
	}
	forcedSet := map[string]bool{}
	for ip := range ips {
		cidr, ok := netOf[ip]
		switch {
		case ok && rollup && netHosts[cidr] >= opts.RollupThreshold:
			ents[ip] = Entity{Value: cidr, IsNet: true, Hosts: netHosts[cidr]}
		case ok && !srcSide && netHosts[cidr] >= forceRollupHosts:
			ents[ip] = Entity{Value: cidr, IsNet: true, Hosts: netHosts[cidr]}
			if !rollup {
				forcedSet[cidr] = true
			}
		default:
			if _, done := ents[ip]; !done {
				ents[ip] = Entity{Value: ip, Hosts: 1}
			}
		}
	}
	var forced []string
	for c := range forcedSet {
		forced = append(forced, c)
	}
	sort.Strings(forced)
	return ents, forced
}

// sideGroup accumulates one grouping bucket while building a strategy.
type sideGroup struct {
	src  map[string]Entity
	dst  map[string]Entity
	svcs map[string]ServiceSpec
	hits int64
}

func newSideGroup() *sideGroup {
	return &sideGroup{src: map[string]Entity{}, dst: map[string]Entity{}, svcs: map[string]ServiceSpec{}}
}

func (g *sideGroup) add(a *Analysis, t TrafficTuple) {
	se, de := a.SrcEnts[t.SrcIP], a.DstEnts[t.DstIP]
	g.src[se.Value] = se
	g.dst[de.Value] = de
	k := svcKey(t)
	g.svcs[k] = a.Services[k]
	g.hits += t.Hits
}

func sortedEntities(m map[string]Entity) []Entity {
	out := make([]Entity, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func sortedSpecs(m map[string]ServiceSpec) []ServiceSpec {
	out := make([]ServiceSpec, 0, len(m))
	for _, s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func entitySig(m map[string]Entity) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func specSig(m map[string]ServiceSpec) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// mergeGroups collapses buckets that ended up with an identical signature into
// one policy and returns them sorted by traffic volume.
func mergeGroups(buckets map[string]*sideGroup, sig func(*sideGroup) string) []RecPolicy {
	merged := map[string]*sideGroup{}
	for _, g := range buckets {
		s := sig(g)
		if m, ok := merged[s]; ok {
			for k, v := range g.src {
				m.src[k] = v
			}
			for k, v := range g.dst {
				m.dst[k] = v
			}
			for k, v := range g.svcs {
				m.svcs[k] = v
			}
			m.hits += g.hits
		} else {
			cp := *g
			merged[s] = &cp
		}
	}
	out := make([]RecPolicy, 0, len(merged))
	for _, g := range merged {
		out = append(out, RecPolicy{
			Src:      sortedEntities(g.src),
			Dst:      sortedEntities(g.dst),
			Services: sortedSpecs(g.svcs),
			Hits:     g.hits,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return policySortKey(out[i]) < policySortKey(out[j])
	})
	return out
}

func policySortKey(p RecPolicy) string {
	var b strings.Builder
	for _, s := range p.Services {
		b.WriteString(s.Key)
		b.WriteByte(',')
	}
	for _, d := range p.Dst {
		b.WriteString(d.Value)
		b.WriteByte(',')
	}
	return b.String()
}

// BuildPerService groups traffic by service; services whose observed
// source-set and destination-set are identical merge into one policy carrying
// several services.
func BuildPerService(a *Analysis) []RecPolicy {
	return finalizePolicies(buildPerServiceRaw(a))
}

func buildPerServiceRaw(a *Analysis) []RecPolicy {
	buckets := map[string]*sideGroup{}
	for _, t := range a.Tuples {
		k := svcKey(t)
		g, ok := buckets[k]
		if !ok {
			g = newSideGroup()
			buckets[k] = g
		}
		g.add(a, t)
	}
	return mergeGroups(buckets, func(g *sideGroup) string {
		return entitySig(g.src) + "|" + entitySig(g.dst)
	})
}

// BuildPerDestination groups traffic by destination entity; destinations whose
// observed source-set and service-set are identical merge into one policy with
// a destination group.
func BuildPerDestination(a *Analysis) []RecPolicy {
	buckets := map[string]*sideGroup{}
	for _, t := range a.Tuples {
		k := a.DstEnts[t.DstIP].Value
		g, ok := buckets[k]
		if !ok {
			g = newSideGroup()
			buckets[k] = g
		}
		g.add(a, t)
	}
	return finalizePolicies(mergeGroups(buckets, func(g *sideGroup) string {
		return entitySig(g.src) + "|" + specSig(g.svcs)
	}))
}

// hybridJaccard is the minimum overlap (on both the source and destination
// sets) at which the hybrid strategy merges two per-service policies. Below
// 1.0 the merge widens scope slightly — the union of two nearly-identical
// sets — in exchange for fewer policies.
const hybridJaccard = 0.75

// BuildHybrid starts from the per-service grouping and greedily merges
// policies whose source AND destination entity sets overlap strongly
// (Jaccard ≥ hybridJaccard), yielding fewer, slightly wider policies than
// per-service when several services flow between almost the same hosts.
func BuildHybrid(a *Analysis) []RecPolicy {
	pols := buildPerServiceRaw(a)
	for merged := true; merged; {
		merged = false
	scan:
		for i := 0; i < len(pols); i++ {
			for j := i + 1; j < len(pols); j++ {
				if jaccardEntities(pols[i].Src, pols[j].Src) >= hybridJaccard &&
					jaccardEntities(pols[i].Dst, pols[j].Dst) >= hybridJaccard {
					pols[i] = mergePolicies(pols[i], pols[j])
					pols = append(pols[:j], pols[j+1:]...)
					merged = true
					break scan
				}
			}
		}
	}
	sort.SliceStable(pols, func(i, j int) bool {
		if pols[i].Hits != pols[j].Hits {
			return pols[i].Hits > pols[j].Hits
		}
		return policySortKey(pols[i]) < policySortKey(pols[j])
	})
	return finalizePolicies(pols)
}

// jaccardEntities is |A∩B| / |A∪B| over the entity values of two policy sides.
func jaccardEntities(a, b []Entity) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	set := map[string]bool{}
	for _, e := range a {
		set[e.Value] = true
	}
	inter := 0
	for _, e := range b {
		if set[e.Value] {
			inter++
		} else {
			set[e.Value] = true
		}
	}
	return float64(inter) / float64(len(set))
}

// mergePolicies unions two recommendations (entity sets by value, services by
// key) and sums their traffic.
func mergePolicies(a, b RecPolicy) RecPolicy {
	src := map[string]Entity{}
	dst := map[string]Entity{}
	svcs := map[string]ServiceSpec{}
	for _, e := range a.Src {
		src[e.Value] = e
	}
	for _, e := range b.Src {
		src[e.Value] = e
	}
	for _, e := range a.Dst {
		dst[e.Value] = e
	}
	for _, e := range b.Dst {
		dst[e.Value] = e
	}
	for _, s := range a.Services {
		svcs[s.Key] = s
	}
	for _, s := range b.Services {
		svcs[s.Key] = s
	}
	return RecPolicy{
		Src:      sortedEntities(src),
		Dst:      sortedEntities(dst),
		Services: sortedSpecs(svcs),
		Hits:     a.Hits + b.Hits,
	}
}

// wellKnownPortNames labels common ports when the logs carried no service
// name, so policies read "RDP" instead of "tcp/3389". Reuse of existing
// objects stays safe: name matches are only honored when the object's exact
// proto/port also matches.
var wellKnownPortNames = map[string]string{
	"tcp/21": "FTP", "tcp/22": "SSH", "tcp/23": "TELNET", "tcp/25": "SMTP",
	"tcp/80": "HTTP", "tcp/110": "POP3", "tcp/143": "IMAP", "tcp/443": "HTTPS",
	"tcp/445": "SMB", "tcp/465": "SMTPS", "tcp/587": "SMTP-SUBMISSION",
	"tcp/636": "LDAPS", "tcp/993": "IMAPS", "tcp/995": "POP3S",
	"tcp/1433": "MSSQL", "tcp/1521": "ORACLE", "tcp/3306": "MYSQL",
	"tcp/3389": "RDP", "tcp/5432": "POSTGRES", "tcp/5900": "VNC",
	"tcp/8080": "HTTP-ALT", "tcp/8443": "HTTPS-ALT", "tcp/9100": "PRINT-RAW",
	"tcp/389": "LDAP", "tcp/88": "KERBEROS", "tcp/135": "RPC-EPMAP",
	"udp/53": "DNS", "tcp/53": "DNS-TCP", "tcpudp/53": "DNS",
	"udp/67": "DHCP", "udp/69": "TFTP", "udp/123": "NTP",
	"udp/161": "SNMP", "udp/162": "SNMP-TRAP", "udp/500": "IKE",
	"udp/514": "SYSLOG", "tcp/514": "SYSLOG-TCP", "udp/1812": "RADIUS",
	"udp/1813": "RADIUS-ACCT", "udp/4500": "IPSEC-NAT-T",
	"tcpudp/88": "KERBEROS", "tcpudp/389": "LDAP", "tcpudp/464": "KPASSWD",
	"tcp/464": "KPASSWD",
}

// mergeDualProto merges tcp/N + udp/N single-port pairs into one tcpudp/N
// spec, so dual-protocol objects like the builtin DNS (tcp+udp 53) can be
// reused and one object covers both.
func mergeDualProto(specs []ServiceSpec) []ServiceSpec {
	tcpIdx := map[int]int{}
	udpIdx := map[int]int{}
	for i, s := range specs {
		if s.PortEnd != 0 || s.Port <= 0 {
			continue
		}
		switch s.Proto {
		case "tcp":
			tcpIdx[s.Port] = i
		case "udp":
			udpIdx[s.Port] = i
		}
	}
	drop := map[int]bool{}
	var merged []ServiceSpec
	for port, ti := range tcpIdx {
		ui, ok := udpIdx[port]
		if !ok {
			continue
		}
		drop[ti], drop[ui] = true, true
		name := specs[ti].LogName
		if name == "" {
			name = specs[ui].LogName
		}
		merged = append(merged, ServiceSpec{Key: fmt.Sprintf("tcpudp/%d", port), Proto: "tcpudp", Port: port, LogName: name})
	}
	if len(merged) == 0 {
		return specs
	}
	out := make([]ServiceSpec, 0, len(specs))
	for i, s := range specs {
		if !drop[i] {
			out = append(out, s)
		}
	}
	out = append(out, merged...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// adCorePorts are the Active-Directory core service ports; a policy carrying
// three or more of them toward the same destinations is an AD access bundle.
var adCorePorts = map[int]bool{88: true, 135: true, 389: true, 445: true, 464: true, 636: true, 3268: true, 3269: true}

// infraServiceKeys are network-infrastructure services (DNS/NTP/syslog/SNMP).
var infraServiceKeys = map[string]bool{
	"udp/53": true, "tcp/53": true, "tcpudp/53": true,
	"udp/123": true, "udp/514": true, "tcp/514": true, "tcpudp/514": true,
	"udp/161": true, "udp/162": true,
}

// policyTags classifies recognized traffic patterns for display and naming.
func policyTags(p RecPolicy) []string {
	var tags []string
	core := map[int]bool{}
	infra := len(p.Services) > 0
	for _, s := range p.Services {
		if !infraServiceKeys[s.Key] {
			infra = false
		}
		if (s.Proto == "tcp" || s.Proto == "udp" || s.Proto == "tcpudp") && s.PortEnd == 0 && adCorePorts[s.Port] {
			core[s.Port] = true
		}
	}
	if len(core) >= 3 {
		tags = append(tags, "active-directory")
	}
	if infra {
		tags = append(tags, "infrastructure")
	}
	return tags
}

// finalizePolicies applies the post-grouping normalizations shared by every
// strategy: dual-protocol merging, adjacent-port consolidation, well-known
// service labels, and pattern tags.
func finalizePolicies(pols []RecPolicy) []RecPolicy {
	for i := range pols {
		pols[i].Services = consolidatePortRanges(mergeDualProto(pols[i].Services))
		for j := range pols[i].Services {
			if pols[i].Services[j].LogName == "" {
				if n, ok := wellKnownPortNames[pols[i].Services[j].Key]; ok {
					pols[i].Services[j].LogName = n
				}
			}
		}
		pols[i].Tags = policyTags(pols[i])
	}
	return pols
}

// consolidatePortRanges merges runs of adjacent single ports of the same
// protocol (tcp/8080 + tcp/8081 + tcp/8082 → tcp/8080-8082) so the generator
// emits one range object instead of three host objects. Non-adjacent ports,
// portless protocols and pre-existing ranges pass through unchanged.
func consolidatePortRanges(specs []ServiceSpec) []ServiceSpec {
	singles := map[string][]ServiceSpec{}
	var out []ServiceSpec
	for _, s := range specs {
		if (s.Proto == "tcp" || s.Proto == "udp" || s.Proto == "sctp") && s.Port > 0 && s.PortEnd == 0 {
			singles[s.Proto] = append(singles[s.Proto], s)
		} else {
			out = append(out, s)
		}
	}
	for proto, list := range singles {
		sort.Slice(list, func(i, j int) bool { return list[i].Port < list[j].Port })
		for i := 0; i < len(list); {
			j := i
			for j+1 < len(list) && list[j+1].Port == list[j].Port+1 {
				j++
			}
			if j > i {
				out = append(out, ServiceSpec{
					Key:     fmt.Sprintf("%s/%d-%d", proto, list[i].Port, list[j].Port),
					Proto:   proto,
					Port:    list[i].Port,
					PortEnd: list[j].Port,
				})
			} else {
				out = append(out, list[i])
			}
			i = j + 1
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
