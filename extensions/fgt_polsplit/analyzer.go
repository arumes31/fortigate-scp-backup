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
		if t.Port <= 0 || t.Port > 65535 {
			return t.Proto + "/any"
		}
		return fmt.Sprintf("%s/%d", t.Proto, t.Port)
	default:
		return t.Proto // icmp, icmp6, ip-<n>
	}
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
	for _, t := range tuples {
		if t.IPv6 {
			a.IPv6Skipped++
			continue
		}
		if net.ParseIP(t.SrcIP) == nil || net.ParseIP(t.DstIP) == nil {
			continue // aggregation artifacts ("(Empty Value)", garbage rows)
		}
		a.Tuples = append(a.Tuples, t)
		key := svcKey(t)
		spec, ok := a.Services[key]
		if !ok {
			port := t.Port
			if strings.HasSuffix(key, "/any") {
				port = 0 // unusable port collapsed; the spec must not carry it
			}
			spec = ServiceSpec{Key: key, Proto: t.Proto, Port: port}
		}
		// Prefer a named service from the logs; first non-generic name wins.
		if spec.LogName == "" && t.Service != "" && !strings.Contains(t.Service, "/") {
			spec.LogName = t.Service
		}
		a.Services[key] = spec
	}
	sort.SliceStable(a.Tuples, func(i, j int) bool { return a.Tuples[i].Hits > a.Tuples[j].Hits })

	a.SrcEnts = buildEntities(a.Tuples, true, opts.RollupSrc, opts)
	a.DstEnts = buildEntities(a.Tuples, false, opts.RollupDst, opts)
	if a.IPv6Skipped > 0 {
		a.Warnings = append(a.Warnings,
			fmt.Sprintf("%d IPv6 tuple(s) observed but excluded — generated config is IPv4-only", a.IPv6Skipped))
	}
	return a
}

// buildEntities maps every observed IP on one side to its entity: itself, or
// its /mask network when rollup is on and at least threshold distinct hosts of
// that network were observed on this side.
func buildEntities(tuples []TrafficTuple, srcSide, rollup bool, opts AnalyzeOptions) map[string]Entity {
	ips := map[string]bool{}
	for _, t := range tuples {
		if srcSide {
			ips[t.SrcIP] = true
		} else {
			ips[t.DstIP] = true
		}
	}
	ents := map[string]Entity{}
	if !rollup {
		for ip := range ips {
			ents[ip] = Entity{Value: ip, Hosts: 1}
		}
		return ents
	}
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
	for ip := range ips {
		cidr, ok := netOf[ip]
		if ok && netHosts[cidr] >= opts.RollupThreshold {
			ents[ip] = Entity{Value: cidr, IsNet: true, Hosts: netHosts[cidr]}
		} else {
			ents[ip] = Entity{Value: ip, Hosts: 1}
		}
	}
	return ents
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

// finalizePolicies applies the post-grouping normalizations shared by every
// strategy — currently the consolidation of adjacent single ports into ranges.
func finalizePolicies(pols []RecPolicy) []RecPolicy {
	for i := range pols {
		pols[i].Services = consolidatePortRanges(pols[i].Services)
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
