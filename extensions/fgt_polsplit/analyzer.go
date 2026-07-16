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
	return mergeGroups(buckets, func(g *sideGroup) string {
		return entitySig(g.src) + "|" + specSig(g.svcs)
	})
}
