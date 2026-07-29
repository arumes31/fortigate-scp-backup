// Fleet IPAM: aggregates every firewall's networks (interface addresses,
// secondary IPs, DHCP scopes, static route destinations and subnet address
// objects) from the cached audit parse of its latest config backup, and
// reports prefixes that overlap ACROSS firewalls. Overlaps inside one
// firewall (an interface, its DHCP scope and its route) are normal and not
// flagged; 0.0.0.0/0 and /32 hosts are excluded from overlap analysis.
package web

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ipamEntry is one prefix in use on one firewall.
type ipamEntry struct {
	Prefix string `json:"prefix"` // canonical CIDR, e.g. "10.20.0.0/24"
	FwID   int    `json:"fw_id"`
	FQDN   string `json:"fqdn"`
	Source string `json:"source"` // interface | secondary | route | dhcp | address
	Name   string `json:"name"`   // interface/object name or detail
}

// ipamOverlap is one cross-firewall collision between two prefixes.
type ipamOverlap struct {
	Kind string    `json:"kind"` // duplicate | containment
	A    ipamEntry `json:"a"`
	B    ipamEntry `json:"b"`
}

type ipamResponse struct {
	Firewalls int           `json:"firewalls"`
	Scanned   int           `json:"scanned"` // firewalls with a parsed config
	Prefixes  int           `json:"prefixes"`
	Entries   []ipamEntry   `json:"entries"`
	Overlaps  []ipamOverlap `json:"overlaps"`
}

// prefixFromIPMask converts "10.1.2.3" + "255.255.255.0" into the canonical
// network prefix 10.1.2.0/24. Returns invalid on any malformed input.
func prefixFromIPMask(ipStr, maskStr string) netip.Prefix {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !ip.Is4() {
		return netip.Prefix{}
	}
	mask, err := netip.ParseAddr(strings.TrimSpace(maskStr))
	if err != nil || !mask.Is4() {
		return netip.Prefix{}
	}
	m := mask.As4()
	ones := 0
	seenZero := false
	for _, b := range m {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<uint(bit)) != 0 {
				if seenZero {
					return netip.Prefix{} // non-contiguous mask
				}
				ones++
			} else {
				seenZero = true
			}
		}
	}
	return netip.PrefixFrom(ip, ones).Masked()
}

// prefixFromRouteDst converts a static-route "set dst A.B.C.D M.M.M.M" value
// (already space-joined by the parser) into a prefix.
func prefixFromRouteDst(dst string) netip.Prefix {
	f := strings.Fields(dst)
	if len(f) == 2 {
		return prefixFromIPMask(f[0], f[1])
	}
	if len(f) == 1 && strings.Contains(f[0], "/") {
		p, err := netip.ParsePrefix(f[0])
		if err != nil || !p.Addr().Is4() {
			return netip.Prefix{}
		}
		return p.Masked()
	}
	return netip.Prefix{}
}

// ipamEntriesFor extracts one firewall's IPAM entries from its parsed config.
func ipamEntriesFor(res *auditResult, fwID int, fqdn string) []ipamEntry {
	var out []ipamEntry
	add := func(p netip.Prefix, source, name string) {
		if !p.IsValid() {
			return
		}
		out = append(out, ipamEntry{Prefix: p.String(), FwID: fwID, FQDN: fqdn, Source: source, Name: name})
	}
	for _, it := range res.Interfaces {
		if it.IP != "" && it.IP != "0.0.0.0" {
			add(prefixFromIPMask(it.IP, it.Mask), "interface", it.Name)
		}
		for _, sec := range it.SecondaryIPs {
			f := strings.Fields(sec)
			if len(f) == 2 {
				add(prefixFromIPMask(f[0], f[1]), "secondary", it.Name)
			}
		}
	}
	for _, r := range res.Routes {
		if r.Dst == "" || strings.HasPrefix(r.Dst, "0.0.0.0") {
			continue // default routes carry no subnet information
		}
		add(prefixFromRouteDst(r.Dst), "route", "route "+r.ID+" via "+r.Device)
	}
	for _, d := range res.DhcpServers {
		// A DHCP scope's network is its gateway+netmask; ranges are shown as
		// the detail text.
		if d.Gateway != "" && d.Netmask != "" {
			add(prefixFromIPMask(d.Gateway, d.Netmask), "dhcp", d.Interface+" ("+strings.Join(d.Ranges, ", ")+")")
		}
	}
	for _, ao := range res.AddressObjs {
		add(prefixFromIPMask(ao.IP, ao.Mask), "address", ao.Name)
	}
	return out
}

// findOverlaps reports collisions between prefixes of DIFFERENT firewalls.
// 0.0.0.0/0 and /32 hosts are skipped as noise. For each colliding pair one
// overlap row is emitted: "duplicate" when the prefixes are identical,
// "containment" when one contains the other (partial overlap is impossible
// between valid CIDR prefixes — two prefixes either nest or are disjoint).
func findOverlaps(entries []ipamEntry) []ipamOverlap {
	type parsed struct {
		e ipamEntry
		p netip.Prefix
	}
	var ps []parsed
	for _, e := range entries {
		p, err := netip.ParsePrefix(e.Prefix)
		if err != nil || p.Bits() == 0 || p.Bits() >= 32 {
			continue
		}
		ps = append(ps, parsed{e, p})
	}
	// Deduplicate identical (prefix, firewall, source, name) rows first so the
	// report never pairs an entry with its own duplicate listing.
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].p.Bits() != ps[j].p.Bits() {
			return ps[i].p.Bits() < ps[j].p.Bits()
		}
		return ps[i].p.Addr().Less(ps[j].p.Addr())
	})
	var out []ipamOverlap
	seen := map[string]bool{}
	for i := 0; i < len(ps); i++ {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			if a.e.FwID == b.e.FwID {
				continue
			}
			if !a.p.Overlaps(b.p) {
				continue
			}
			kind := "containment"
			if a.p == b.p {
				kind = "duplicate"
			}
			// One row per (pair of prefixes, pair of firewalls) — source-level
			// fan-out (interface+dhcp+route on both sides) would explode the list.
			key := a.p.String() + "|" + b.p.String() + "|" + strconv.Itoa(a.e.FwID) + "|" + strconv.Itoa(b.e.FwID)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ipamOverlap{Kind: kind, A: a.e, B: b.e})
		}
	}
	// Duplicates first, then by prefix.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == "duplicate"
		}
		return out[i].A.Prefix < out[j].A.Prefix
	})
	return out
}

// ---- handlers ---------------------------------------------------------------

type ipamData struct {
	Base  BaseData
	Error string
}

// handleIPAM renders the page shell; the data loads asynchronously from
// /ipam/data so a cold audit cache never blocks first paint.
func (s *Server) handleIPAM(w http.ResponseWriter, r *http.Request) {
	s.render(w, "ipam.html", ipamData{Base: s.base(r, "IPAM", "ipam")})
}

// handleIPAMData aggregates the fleet. Cached audit results make this cheap;
// cold entries are parsed with bounded concurrency.
func (s *Server) handleIPAMData(w http.ResponseWriter, r *http.Request) {
	fws, err := s.store.ListFirewallRefs(r.Context())
	if err != nil {
		s.logger.Error("ipam: list firewalls failed", "err", err)
		http.Error(w, "failed to list firewalls", http.StatusInternalServerError)
		return
	}
	db, err := s.insightsDB()
	if err != nil {
		s.logger.Error("ipam: insights DB unavailable", "err", err)
		http.Error(w, "insights DB unavailable", http.StatusInternalServerError)
		return
	}

	var (
		mu      sync.Mutex
		entries []ipamEntry
		scanned int
		sem     = make(chan struct{}, 4)
		wg      sync.WaitGroup
	)
	for _, fw := range fws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, ok := s.auditResultFor(db, fw.ID)
			if !ok || res == nil {
				return
			}
			ents := ipamEntriesFor(res, fw.ID, fw.FQDN)
			mu.Lock()
			scanned++
			entries = append(entries, ents...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Prefix != entries[j].Prefix {
			return entries[i].Prefix < entries[j].Prefix
		}
		return entries[i].FQDN < entries[j].FQDN
	})
	unique := map[string]bool{}
	for _, e := range entries {
		unique[e.Prefix] = true
	}

	resp := ipamResponse{
		Firewalls: len(fws),
		Scanned:   scanned,
		Prefixes:  len(unique),
		Entries:   entries,
		Overlaps:  findOverlaps(entries),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
