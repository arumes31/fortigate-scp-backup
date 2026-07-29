// Fleet IPAM: aggregates every firewall's networks (interface addresses,
// secondary IPs, DHCP scopes, static route destinations and subnet address
// objects) from the cached audit parse of its latest config backup, and
// reports prefixes that overlap ACROSS firewalls. Overlaps inside one
// firewall (an interface, its DHCP scope and its route) are normal and not
// flagged; 0.0.0.0/0 and /32 hosts are excluded from overlap analysis.
//
// The aggregation can be expensive (a cold audit cache means one full config
// parse per firewall), so it never runs inside a page request: /ipam/data
// serves a stored snapshot instantly, and the snapshot is recomputed by a
// background sweep — daily via the scheduler, on demand via POST
// /ipam/refresh, or automatically on the first visit — with progress the
// page polls and renders.
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// ipamEntry is one prefix in use on one firewall.
type ipamEntry struct {
	Prefix string `json:"prefix"` // canonical CIDR, e.g. "10.20.0.0/24"
	FwID   int    `json:"fw_id"`
	FQDN   string `json:"fqdn"`
	Source string `json:"source"` // interface | secondary | route | dhcp | address
	Name   string `json:"name"`   // interface/object name or detail
}

// ipamOverlap is one cross-firewall collision, GROUPED by prefix. Grouping is
// essential at fleet scale: a template-deployed prefix shared by 147 firewalls
// is one row with a count — not the ~10,700 pairwise rows that made the
// original pair-based report balloon to hundreds of MB.
type ipamOverlap struct {
	Kind      string   `json:"kind"`            // duplicate | containment
	Prefix    string   `json:"prefix"`          // duplicate: the shared prefix; containment: the outer prefix
	Inner     string   `json:"inner,omitempty"` // containment: the contained prefix
	Count     int      `json:"count"`           // distinct firewalls involved
	Firewalls []string `json:"firewalls"`       // capped samples: "fqdn (detail)"
}

const (
	// ipamOverlapMaxRows caps how many overlap groups are stored/rendered;
	// the total is still reported so truncation is visible.
	ipamOverlapMaxRows = 500
	// ipamOverlapMaxFws caps the example firewalls listed per overlap group.
	ipamOverlapMaxFws = 6
)

// ipamSnapshot is the stored fleet aggregation.
type ipamSnapshot struct {
	Firewalls     int           `json:"firewalls"`
	Scanned       int           `json:"scanned"` // firewalls with a parsed config
	Prefixes      int           `json:"prefixes"`
	Entries       []ipamEntry   `json:"entries"`
	Overlaps      []ipamOverlap `json:"overlaps"`
	OverlapsTotal int           `json:"overlaps_total"`
}

// ipamDataOut is the /ipam/data payload: the stored snapshot (if any) plus
// the live progress of a running recompute. The snapshot is passed through as
// raw JSON — it was serialized by refreshIPAM, and re-decoding a multi-MB
// blob on every page load would burn CPU for nothing.
type ipamDataOut struct {
	Running    bool            `json:"running"`
	Done       int             `json:"done"`
	Total      int             `json:"total"`
	Current    string          `json:"current,omitempty"`
	ComputedAt string          `json:"computed_at,omitempty"`
	Snapshot   json.RawMessage `json:"snapshot,omitempty"`
}

// sweepProgress tracks one background fleet sweep (IPAM aggregation, license
// collection) for the pages' progress display. begin() also coalesces: only
// one sweep of a kind runs at a time.
type sweepProgress struct {
	mu      sync.Mutex
	running bool
	done    int
	total   int
	current string
}

// begin marks the sweep started; it returns false when one is already
// running, in which case the caller must not proceed.
func (p *sweepProgress) begin(total int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return false
	}
	p.running, p.done, p.total, p.current = true, 0, total, ""
	return true
}

func (p *sweepProgress) step(current string) {
	p.mu.Lock()
	p.done++
	p.current = current
	p.mu.Unlock()
}

func (p *sweepProgress) end() {
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()
}

func (p *sweepProgress) snapshot() (running bool, done, total int, current string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running, p.done, p.total, p.current
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

// ipamPrefixGroup collects everything using one exact prefix.
type ipamPrefixGroup struct {
	p     netip.Prefix
	fws   map[int]bool
	names []string // capped samples: "fqdn (detail)"
}

func (g *ipamPrefixGroup) addSample(e ipamEntry) {
	if len(g.names) < ipamOverlapMaxFws && !g.fws[e.FwID] {
		g.names = append(g.names, e.FQDN+" ("+e.Name+")")
	}
	g.fws[e.FwID] = true
}

// crossFirewall reports whether two prefix groups belong to entirely
// DIFFERENT firewalls. Any shared firewall means the nesting is explainable
// as that firewall's own address hierarchy (its LAN under its own aggregate
// route — which other template-deployed sites may carry too), so it is never
// counted as an overlap.
func crossFirewall(a, b *ipamPrefixGroup) bool {
	for fw := range b.fws {
		if a.fws[fw] {
			return false
		}
	}
	return true
}

// findOverlaps reports collisions between prefixes of DIFFERENT firewalls,
// grouped per prefix. 0.0.0.0/0 and /32 hosts are skipped as noise.
//   - duplicate: the same prefix in use on ≥2 firewalls (one row per prefix,
//     however many devices share it).
//   - containment: a prefix nested inside its NEAREST enclosing prefix when
//     different firewalls are involved (partial overlap is impossible between
//     CIDR prefixes — they either nest or are disjoint). The sweep is a
//     sorted stack walk, linear in the number of unique prefixes.
//
// The row list is capped at ipamOverlapMaxRows; the returned total counts all
// groups found so the UI can show truncation.
func findOverlaps(entries []ipamEntry) ([]ipamOverlap, int) {
	groups := map[netip.Prefix]*ipamPrefixGroup{}
	for _, e := range entries {
		p, err := netip.ParsePrefix(e.Prefix)
		if err != nil || p.Bits() == 0 || p.Bits() >= 32 {
			continue
		}
		g := groups[p]
		if g == nil {
			g = &ipamPrefixGroup{p: p, fws: map[int]bool{}}
			groups[p] = g
		}
		g.addSample(e)
	}
	// Sort by address, then shorter prefix first, so an enclosing prefix is
	// always visited before everything nested inside it.
	list := make([]*ipamPrefixGroup, 0, len(groups))
	for _, g := range groups {
		list = append(list, g)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].p.Addr() != list[j].p.Addr() {
			return list[i].p.Addr().Less(list[j].p.Addr())
		}
		return list[i].p.Bits() < list[j].p.Bits()
	})

	var dups, contains []ipamOverlap
	var stack []*ipamPrefixGroup
	for _, g := range list {
		if len(g.fws) >= 2 {
			dups = append(dups, ipamOverlap{
				Kind: "duplicate", Prefix: g.p.String(), Count: len(g.fws), Firewalls: g.names,
			})
		}
		for len(stack) > 0 && !stack[len(stack)-1].p.Contains(g.p.Addr()) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			parent := stack[len(stack)-1]
			if crossFirewall(parent, g) {
				union := map[int]bool{}
				for fw := range parent.fws {
					union[fw] = true
				}
				for fw := range g.fws {
					union[fw] = true
				}
				names := append(append([]string{}, parent.names...), g.names...)
				if len(names) > ipamOverlapMaxFws {
					names = names[:ipamOverlapMaxFws]
				}
				contains = append(contains, ipamOverlap{
					Kind: "containment", Prefix: parent.p.String(), Inner: g.p.String(),
					Count: len(union), Firewalls: names,
				})
			}
		}
		stack = append(stack, g)
	}

	// Most widely shared duplicates first, then containments.
	sort.SliceStable(dups, func(i, j int) bool {
		if dups[i].Count != dups[j].Count {
			return dups[i].Count > dups[j].Count
		}
		return dups[i].Prefix < dups[j].Prefix
	})
	sort.SliceStable(contains, func(i, j int) bool { return contains[i].Prefix < contains[j].Prefix })
	out := append(dups, contains...)
	total := len(out)
	if len(out) > ipamOverlapMaxRows {
		out = out[:ipamOverlapMaxRows]
	}
	return out, total
}

// ---- snapshot compute & storage ---------------------------------------------

// refreshIPAM recomputes the fleet snapshot in the background and stores it.
// Coalesced: a call while a sweep is running is a no-op. Registered with the
// scheduler for a daily run and triggered by POST /ipam/refresh (or the first
// visit when no snapshot exists yet).
func (s *Server) refreshIPAM() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	fws, err := s.store.ListFirewallRefs(ctx)
	cancel()
	if err != nil {
		s.logger.Error("ipam refresh: list firewalls failed", "err", err)
		return
	}
	if !s.ipamProgress.begin(len(fws)) {
		return
	}
	defer s.ipamProgress.end()
	db, err := s.insightsDB()
	if err != nil {
		s.logger.Error("ipam refresh: insights DB unavailable", "err", err)
		return
	}

	var (
		mu      sync.Mutex
		entries []ipamEntry
		scanned int
		sem     = make(chan struct{}, 2) // bound cold-cache config parses
		wg      sync.WaitGroup
	)
	for _, fw := range fws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, ok := s.auditResultFor(db, fw.ID)
			if ok && res != nil {
				ents := ipamEntriesFor(res, fw.ID, fw.FQDN)
				mu.Lock()
				scanned++
				entries = append(entries, ents...)
				mu.Unlock()
			}
			s.ipamProgress.step(fw.FQDN)
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
	overlaps, overlapsTotal := findOverlaps(entries)
	snap := ipamSnapshot{
		Firewalls:     len(fws),
		Scanned:       scanned,
		Prefixes:      len(unique),
		Entries:       entries,
		Overlaps:      overlaps,
		OverlapsTotal: overlapsTotal,
	}
	blob, err := json.Marshal(snap)
	if err != nil {
		s.logger.Error("ipam refresh: marshal failed", "err", err)
		return
	}
	if _, err := db.Exec(`INSERT INTO ipam_cache (id, computed_at, results_json) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET computed_at=excluded.computed_at, results_json=excluded.results_json`,
		time.Now().UTC().Format(time.RFC3339), string(blob)); err != nil {
		s.logger.Error("ipam refresh: store failed", "err", err)
		return
	}
	s.logger.Info("ipam snapshot refreshed", "firewalls", len(fws), "scanned", scanned,
		"prefixes", snap.Prefixes, "overlaps", overlapsTotal)
}

// ---- handlers ---------------------------------------------------------------

type ipamData struct {
	Base  BaseData
	Error string
}

// handleIPAM renders the page shell; data and progress come from /ipam/data.
func (s *Server) handleIPAM(w http.ResponseWriter, r *http.Request) {
	s.render(w, "ipam.html", ipamData{Base: s.base(r, "IPAM", "ipam")})
}

// handleIPAMData serves the stored snapshot plus live sweep progress. It never
// computes anything itself; when no snapshot exists yet it kicks off the
// first background sweep so a fresh install fills in by itself.
func (s *Server) handleIPAMData(w http.ResponseWriter, r *http.Request) {
	db, err := s.insightsDB()
	if err != nil {
		s.logger.Error("ipam: insights DB unavailable", "err", err)
		http.Error(w, "insights DB unavailable", http.StatusInternalServerError)
		return
	}
	out := ipamDataOut{}
	var blob string
	haveSnap := db.QueryRow(`SELECT computed_at, results_json FROM ipam_cache WHERE id = 1`).
		Scan(&out.ComputedAt, &blob) == nil
	if haveSnap {
		out.Snapshot = json.RawMessage(blob)
	}
	out.Running, out.Done, out.Total, out.Current = s.ipamProgress.snapshot()
	if !haveSnap && !out.Running {
		go s.refreshIPAM()
		out.Running = true
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleIPAMRefresh starts a background snapshot recompute (POST).
func (s *Server) handleIPAMRefresh(w http.ResponseWriter, r *http.Request) {
	s.store.LogActivity(s.sess.User(r).Username, "IPAM Refresh", "Triggered fleet IPAM recompute")
	go s.refreshIPAM()
	w.WriteHeader(http.StatusAccepted)
}
