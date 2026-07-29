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
	"strconv"
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

// ipamOverlap is one cross-firewall collision between two prefixes.
type ipamOverlap struct {
	Kind string    `json:"kind"` // duplicate | containment
	A    ipamEntry `json:"a"`
	B    ipamEntry `json:"b"`
}

// ipamSnapshot is the stored fleet aggregation.
type ipamSnapshot struct {
	Firewalls int           `json:"firewalls"`
	Scanned   int           `json:"scanned"` // firewalls with a parsed config
	Prefixes  int           `json:"prefixes"`
	Entries   []ipamEntry   `json:"entries"`
	Overlaps  []ipamOverlap `json:"overlaps"`
}

// ipamDataOut is the /ipam/data payload: the stored snapshot (if any) plus
// the live progress of a running recompute.
type ipamDataOut struct {
	Running    bool          `json:"running"`
	Done       int           `json:"done"`
	Total      int           `json:"total"`
	Current    string        `json:"current,omitempty"`
	ComputedAt string        `json:"computed_at,omitempty"`
	Snapshot   *ipamSnapshot `json:"snapshot,omitempty"`
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
	snap := ipamSnapshot{
		Firewalls: len(fws),
		Scanned:   scanned,
		Prefixes:  len(unique),
		Entries:   entries,
		Overlaps:  findOverlaps(entries),
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
		"prefixes", snap.Prefixes, "overlaps", len(snap.Overlaps))
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
		var snap ipamSnapshot
		if err := json.Unmarshal([]byte(blob), &snap); err == nil {
			out.Snapshot = &snap
		}
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
