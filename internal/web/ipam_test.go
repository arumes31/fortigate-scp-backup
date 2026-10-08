package web

import (
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestPrefixFromIPMask(t *testing.T) {
	cases := []struct{ ip, mask, want string }{
		{"10.20.30.5", "255.255.255.0", "10.20.30.0/24"},
		{"192.168.1.1", "255.255.255.255", "192.168.1.1/32"},
		{"10.0.0.0", "255.0.0.0", "10.0.0.0/8"},
		{"172.16.5.9", "255.255.254.0", "172.16.4.0/23"},
		{"10.1.1.1", "255.0.255.0", ""}, // non-contiguous mask
		{"not-an-ip", "255.255.255.0", ""},
		{"10.1.1.1", "junk", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		p := prefixFromIPMask(c.ip, c.mask)
		got := ""
		if p.IsValid() {
			got = p.String()
		}
		if got != c.want {
			t.Errorf("prefixFromIPMask(%q, %q) = %q, want %q", c.ip, c.mask, got, c.want)
		}
	}
}

func TestPrefixFromRouteDst(t *testing.T) {
	cases := []struct{ dst, want string }{
		{"10.50.0.0 255.255.0.0", "10.50.0.0/16"},
		{"10.50.1.0/24", "10.50.1.0/24"},
		{"garbage", ""},
		{"", ""},
	}
	for _, c := range cases {
		p := prefixFromRouteDst(c.dst)
		got := ""
		if p.IsValid() {
			got = p.String()
		}
		if got != c.want {
			t.Errorf("prefixFromRouteDst(%q) = %q, want %q", c.dst, got, c.want)
		}
	}
}

// ipamParseFixture is a synthetic FortiGate config covering every IPAM source:
// interface + secondaryip, static route, DHCP scope and address objects.
const ipamParseFixture = `config system interface
    edit "lan"
        set ip 10.20.0.1 255.255.255.0
        config secondaryip
            edit 1
                set ip 10.21.0.1 255.255.255.0
            next
        end
        set role lan
    next
    edit "wan1"
        set ip 198.51.100.2 255.255.255.248
    next
end
config router static
    edit 1
        set gateway 198.51.100.1
        set device "wan1"
    next
    edit 2
        set dst 10.30.0.0 255.255.0.0
        set gateway 10.20.0.254
        set device "lan"
    next
end
config system dhcp server
    edit 1
        set default-gateway 10.20.0.1
        set netmask 255.255.255.0
        set interface "lan"
        config ip-range
            edit 1
                set start-ip 10.20.0.100
                set end-ip 10.20.0.200
            next
        end
    next
end
config firewall address
    edit "all"
    next
    edit "net-office"
        set subnet 10.40.0.0 255.255.255.0
    next
    edit "srv-web"
        set type fqdn
        set fqdn "web.example.com"
    next
end
`

func TestParseConfigDataIPAMSources(t *testing.T) {
	pc := parseConfigData(parseCfg(ipamParseFixture))

	var lan *Interface
	for i := range pc.Interfaces {
		if pc.Interfaces[i].Name == "lan" {
			lan = &pc.Interfaces[i]
		}
	}
	if lan == nil {
		t.Fatal("lan interface missing")
	}
	if len(lan.SecondaryIPs) != 1 || lan.SecondaryIPs[0] != "10.21.0.1 255.255.255.0" {
		t.Errorf("secondary IPs = %v", lan.SecondaryIPs)
	}
	// "all" and the fqdn object are skipped; only the subnet object remains.
	if len(pc.AddressObjs) != 1 || pc.AddressObjs[0].Name != "net-office" ||
		pc.AddressObjs[0].IP != "10.40.0.0" || pc.AddressObjs[0].Mask != "255.255.255.0" {
		t.Errorf("address objects = %+v", pc.AddressObjs)
	}

	res := &auditResult{
		Interfaces: pc.Interfaces, Routes: pc.Routes,
		DhcpServers: pc.DhcpServers, AddressObjs: pc.AddressObjs,
	}
	entries := ipamEntriesFor(res, 1, "fw-a.example")
	bySrc := map[string][]string{}
	for _, e := range entries {
		bySrc[e.Source] = append(bySrc[e.Source], e.Prefix)
	}
	want := map[string]string{
		"interface": "10.20.0.0/24",
		"secondary": "10.21.0.0/24",
		"route":     "10.30.0.0/16",
		"dhcp":      "10.20.0.0/24",
		"address":   "10.40.0.0/24",
	}
	for src, prefix := range want {
		if len(bySrc[src]) == 0 || bySrc[src][0] != prefix {
			t.Errorf("source %s: got %v, want %s", src, bySrc[src], prefix)
		}
	}
	// The default route (route 1 has no dst) must not appear.
	if len(bySrc["route"]) != 1 {
		t.Errorf("routes = %v, want exactly one", bySrc["route"])
	}
}

const ipamMultiVDOMFixture = `config vdom
    edit "root"
        config system interface
            edit "lan-root"
                set ip 10.90.0.1 255.255.255.0
            next
        end
        config router static
            edit 1
                set dst 10.91.0.0 255.255.255.0
                set device "lan-root"
            next
        end
        config system dhcp server
            edit 1
                set interface "lan-root"
                set default-gateway 10.92.0.1
                set netmask 255.255.255.0
            next
        end
        config firewall address
            edit "net-root"
                set subnet 10.93.0.0 255.255.255.0
            next
        end
    next
    edit "tenant-a"
        config system interface
            edit "lan-tenant"
                set ip 10.90.0.1 255.255.255.0
            next
        end
        config router static
            edit 1
                set dst 10.91.0.0 255.255.255.0
                set device "lan-tenant"
            next
        end
        config system dhcp server
            edit 1
                set interface "lan-tenant"
                set default-gateway 10.92.0.1
                set netmask 255.255.255.0
            next
        end
        config firewall address
            edit "net-tenant"
                set subnet 10.93.0.0 255.255.255.0
            next
        end
    next
end
config global
    config system interface
        edit "global-port"
            set vdom "tenant-a"
            set ip 10.94.0.1 255.255.255.0
        next
    end
end`

func TestParseConfigDataIPAMPreservesVDOM(t *testing.T) {
	t.Parallel()
	pc := parseConfigData(parseCfg(ipamMultiVDOMFixture))
	if len(pc.Interfaces) != 3 || len(pc.Routes) != 2 || len(pc.DhcpServers) != 2 || len(pc.AddressObjs) != 2 {
		t.Fatalf("parsed IPAM source counts = interfaces %d routes %d DHCP %d addresses %d", len(pc.Interfaces), len(pc.Routes), len(pc.DhcpServers), len(pc.AddressObjs))
	}
	for _, test := range []struct {
		name string
		got  string
		want string
	}{
		{"root interface", pc.Interfaces[0].VDOM, "root"},
		{"tenant interface", pc.Interfaces[1].VDOM, "tenant-a"},
		{"global interface direct setting", pc.Interfaces[2].VDOM, "tenant-a"},
		{"root route", pc.Routes[0].VDOM, "root"},
		{"tenant route", pc.Routes[1].VDOM, "tenant-a"},
		{"root DHCP", pc.DhcpServers[0].VDOM, "root"},
		{"tenant DHCP", pc.DhcpServers[1].VDOM, "tenant-a"},
		{"root address", pc.AddressObjs[0].VDOM, "root"},
		{"tenant address", pc.AddressObjs[1].VDOM, "tenant-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("VDOM = %q, want %q", test.got, test.want)
			}
		})
	}
	entries := ipamEntriesFor(&auditResult{Interfaces: pc.Interfaces, Routes: pc.Routes, DhcpServers: pc.DhcpServers, AddressObjs: pc.AddressObjs}, 7, "edge.example.test")
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.Source+"|"+entry.Prefix+"|"+entry.VDOM] = true
	}
	for _, key := range []string{
		"interface|10.90.0.0/24|root", "interface|10.90.0.0/24|tenant-a",
		"route|10.91.0.0/24|root", "route|10.91.0.0/24|tenant-a",
		"dhcp|10.92.0.0/24|root", "dhcp|10.92.0.0/24|tenant-a",
		"address|10.93.0.0/24|root", "address|10.93.0.0/24|tenant-a",
	} {
		if !seen[key] {
			t.Errorf("missing IPAM entry %q: %+v", key, entries)
		}
	}
}

func TestIPAMRejectsSnapshotFromSchemaBeforeVDOM(t *testing.T) {
	t.Parallel()
	s := &Server{cfg: &config.Config{DataDir: t.TempDir()}, logger: slog.New(slog.DiscardHandler)}
	db, err := s.insightsDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ipam_cache (id, computed_at, results_json, snap_schema) VALUES (1, '2026-09-02T08:00:00Z', '{"entries":[{"prefix":"10.0.0.0/24"}]}', ?)`, ipamSnapshotSchema-1); err != nil {
		t.Fatal(err)
	}
	s.ipamProgress.begin(1)
	defer s.ipamProgress.end()
	recorder := httptest.NewRecorder()
	s.handleIPAMData(recorder, httptest.NewRequest("GET", "/ipam/data", nil))
	var response ipamDataOut
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Snapshot) != 0 {
		t.Fatalf("old-schema snapshot was served: %s", response.Snapshot)
	}
}

func TestIPAMVDOMSchemaVersions(t *testing.T) {
	if auditSchemaVersion < 8 || ipamSnapshotSchema < 4 {
		t.Fatalf("VDOM contract requires audit schema >= 8 and IPAM schema >= 4; got %d/%d", auditSchemaVersion, ipamSnapshotSchema)
	}
}

// TestSweepProgress covers the begin-coalescing and progress reporting used
// by the IPAM and license background sweeps.
func TestSweepProgress(t *testing.T) {
	var p sweepProgress
	if running, _, _, _ := p.snapshot(); running {
		t.Fatal("fresh progress must not be running")
	}
	if !p.begin(3) {
		t.Fatal("first begin must succeed")
	}
	if p.begin(5) {
		t.Fatal("second begin must coalesce (return false)")
	}
	p.step("fw-a")
	p.step("fw-b")
	running, done, total, current := p.snapshot()
	if !running || done != 2 || total != 3 || current != "fw-b" {
		t.Fatalf("snapshot = (%v, %d, %d, %q), want (true, 2, 3, fw-b)", running, done, total, current)
	}
	p.end()
	if running, _, _, _ := p.snapshot(); running {
		t.Fatal("ended progress must not be running")
	}
	if !p.begin(1) {
		t.Fatal("begin after end must succeed again")
	}
	p.end()
}

func TestFindOverlaps(t *testing.T) {
	entries := []ipamEntry{
		// Template prefix shared by three firewalls; fw-a lists it from two
		// sources, which must count as ONE firewall.
		{Prefix: "192.168.10.0/24", FwID: 1, FQDN: "fw-a", Source: "interface", Name: "lan"},
		{Prefix: "192.168.10.0/24", FwID: 1, FQDN: "fw-a", Source: "dhcp", Name: "lan scope"},
		{Prefix: "192.168.10.0/24", FwID: 2, FQDN: "fw-b", Source: "interface", Name: "lan"},
		{Prefix: "192.168.10.0/24", FwID: 3, FQDN: "fw-c", Source: "interface", Name: "lan"},
		// Containment between disjoint firewalls: fw-d's /16 contains fw-e's /24.
		{Prefix: "10.50.0.0/16", FwID: 4, FQDN: "fw-d", Source: "route", Name: "agg"},
		{Prefix: "10.50.1.0/24", FwID: 5, FQDN: "fw-e", Source: "interface", Name: "lan"},
		// Containment sharing a firewall: fw-f's own LAN under an aggregate
		// fw-f itself carries (fw-g too) — never flagged, per design.
		{Prefix: "10.60.0.0/16", FwID: 6, FQDN: "fw-f", Source: "route", Name: "agg"},
		{Prefix: "10.60.0.0/16", FwID: 7, FQDN: "fw-g", Source: "route", Name: "agg"},
		{Prefix: "10.60.1.0/24", FwID: 6, FQDN: "fw-f", Source: "interface", Name: "lan"},
		// Excluded noise.
		{Prefix: "0.0.0.0/0", FwID: 8, FQDN: "fw-h", Source: "route", Name: "default"},
		{Prefix: "10.60.1.7/32", FwID: 9, FQDN: "fw-i", Source: "address", Name: "host"},
	}
	overlaps := findOverlaps(entries)
	byKey := map[string]ipamOverlap{}
	for _, o := range overlaps {
		byKey[o.Kind+"|"+o.Prefix+"|"+o.Inner] = o
		if o.Prefix == "0.0.0.0/0" || o.Inner == "10.60.1.7/32" {
			t.Errorf("excluded prefix in overlap: %+v", o)
		}
	}
	if dup := byKey["duplicate|192.168.10.0/24|"]; dup.Count != 3 {
		t.Errorf("shared template prefix count = %d, want 3 (distinct firewalls): %+v", dup.Count, dup)
	}
	if dup := byKey["duplicate|10.60.0.0/16|"]; dup.Count != 2 {
		t.Errorf("shared aggregate count = %d, want 2: %+v", dup.Count, dup)
	}
	if c := byKey["containment|10.50.0.0/16|10.50.1.0/24"]; c.Count != 2 {
		t.Errorf("disjoint containment missing or wrong count: %+v", c)
	}
	if _, flagged := byKey["containment|10.60.0.0/16|10.60.1.0/24"]; flagged {
		t.Error("containment sharing a firewall must not be flagged")
	}
	if len(overlaps) != 3 {
		t.Errorf("overlaps = %d, want 3: %+v", len(overlaps), overlaps)
	}
	// Duplicates sort first, widest sharing first.
	if overlaps[0].Kind != "duplicate" || overlaps[0].Count != 3 {
		t.Errorf("first overlap = %+v, want the 3-firewall duplicate", overlaps[0])
	}
}
