package web

import (
	"testing"
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

func TestFindOverlaps(t *testing.T) {
	entries := []ipamEntry{
		{Prefix: "10.20.0.0/24", FwID: 1, FQDN: "fw-a", Source: "interface", Name: "lan"},
		{Prefix: "10.20.0.0/24", FwID: 1, FQDN: "fw-a", Source: "dhcp", Name: "lan scope"}, // same fw: never flagged
		{Prefix: "10.20.0.0/24", FwID: 2, FQDN: "fw-b", Source: "interface", Name: "lan"},  // duplicate vs fw-a
		{Prefix: "10.20.0.0/16", FwID: 3, FQDN: "fw-c", Source: "route", Name: "agg"},      // contains both
		{Prefix: "10.99.0.0/24", FwID: 4, FQDN: "fw-d", Source: "interface", Name: "lan"},  // disjoint
		{Prefix: "0.0.0.0/0", FwID: 5, FQDN: "fw-e", Source: "route", Name: "default"},     // excluded
		{Prefix: "10.20.0.7/32", FwID: 6, FQDN: "fw-f", Source: "address", Name: "host"},   // /32 excluded
	}
	overlaps := findOverlaps(entries)

	var dups, contains int
	for _, o := range overlaps {
		if o.A.FwID == o.B.FwID {
			t.Errorf("same-firewall overlap flagged: %+v", o)
		}
		switch o.Kind {
		case "duplicate":
			dups++
			isAB := o.A.FwID == 1 && o.B.FwID == 2
			isBA := o.A.FwID == 2 && o.B.FwID == 1
			if !isAB && !isBA {
				t.Errorf("unexpected duplicate pair: %+v", o)
			}
		case "containment":
			contains++
		}
		if o.A.Prefix == "0.0.0.0/0" || o.B.Prefix == "0.0.0.0/0" ||
			o.A.Prefix == "10.20.0.7/32" || o.B.Prefix == "10.20.0.7/32" {
			t.Errorf("excluded prefix in overlap: %+v", o)
		}
	}
	if dups != 1 {
		t.Errorf("duplicates = %d, want 1", dups)
	}
	// fw-c's /16 contains fw-a's /24 and fw-b's /24 (one row per fw pair).
	if contains != 2 {
		t.Errorf("containments = %d, want 2: %+v", contains, overlaps)
	}
	// Duplicates sort first.
	if len(overlaps) > 0 && overlaps[0].Kind != "duplicate" {
		t.Errorf("first overlap kind = %s, want duplicate", overlaps[0].Kind)
	}
}
