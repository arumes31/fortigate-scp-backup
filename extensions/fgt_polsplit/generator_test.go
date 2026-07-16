package fgt_polsplit

import (
	"strings"
	"testing"
)

func testParsedBackup() *ParsedBackup {
	return &ParsedBackup{
		Policy: &OrigPolicy{
			ID:     5,
			Action: "accept",
			CloneLines: []string{
				`set srcintf "lan1"`,
				`set dstintf "wan1"`,
				`set action accept`,
				`set schedule "always"`,
				`set nat enable`,
			},
		},
		UsedPolicyIDs: []int{1, 5, 12},
		AddrByCIDR: map[string][]string{
			"10.0.0.10/32":    {"H_Server1"},
			"192.168.10.0/24": {"LAN_Users"},
		},
		SvcByKey: map[string][]string{"tcp/443": {"HTTPS"}},
		SvcNames: map[string]string{"https": "HTTPS", "dns": "DNS"},
		TakenNames: map[string]bool{
			"h_server1": true, "lan_users": true, "https": true, "dns": true,
		},
	}
}

func ent(v string) Entity { return Entity{Value: v, Hosts: 1} }

func TestGenerateReuseAndCreate(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{
		{
			Src:      []Entity{ent("10.0.0.10"), ent("10.0.0.99")},
			Dst:      []Entity{{Value: "192.168.10.0/24", IsNet: true, Hosts: 6}},
			Services: []ServiceSpec{{Key: "tcp/443", Proto: "tcp", Port: 443, LogName: "HTTPS"}, {Key: "tcp/8443", Proto: "tcp", Port: 8443}},
			Hits:     100,
		},
	}
	res := Generate(pb.Policy, pb, pols, "PS5", "per_service")

	// Existing objects reused, only the gaps created.
	if strings.Contains(res.Config, `edit "H_Server1"`) {
		t.Error("existing host object must not be re-created")
	}
	if !strings.Contains(res.Config, `edit "PS5_h_10.0.0.99"`) ||
		!strings.Contains(res.Config, "set subnet 10.0.0.99 255.255.255.255") {
		t.Errorf("missing new host object:\n%s", res.Config)
	}
	if !strings.Contains(res.Config, `edit "PS5_tcp8443"`) ||
		!strings.Contains(res.Config, "set tcp-portrange 8443") {
		t.Errorf("missing new service object:\n%s", res.Config)
	}
	if strings.Contains(res.Config, `edit "PS5_tcp443"`) {
		t.Error("tcp/443 must reuse the existing HTTPS object")
	}

	// New-object report matches what was generated.
	kinds := map[string]int{}
	for _, o := range res.NewObjects {
		kinds[o.Kind]++
	}
	if kinds["address"] != 1 || kinds["service"] != 1 || kinds["addrgrp"] != 0 {
		t.Errorf("new objects = %+v", res.NewObjects)
	}

	// Policy: allocated ID after max used (12 → 13), clone lines, forced logging.
	if pols[0].ID != 13 {
		t.Errorf("allocated ID = %d", pols[0].ID)
	}
	for _, want := range []string{
		"edit 13",
		`set srcintf "lan1"`,
		"set action accept",
		"set nat enable",
		`set srcaddr "H_Server1" "PS5_h_10.0.0.99"`,
		`set dstaddr "LAN_Users"`,
		`set service "HTTPS" "PS5_tcp8443"`,
		"set logtraffic all",
		"move 13 before 5",
		"set status disable",
	} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("config missing %q:\n%s", want, res.Config)
		}
	}
	if !strings.HasPrefix(pols[0].Name, "PS5-HTTPS") {
		t.Errorf("policy name = %q", pols[0].Name)
	}
}

func TestGenerateAddressGroup(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{
		{
			Src:      []Entity{ent("10.0.0.1"), ent("10.0.0.2"), ent("10.0.0.3"), ent("10.0.0.4")},
			Dst:      []Entity{ent("10.9.9.9")},
			Services: []ServiceSpec{{Key: "udp/53", Proto: "udp", Port: 53, LogName: "DNS"}},
			Hits:     10,
		},
	}
	res := Generate(pb.Policy, pb, pols, "PS5", "per_service")
	if !strings.Contains(res.Config, "config firewall addrgrp") {
		t.Errorf("expected an address group for 4 members:\n%s", res.Config)
	}
	grp := 0
	for _, o := range res.NewObjects {
		if o.Kind == "addrgrp" {
			grp++
		}
	}
	if grp != 1 {
		t.Errorf("expected 1 addrgrp in new objects, got %d", grp)
	}
	// The group must be referenced instead of the member list.
	if strings.Contains(res.Config, `set srcaddr "PS5_h_10.0.0.1" "PS5_h_10.0.0.2"`) {
		t.Error("srcaddr should reference the group, not inline members")
	}
}

func TestGeneratePerDestinationNaming(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{
		{
			Src:      []Entity{ent("10.0.0.1")},
			Dst:      []Entity{ent("10.9.9.9")},
			Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22, LogName: "SSH"}},
			Hits:     10,
		},
	}
	res := Generate(pb.Policy, pb, pols, "PS5", "per_destination")
	if !strings.HasPrefix(pols[0].Name, "PS5-10.9.9.9") {
		t.Errorf("policy name = %q", pols[0].Name)
	}
	if res.Config == "" {
		t.Error("empty config")
	}
}

func TestGeneratePortlessServices(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{
		{
			Src:      []Entity{ent("10.0.0.1")},
			Dst:      []Entity{ent("10.9.9.9")},
			Services: []ServiceSpec{{Key: "icmp", Proto: "icmp"}, {Key: "ip-47", Proto: "ip-47"}},
			Hits:     3,
		},
	}
	res := Generate(pb.Policy, pb, pols, "PS5", "per_service")
	if !strings.Contains(res.Config, "set protocol ICMP") {
		t.Errorf("missing ICMP service:\n%s", res.Config)
	}
	if !strings.Contains(res.Config, "set protocol IP") || !strings.Contains(res.Config, "set protocol-number 47") {
		t.Errorf("missing IP-proto service:\n%s", res.Config)
	}
}

func TestGenerateWarnsOnNonAcceptPolicy(t *testing.T) {
	pb := testParsedBackup()
	pb.Policy.Action = ""
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22}}}}
	res := Generate(pb.Policy, pb, pols, "", "per_service")
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for a non-accept original policy")
	}
}

func TestNamerCollisions(t *testing.T) {
	nm := newNamer(map[string]bool{"ps5_h_10.0.0.1": true})
	n1 := nm.alloc("PS5_h_10.0.0.1", 79)
	if n1 == "PS5_h_10.0.0.1" {
		t.Errorf("collision not avoided: %q", n1)
	}
	n2 := nm.alloc("PS5_h_10.0.0.1", 79)
	if n2 == n1 {
		t.Errorf("duplicate allocation: %q", n2)
	}
	long := strings.Repeat("x", 100)
	if got := nm.alloc(long, 35); len(got) > 35 {
		t.Errorf("name too long: %d", len(got))
	}
}
