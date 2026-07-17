package fgt_polsplit

import (
	"strings"
	"testing"
)

func testParsedBackup() *ParsedBackup {
	return &ParsedBackup{
		Policy: &OrigPolicy{
			ID:      5,
			Action:  "accept",
			SrcIntf: []string{"lan1"},
			DstIntf: []string{"wan1"},
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
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})

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
	// Path-based naming convention: SRCINTF>DSTINTF (SERVICE[+N]).
	if pols[0].Name != "LAN1>WAN1 (HTTPS+1)" {
		t.Errorf("policy name = %q, want LAN1>WAN1 (HTTPS+1)", pols[0].Name)
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
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
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

// TestGeneratePathNaming: the naming convention is SRCINTF>DSTINTF (SERVICE);
// multiple interfaces sharing a prefix collapse to prefix+XX.
func TestGeneratePathNaming(t *testing.T) {
	pb := testParsedBackup()
	pb.Policy.SrcIntf = []string{"VL1"}
	pb.Policy.DstIntf = []string{"VL2", "VL3"}
	pols := []RecPolicy{
		{
			Src:      []Entity{ent("10.0.0.1")},
			Dst:      []Entity{ent("10.9.9.9")},
			Services: []ServiceSpec{{Key: "tcp/3389", Proto: "tcp", Port: 3389, LogName: "RDP"}},
			Hits:     10,
		},
	}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if pols[0].Name != "VL1>VLXX (RDP)" {
		t.Errorf("policy name = %q, want VL1>VLXX (RDP)", pols[0].Name)
	}
	if !strings.Contains(res.Config, `set name "VL1>VLXX (RDP)"`) {
		t.Errorf("config missing quoted path name:\n%s", res.Config)
	}
}

// TestFitPolicyName: the 35-char limit must eat the interface path, never the
// service label — the label is what distinguishes sibling splits.
func TestFitPolicyName(t *testing.T) {
	cases := []struct {
		path, label, want string
	}{
		{"LAN1>WAN1", "RDP", "LAN1>WAN1 (RDP)"},
		{"ONBOARDING_D1X>VIRTUAL-WAN-LINK", "RDP", "ONBOARDING_D1X>VIRTUAL-WAN-LI (RDP)"},
		{"ONBOARDING_D1X>VIRTUAL-WAN-LINK", "DENY-REST", "ONBOARDING_D1X>VIRTUAL- (DENY-REST)"},
	}
	for _, c := range cases {
		got := fitPolicyName(c.path, c.label, maxPolicyNameLen)
		if got != c.want {
			t.Errorf("fitPolicyName(%q, %q) = %q, want %q", c.path, c.label, got, c.want)
		}
		if len(got) > maxPolicyNameLen {
			t.Errorf("fitPolicyName(%q, %q) = %q exceeds %d chars", c.path, c.label, got, maxPolicyNameLen)
		}
	}
}

// TestGenerateLongPathKeepsLabel: end-to-end — long real-world interface
// names must not truncate away the distinguishing service label.
func TestGenerateLongPathKeepsLabel(t *testing.T) {
	pb := testParsedBackup()
	pb.Policy.SrcIntf = []string{"onboarding_d1x"}
	pb.Policy.DstIntf = []string{"virtual-wan-link"}
	pols := []RecPolicy{
		{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
			Services: []ServiceSpec{{Key: "tcp/3389", Proto: "tcp", Port: 3389, LogName: "RDP"}}, Hits: 9},
		{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.8")},
			Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22, LogName: "SSH"}}, Hits: 5},
	}
	Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.HasSuffix(pols[0].Name, "(RDP)") || !strings.HasSuffix(pols[1].Name, "(SSH)") {
		t.Errorf("labels lost to truncation: %q / %q", pols[0].Name, pols[1].Name)
	}
	if pols[0].Name == pols[1].Name {
		t.Errorf("sibling splits share one name: %q", pols[0].Name)
	}
}

// TestInsertSuffix: collision disambiguation keeps the parenthesised label
// balanced and legible instead of truncating away the ")" and label digits.
func TestInsertSuffix(t *testing.T) {
	// Exact cases (no truncation needed).
	exact := []struct {
		base, suffix string
		maxLen       int
		want         string
	}{
		{"VL1>VL2 (RDP)", "_2", 35, "VL1>VL2 (RDP_2)"},   // suffix lands inside the parens
		{"PS5_h_10.0.0.1", "_2", 79, "PS5_h_10.0.0.1_2"}, // object name (no paren) → appended
		{"udp (X)", "_10", 7, "udp_10)"},                 // tight paren fit
	}
	for _, c := range exact {
		if got := insertSuffix(c.base, c.suffix, c.maxLen); got != c.want {
			t.Errorf("insertSuffix(%q,%q,%d) = %q, want %q", c.base, c.suffix, c.maxLen, got, c.want)
		}
	}
	// Truncating case: the disambiguator must never leave an unbalanced paren
	// or drop the "_N" suffix, and must stay within maxLen.
	got := insertSuffix("LB-EXADM>VPN_EX-ADM (udp_1812-1813)", "_2", 35)
	if len(got) > 35 {
		t.Errorf("insertSuffix over budget: %q (%d)", got, len(got))
	}
	if !strings.HasSuffix(got, "_2)") {
		t.Errorf("truncated name must keep the _N inside the close paren: %q", got)
	}
	if strings.Count(got, "(") != strings.Count(got, ")") {
		t.Errorf("unbalanced parens: %q", got)
	}
}

// TestGeneratePerDestinationNameCollision: sibling per-destination splits that
// share interfaces + top service collide on name — the disambiguator must keep
// each name valid (balanced parens, distinct, ≤35, service label intact).
func TestGeneratePerDestinationNameCollision(t *testing.T) {
	pb := testParsedBackup()
	pb.Policy.SrcIntf = []string{"lb-exadm"}
	pb.Policy.DstIntf = []string{"vpn_ex-adm"}
	mk := func(dst string) RecPolicy {
		return RecPolicy{
			Src:      []Entity{ent("10.0.0.1")},
			Dst:      []Entity{ent(dst)},
			Services: []ServiceSpec{{Key: "udp/1812-1813", Proto: "udp", Port: 1812, PortEnd: 1813}},
			Hits:     5,
		}
	}
	pols := []RecPolicy{mk("10.9.9.1"), mk("10.9.9.2"), mk("10.9.9.3")}
	Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	seen := map[string]bool{}
	for _, p := range pols {
		if len(p.Name) > maxPolicyNameLen {
			t.Errorf("name too long: %q (%d)", p.Name, len(p.Name))
		}
		if strings.Count(p.Name, "(") != strings.Count(p.Name, ")") {
			t.Errorf("unbalanced parens in name: %q", p.Name)
		}
		if !strings.Contains(p.Name, "udp") {
			t.Errorf("service label lost from name: %q", p.Name)
		}
		if seen[p.Name] {
			t.Errorf("duplicate policy name: %q", p.Name)
		}
		seen[p.Name] = true
	}
}

// TestGenerateServiceGroupCap: a policy with more than groupInlineMax services
// collapses them into a firewall service group instead of inlining a long
// `set service` line.
func TestGenerateServiceGroupCap(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{
		Src: []Entity{ent("10.0.0.1")},
		Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{
			{Key: "tcp/22", Proto: "tcp", Port: 22},
			{Key: "tcp/80", Proto: "tcp", Port: 80},
			{Key: "tcp/443", Proto: "tcp", Port: 443},
			{Key: "tcp/3389", Proto: "tcp", Port: 3389},
		},
		Hits: 5,
	}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, "config firewall service group") {
		t.Errorf("expected a service group for 4 services:\n%s", res.Config)
	}
	grp := 0
	for _, o := range res.NewObjects {
		if o.Kind == "svcgrp" {
			grp++
		}
	}
	if grp != 1 {
		t.Errorf("expected 1 svcgrp new object, got %d", grp)
	}
	// The service group must be defined before the policy references it.
	gi := strings.Index(res.Config, "config firewall service group")
	pi := strings.Index(res.Config, "config firewall policy")
	if gi < 0 || pi < 0 || gi > pi {
		t.Errorf("service group must precede firewall policy:\n%s", res.Config)
	}
}

// TestGenerateIPProtoValueFormat: the NewObject.Value for an ip-<n> service
// uses the canonical hyphen key form, matching ServiceSpec.Key / SvcByKey.
func TestGenerateIPProtoValueFormat(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "ip-47", Proto: "ip-47"}}, Hits: 3}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	for _, o := range res.NewObjects {
		if o.Kind == "service" && strings.Contains(o.Value, "/") {
			t.Errorf("ip-proto NewObject.Value must use hyphen form, got %q", o.Value)
		}
	}
}

func TestIfaceLabel(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"VL1"}, "VL1"},
		{[]string{"port1"}, "PORT1"},
		{[]string{"VL2", "VL3"}, "VLXX"},
		{[]string{"port1", "port2", "port7"}, "PORTXX"},
		{[]string{"VL2", "port3"}, "MULTI"},
		{[]string{"voice", "video"}, "MULTI"},
		{nil, "ANY"},
	}
	for _, c := range cases {
		if got := ifaceLabel(c.in); got != c.want {
			t.Errorf("ifaceLabel(%v) = %q, want %q", c.in, got, c.want)
		}
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
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
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
	res := Generate(pb.Policy, pb, pols, GenOptions{})
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for a non-accept original policy")
	}
}

// TestGenerateVDOMWrapper: policies in a named VDOM must emit the
// config vdom / edit <vdom> entry wrapper or the paste fails on
// multi-VDOM units.
func TestGenerateVDOMWrapper(t *testing.T) {
	pb := testParsedBackup()
	pb.Policy.VDOM = "dmz"
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22}}, Hits: 1}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.HasPrefix(res.Config, "config vdom\nedit dmz\n") {
		t.Errorf("config must start with the vdom wrapper:\n%s", res.Config)
	}
	if !strings.HasSuffix(strings.TrimRight(res.Config, "\n"), "end") {
		t.Errorf("config must close the vdom wrapper:\n%s", res.Config)
	}
	// Single-VDOM policies must stay unwrapped.
	pb.Policy.VDOM = ""
	res = Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if strings.HasPrefix(res.Config, "config vdom") {
		t.Errorf("single-vdom config must not be wrapped:\n%s", res.Config)
	}
}

// TestGeneratePolicyNameCollision: names of policies already on the device
// (from the backup) must not be re-allocated.
func TestGeneratePolicyNameCollision(t *testing.T) {
	pb := testParsedBackup()
	pb.PolicyNames = map[string]bool{"lan1>wan1 (ssh)": true}
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22, LogName: "SSH"}}, Hits: 1}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if pols[0].Name == "LAN1>WAN1 (SSH)" {
		t.Errorf("policy name %q collides with an existing policy", pols[0].Name)
	}
	// The disambiguator goes inside the parenthesised label (paren-aware), so
	// the name reads "LAN1>WAN1 (SSH_2)" — base recognizable, parens balanced.
	if !strings.HasPrefix(pols[0].Name, "LAN1>WAN1 (SSH") {
		t.Errorf("collision suffix should extend the base name, got %q", pols[0].Name)
	}
	if strings.Count(pols[0].Name, "(") != strings.Count(pols[0].Name, ")") {
		t.Errorf("unbalanced parens after disambiguation: %q", pols[0].Name)
	}
	if res.Config == "" {
		t.Error("empty config")
	}
}

// TestGeneratePortlessTCP: a tcp tuple without a usable dstport must emit a
// 1-65535 range, never `set tcp-portrange 0` (FortiOS rejects it).
func TestGeneratePortlessTCP(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/any", Proto: "tcp", Port: 0}}, Hits: 1}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if strings.Contains(res.Config, "portrange 0") {
		t.Errorf("must not emit port 0:\n%s", res.Config)
	}
	if !strings.Contains(res.Config, "set tcp-portrange 1-65535") {
		t.Errorf("missing 1-65535 range for portless tcp:\n%s", res.Config)
	}
}

// TestFgtQuoteEscaping: reused object names with embedded quotes/backslashes
// must be escaped in emitted CLI.
func TestFgtQuoteEscaping(t *testing.T) {
	if got := fgtQuote(`Cust "A" Net`); got != `"Cust \"A\" Net"` {
		t.Errorf("fgtQuote = %s", got)
	}
	if got := fgtQuote(`back\slash`); got != `"back\\slash"` {
		t.Errorf("fgtQuote = %s", got)
	}
}

// TestGenerateRangeService: consolidated port ranges emit one range object and
// reuse an existing exact-range object when the backup has one.
func TestGenerateRangeService(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/8080-8082", Proto: "tcp", Port: 8080, PortEnd: 8082}}, Hits: 5}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, `edit "PS5_tcp8080_8082"`) ||
		!strings.Contains(res.Config, "set tcp-portrange 8080-8082") {
		t.Errorf("missing range service object:\n%s", res.Config)
	}

	// Existing exact-range object must be reused instead.
	pb = testParsedBackup()
	pb.SvcByKey["tcp/8080-8082"] = []string{"WEB_ALT"}
	pols = []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/8080-8082", Proto: "tcp", Port: 8080, PortEnd: 8082}}, Hits: 5}}
	res = Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, `set service "WEB_ALT"`) || strings.Contains(res.Config, "PS5_tcp8080") {
		t.Errorf("existing range object not reused:\n%s", res.Config)
	}
}

// TestGenerateAddrGrpReuse: an existing address group with exactly the
// resolved member set is referenced instead of creating a new group.
func TestGenerateAddrGrpReuse(t *testing.T) {
	pb := testParsedBackup()
	pb.AddrByCIDR["10.0.0.1/32"] = []string{"H_A"}
	pb.AddrByCIDR["10.0.0.2/32"] = []string{"H_B"}
	pb.AddrGrpBySig = map[string]string{groupSig([]string{"H_A", "H_B"}): "G_Pair"}
	pols := []RecPolicy{{
		Src:      []Entity{ent("10.0.0.1"), ent("10.0.0.2")},
		Dst:      []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22, LogName: "SSH"}},
		Hits:     5,
	}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, `set srcaddr "G_Pair"`) {
		t.Errorf("existing addrgrp not reused:\n%s", res.Config)
	}
	if strings.Contains(res.Config, "config firewall addrgrp") {
		t.Errorf("no new addrgrp should be created:\n%s", res.Config)
	}
}

// TestGenerateSvcGrpReuse: same for an existing service group.
func TestGenerateSvcGrpReuse(t *testing.T) {
	pb := testParsedBackup()
	pb.SvcByKey["tcp/80"] = []string{"HTTP"}
	pb.SvcGrpBySig = map[string]string{groupSig([]string{"HTTP", "HTTPS"}): "Web Access"}
	pols := []RecPolicy{{
		Src: []Entity{ent("10.0.0.1")},
		Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{
			{Key: "tcp/80", Proto: "tcp", Port: 80, LogName: "HTTP"},
			{Key: "tcp/443", Proto: "tcp", Port: 443, LogName: "HTTPS"},
		},
		Hits: 5,
	}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, `set service "Web Access"`) {
		t.Errorf("existing service group not reused:\n%s", res.Config)
	}
}

// TestGenerateTicketComment: a change ticket lands sanitized in the comments.
func TestGenerateTicketComment(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22}}, Hits: 1}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5", Ticket: `CHG-1234 "quote"`})
	if !strings.Contains(res.Config, "Split from policy 5 (FortiSafe polsplit) [CHG-1234 _quote_]") {
		t.Errorf("ticket missing or unsanitized in comments:\n%s", res.Config)
	}
}

// TestGenerateWANAllEntity: the WAN-as-all collapse produces entities valued
// "all", which must resolve to the built-in object without creating anything.
func TestGenerateWANAllEntity(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{
		Src:      []Entity{ent("10.0.0.1")},
		Dst:      []Entity{{Value: "all", IsNet: true, Hosts: 12}},
		Services: []ServiceSpec{{Key: "tcp/443", Proto: "tcp", Port: 443, LogName: "HTTPS"}},
		Hits:     100,
	}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, `set dstaddr "all"`) {
		t.Errorf("dstaddr must reference the builtin all object:\n%s", res.Config)
	}
	for _, o := range res.NewObjects {
		if o.Kind == "address" && strings.Contains(o.Value, "all") {
			t.Errorf("no address object may be created for 'all': %+v", o)
		}
	}
	if strings.Contains(res.Config, `edit "all"`) {
		t.Errorf("builtin all must not be redefined:\n%s", res.Config)
	}
}

// TestGenerateDualProtoService: a merged tcpudp spec emits one object with
// both port ranges, or reuses an existing dual-protocol object exactly.
func TestGenerateDualProtoService(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcpudp/5514", Proto: "tcpudp", Port: 5514}}, Hits: 5}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, "set tcp-portrange 5514") || !strings.Contains(res.Config, "set udp-portrange 5514") {
		t.Errorf("dual-proto object must set both port ranges:\n%s", res.Config)
	}

	pb = testParsedBackup()
	pb.SvcByKey["tcpudp/53"] = []string{"DNS"}
	pols = []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcpudp/53", Proto: "tcpudp", Port: 53, LogName: "DNS"}}, Hits: 5}}
	res = Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if !strings.Contains(res.Config, `set service "DNS"`) || strings.Contains(res.Config, "PS5_tcpudp53") {
		t.Errorf("existing dual-proto DNS object not reused:\n%s", res.Config)
	}
}

// TestGenerateEmitDeny: the fallthrough deny policy covers the original's
// scope, carries deny+log, and moves last (directly above the original).
func TestGenerateEmitDeny(t *testing.T) {
	pb := testParsedBackup()
	pb.Policy.SrcAddr = []string{"all"}
	pb.Policy.DstAddr = []string{"all"}
	pb.Policy.Services = []string{"ALL"}
	// Identity selectors restrict the original's scope — the deny must carry
	// them, or it would block traffic that used to fall through to policies
	// below the original.
	pb.Policy.CloneLines = append(pb.Policy.CloneLines, `set groups "VPN-Users"`)
	pols := []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22, LogName: "SSH"}}, Hits: 1}}
	res := Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5", EmitDeny: true})
	for _, want := range []string{
		`set name "LAN1>WAN1 (DENY-REST)"`,
		"set action deny",
		`set srcaddr "all"`,
		`set service "ALL"`,
		"move 14 before 5", // deny (ID 14) moves after the split (13) → lands just above the original
	} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("deny block missing %q:\n%s", want, res.Config)
		}
	}
	// Deny must not inherit accept-side settings.
	denyIdx := strings.Index(res.Config, "edit 14")
	if denyIdx < 0 {
		t.Fatalf("deny policy not emitted:\n%s", res.Config)
	}
	denyBlock := res.Config[denyIdx:]
	if end := strings.Index(denyBlock, "next"); end > 0 {
		denyBlock = denyBlock[:end]
	}
	if strings.Contains(denyBlock, "set nat enable") || strings.Contains(denyBlock, "set action accept") {
		t.Errorf("deny policy inherited accept-side clone lines:\n%s", denyBlock)
	}
	if !strings.Contains(denyBlock, `set groups "VPN-Users"`) {
		t.Errorf("deny policy must preserve the identity selectors:\n%s", denyBlock)
	}

	// Without the option, no deny is emitted.
	pols = []RecPolicy{{Src: []Entity{ent("10.0.0.1")}, Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{{Key: "tcp/22", Proto: "tcp", Port: 22}}, Hits: 1}}
	res = Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if strings.Contains(res.Config, "DENY-REST") {
		t.Errorf("deny emitted without EmitDeny:\n%s", res.Config)
	}
}

// TestGenerateADLabel: policies tagged active-directory use the AD path label.
func TestGenerateADLabel(t *testing.T) {
	pb := testParsedBackup()
	pols := []RecPolicy{{
		Src: []Entity{ent("10.0.0.1")},
		Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{
			{Key: "tcp/88", Proto: "tcp", Port: 88},
			{Key: "tcp/389", Proto: "tcp", Port: 389},
			{Key: "tcp/445", Proto: "tcp", Port: 445},
		},
		Tags: []string{"active-directory"},
		Hits: 9,
	}}
	Generate(pb.Policy, pb, pols, GenOptions{Prefix: "PS5"})
	if pols[0].Name != "LAN1>WAN1 (AD)" {
		t.Errorf("policy name = %q, want LAN1>WAN1 (AD)", pols[0].Name)
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
