package fgt_polsplit

import (
	"fmt"
	"strings"
	"testing"
)

func tup(src, dst, proto string, port int, svc string, hits int64) TrafficTuple {
	return TrafficTuple{SrcIP: src, DstIP: dst, Proto: proto, Port: port, Service: svc, Hits: hits}
}

func TestAnalyzeRollup(t *testing.T) {
	var tuples []TrafficTuple
	// 5 hosts in 10.1.2.0/24 → rolled up at threshold 5
	for _, ip := range []string{"10.1.2.1", "10.1.2.2", "10.1.2.3", "10.1.2.4", "10.1.2.5"} {
		tuples = append(tuples, tup(ip, "10.9.9.9", "tcp", 443, "HTTPS", 10))
	}
	// 2 hosts in 10.1.3.0/24 → stays as hosts
	tuples = append(tuples, tup("10.1.3.1", "10.9.9.9", "tcp", 443, "HTTPS", 10))
	tuples = append(tuples, tup("10.1.3.2", "10.9.9.9", "tcp", 443, "HTTPS", 10))

	a := Analyze(tuples, AnalyzeOptions{RollupSrc: true, RollupThreshold: 5, RollupMask: 24})
	if e := a.SrcEnts["10.1.2.3"]; !e.IsNet || e.Value != "10.1.2.0/24" || e.Hosts != 5 {
		t.Errorf("rolled entity = %+v", e)
	}
	if e := a.SrcEnts["10.1.3.1"]; e.IsNet || e.Value != "10.1.3.1" {
		t.Errorf("host entity = %+v", e)
	}
	// destination side has rollup off
	if e := a.DstEnts["10.9.9.9"]; e.IsNet {
		t.Errorf("dst entity rolled up unexpectedly: %+v", e)
	}
}

func TestAnalyzeIPv6Excluded(t *testing.T) {
	tuples := []TrafficTuple{
		tup("10.0.0.1", "10.0.1.1", "tcp", 443, "HTTPS", 5),
		{SrcIP: "fd00::1", DstIP: "10.0.1.1", Proto: "tcp", Port: 443, Hits: 3, IPv6: true},
	}
	a := Analyze(tuples, AnalyzeOptions{})
	if len(a.Tuples) != 1 || a.IPv6Skipped != 1 {
		t.Errorf("tuples=%d skipped=%d", len(a.Tuples), a.IPv6Skipped)
	}
	if len(a.Warnings) == 0 {
		t.Error("expected IPv6 warning")
	}
}

func TestBuildPerServiceMergesSameSignature(t *testing.T) {
	tuples := []TrafficTuple{
		// HTTP and HTTPS: same src/dst pair → one merged policy with 2 services
		tup("10.0.0.1", "10.0.1.1", "tcp", 80, "HTTP", 10),
		tup("10.0.0.1", "10.0.1.1", "tcp", 443, "HTTPS", 20),
		// DNS towards a different destination → separate policy
		tup("10.0.0.1", "10.0.2.2", "udp", 53, "DNS", 5),
	}
	a := Analyze(tuples, AnalyzeOptions{})
	pols := BuildPerService(a)
	if len(pols) != 2 {
		t.Fatalf("expected 2 policies, got %d: %+v", len(pols), pols)
	}
	// sorted by hits: merged web policy (30) first
	if len(pols[0].Services) != 2 || pols[0].Hits != 30 {
		t.Errorf("merged policy = %+v", pols[0])
	}
	if len(pols[1].Services) != 1 || pols[1].Services[0].Key != "udp/53" {
		t.Errorf("dns policy = %+v", pols[1])
	}
}

func TestBuildPerDestinationMergesSameSignature(t *testing.T) {
	tuples := []TrafficTuple{
		// two destinations with identical source+service signature → merged
		tup("10.0.0.1", "10.0.1.1", "tcp", 443, "HTTPS", 10),
		tup("10.0.0.1", "10.0.1.2", "tcp", 443, "HTTPS", 10),
		// third destination with a different service set → separate
		tup("10.0.0.1", "10.0.1.3", "tcp", 22, "SSH", 50),
	}
	a := Analyze(tuples, AnalyzeOptions{})
	pols := BuildPerDestination(a)
	if len(pols) != 2 {
		t.Fatalf("expected 2 policies, got %d: %+v", len(pols), pols)
	}
	if pols[0].Hits != 50 { // ssh policy has more hits
		t.Errorf("expected ssh policy first, got %+v", pols[0])
	}
	if len(pols[1].Dst) != 2 {
		t.Errorf("merged dst policy = %+v", pols[1])
	}
}

func TestSvcKeyAndProtoName(t *testing.T) {
	if k := svcKey(tup("a", "b", "tcp", 8443, "", 1)); k != "tcp/8443" {
		t.Errorf("svcKey = %q", k)
	}
	if k := svcKey(TrafficTuple{Proto: "icmp"}); k != "icmp" {
		t.Errorf("icmp svcKey = %q", k)
	}
	// Port-carrying protocol without a usable port collapses to /any so the
	// generator never emits `set tcp-portrange 0`.
	if k := svcKey(tup("a", "b", "tcp", 0, "", 1)); k != "tcp/any" {
		t.Errorf("portless tcp svcKey = %q, want tcp/any", k)
	}
	cases := map[string]string{"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp6", "132": "sctp", "47": "ip-47", "TCP": "tcp"}
	for in, want := range cases {
		if got := protoName(in, 0); got != want {
			t.Errorf("protoName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := protoName("", 443); got != "unknown" {
		t.Errorf("protoName empty with port = %q", got)
	}
}

// TestConsolidatePortRanges: adjacent single ports merge into one range;
// gaps, other protocols and portless specs pass through.
func TestConsolidatePortRanges(t *testing.T) {
	in := []ServiceSpec{
		{Key: "tcp/8080", Proto: "tcp", Port: 8080},
		{Key: "tcp/8082", Proto: "tcp", Port: 8082},
		{Key: "tcp/8081", Proto: "tcp", Port: 8081},
		{Key: "tcp/9000", Proto: "tcp", Port: 9000},
		{Key: "udp/8081", Proto: "udp", Port: 8081},
		{Key: "icmp", Proto: "icmp"},
	}
	out := consolidatePortRanges(in)
	keys := make([]string, len(out))
	for i, s := range out {
		keys[i] = s.Key
	}
	want := map[string]bool{"tcp/8080-8082": true, "tcp/9000": true, "udp/8081": true, "icmp": true}
	if len(out) != len(want) {
		t.Fatalf("consolidated keys = %v", keys)
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected key %q in %v", k, keys)
		}
	}
	for _, s := range out {
		if s.Key == "tcp/8080-8082" && (s.Port != 8080 || s.PortEnd != 8082) {
			t.Errorf("range spec = %+v", s)
		}
	}
}

// TestBuildHybrid: per-service groups with strongly overlapping (but not
// identical) src/dst sets merge into one policy.
func TestBuildHybrid(t *testing.T) {
	var tuples []TrafficTuple
	// HTTPS: sources A,B,C,D → dst X
	for _, s := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		tuples = append(tuples, tup(s, "10.9.9.9", "tcp", 443, "HTTPS", 10))
	}
	// SSH: sources A,B,C (3/4 overlap = 0.75) → same dst X
	for _, s := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		tuples = append(tuples, tup(s, "10.9.9.9", "tcp", 22, "SSH", 5))
	}
	// DNS: disjoint source → different dst (must stay separate)
	tuples = append(tuples, tup("172.16.0.1", "10.8.8.8", "udp", 53, "DNS", 3))

	a := Analyze(tuples, AnalyzeOptions{})
	pols := BuildHybrid(a)
	if len(pols) != 2 {
		t.Fatalf("expected 2 hybrid policies, got %d: %+v", len(pols), pols)
	}
	// Merged policy carries both services and the union of sources.
	if len(pols[0].Services) != 2 || len(pols[0].Src) != 4 || pols[0].Hits != 55 {
		t.Errorf("merged policy = %+v", pols[0])
	}
	// Per-service on the same input yields 3 policies (no merge).
	if got := BuildPerService(a); len(got) != 3 {
		t.Errorf("per-service should keep 3 policies, got %d", len(got))
	}
}

// TestPreprocessPairsScan: many barely-hit ports on one pair = port scan,
// excluded entirely.
func TestPreprocessPairsScan(t *testing.T) {
	var tuples []TrafficTuple
	for p := 1; p <= 30; p++ {
		tuples = append(tuples, tup("10.0.0.66", "10.9.9.9", "tcp", p, "", 1))
	}
	tuples = append(tuples, tup("10.0.0.1", "10.9.9.9", "tcp", 443, "HTTPS", 500))
	out, warnings := preprocessPairs(tuples)
	if len(out) != 1 || out[0].Port != 443 {
		t.Fatalf("scan not excluded, out = %+v", out)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "port scan") {
		t.Errorf("warnings = %v", warnings)
	}
}

// TestPreprocessPairsRPC: tcp/135 plus dynamic high ports collapse into one
// 49152-65535 range tuple; the endpoint-mapper port survives.
func TestPreprocessPairsRPC(t *testing.T) {
	tuples := []TrafficTuple{tup("10.0.0.1", "10.9.9.9", "tcp", 135, "", 50)}
	for _, p := range []int{49700, 50123, 52001, 55555, 60001, 61234} {
		tuples = append(tuples, tup("10.0.0.1", "10.9.9.9", "tcp", p, "", 10))
	}
	out, warnings := preprocessPairs(tuples)
	var has135, hasRange bool
	for _, o := range out {
		if o.Port == 135 {
			has135 = true
		}
		if o.Port == rpcRangeLo && o.PortEnd == 65535 {
			hasRange = true
			if o.Hits != 60 {
				t.Errorf("range hits = %d, want 60", o.Hits)
			}
		}
	}
	if !has135 || !hasRange || len(out) != 2 {
		t.Fatalf("rpc collapse failed: %+v (warnings %v)", out, warnings)
	}
	if k := svcKey(out[len(out)-1]); k != "tcp/49152-65535" {
		t.Errorf("range svcKey = %q", k)
	}
}

// TestPreprocessPairsRPCIPv6: synthesized range tuples must inherit the
// pair's IPv6 status, or IPv6 traffic would leak into the IPv4-only output.
func TestPreprocessPairsRPCIPv6(t *testing.T) {
	tuples := []TrafficTuple{tup("fd00::1", "fd00::2", "tcp", 135, "", 50)}
	for _, p := range []int{49700, 50123, 52001, 55555, 60001, 61234} {
		tuples = append(tuples, tup("fd00::1", "fd00::2", "tcp", p, "", 10))
	}
	for i := range tuples {
		tuples[i].IPv6 = true
	}
	out, _ := preprocessPairs(tuples)
	for _, o := range out {
		if o.PortEnd == 65535 && !o.IPv6 {
			t.Errorf("synthesized range tuple lost the IPv6 flag: %+v", o)
		}
	}
	// End to end: Analyze must still exclude everything as IPv6.
	a := Analyze(tuples, AnalyzeOptions{})
	if len(a.Tuples) != 0 {
		t.Errorf("IPv6 tuples leaked into the analysis: %+v", a.Tuples)
	}
}

// TestPreprocessPairsFTP: passive FTP data channels fold into the control
// tuple, preserving total hits.
func TestPreprocessPairsFTP(t *testing.T) {
	tuples := []TrafficTuple{tup("10.0.0.1", "10.9.9.9", "tcp", 21, "FTP", 40)}
	for _, p := range []int{50100, 50101, 50102, 50103, 50104} {
		tuples = append(tuples, tup("10.0.0.1", "10.9.9.9", "tcp", p, "", 4))
	}
	out, _ := preprocessPairs(tuples)
	if len(out) != 1 || out[0].Port != 21 || out[0].Hits != 60 {
		t.Fatalf("ftp fold failed: %+v", out)
	}
}

// TestAnalyzeWANAsAll: public destinations collapse to the "all" entity,
// private ones stay explicit.
func TestAnalyzeWANAsAll(t *testing.T) {
	tuples := []TrafficTuple{
		tup("10.0.0.1", "142.250.1.1", "tcp", 443, "HTTPS", 100), // public
		tup("10.0.0.1", "52.96.1.2", "tcp", 443, "HTTPS", 50),    // public
		tup("10.0.0.1", "192.168.5.10", "tcp", 443, "HTTPS", 10), // private
	}
	a := Analyze(tuples, AnalyzeOptions{WANAsAll: true})
	if e := a.DstEnts["142.250.1.1"]; e.Value != "all" || e.Hosts != 2 {
		t.Errorf("public dst entity = %+v", e)
	}
	if e := a.DstEnts["52.96.1.2"]; e.Value != "all" {
		t.Errorf("public dst entity = %+v", e)
	}
	if e := a.DstEnts["192.168.5.10"]; e.Value != "192.168.5.10" {
		t.Errorf("private dst must stay explicit: %+v", e)
	}
	// Per-service grouping now yields one policy with dst all + the private host.
	pols := BuildPerService(a)
	if len(pols) != 1 || len(pols[0].Dst) != 2 {
		t.Errorf("policies = %+v", pols)
	}
}

// TestWANAsAllNonPublicRanges: degenerate/non-unicast destinations
// (this-network, multicast, reserved incl. broadcast) are NOT routable
// internet destinations and must not collapse to "all".
func TestWANAsAllNonPublicRanges(t *testing.T) {
	tuples := []TrafficTuple{
		tup("10.0.0.1", "8.8.8.8", "udp", 53, "DNS", 100),        // genuinely public
		tup("10.0.0.1", "224.0.0.251", "udp", 5353, "MDNS", 5),   // multicast
		tup("10.0.0.1", "255.255.255.255", "udp", 67, "DHCP", 5), // broadcast (reserved)
		tup("10.0.0.1", "0.0.0.0", "udp", 68, "", 3),             // this-network
		tup("10.0.0.1", "192.0.2.55", "tcp", 80, "HTTP", 4),      // TEST-NET-1
		tup("10.0.0.1", "198.51.100.7", "tcp", 80, "HTTP", 4),    // TEST-NET-2
		tup("10.0.0.1", "203.0.113.9", "tcp", 80, "HTTP", 4),     // TEST-NET-3
		tup("10.0.0.1", "198.18.0.20", "tcp", 80, "HTTP", 4),     // benchmarking
		tup("10.0.0.1", "192.0.0.8", "tcp", 80, "HTTP", 4),       // IETF proto assignments
	}
	a := Analyze(tuples, AnalyzeOptions{WANAsAll: true})
	if e := a.DstEnts["8.8.8.8"]; e.Value != "all" {
		t.Errorf("public dst should collapse to all: %+v", e)
	}
	for _, ip := range []string{"224.0.0.251", "255.255.255.255", "0.0.0.0",
		"192.0.2.55", "198.51.100.7", "203.0.113.9", "198.18.0.20", "192.0.0.8"} {
		if e := a.DstEnts[ip]; e.Value != ip {
			t.Errorf("non-public %s must stay explicit, got %+v", ip, e)
		}
	}
}

// TestAnalyzeFirewallSelfExcluded: flows to the firewall's own addresses are
// local-in traffic and never reach the recommendations.
func TestAnalyzeFirewallSelfExcluded(t *testing.T) {
	tuples := []TrafficTuple{
		tup("10.0.0.1", "10.0.0.254", "tcp", 443, "HTTPS", 10), // firewall GUI
		tup("10.0.0.1", "10.9.9.9", "tcp", 443, "HTTPS", 10),
	}
	a := Analyze(tuples, AnalyzeOptions{FirewallIPs: map[string]bool{"10.0.0.254": true}})
	if len(a.Tuples) != 1 || a.Tuples[0].DstIP != "10.9.9.9" {
		t.Errorf("tuples = %+v", a.Tuples)
	}
	found := false
	for _, w := range a.Warnings {
		if strings.Contains(w, "local-in") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing local-in warning: %v", a.Warnings)
	}
}

// TestAnalyzeForcedRollup: a destination /24 with ≥forceRollupHosts hosts
// rolls up even with rollup disabled.
func TestAnalyzeForcedRollup(t *testing.T) {
	var tuples []TrafficTuple
	for i := 1; i <= forceRollupHosts; i++ {
		tuples = append(tuples, tup("10.0.0.1", fmt.Sprintf("10.50.1.%d", i), "tcp", 443, "HTTPS", 2))
	}
	a := Analyze(tuples, AnalyzeOptions{}) // rollup off
	if e := a.DstEnts["10.50.1.1"]; !e.IsNet || e.Value != "10.50.1.0/24" {
		t.Errorf("forced rollup entity = %+v", e)
	}
	found := false
	for _, w := range a.Warnings {
		if strings.Contains(w, "rolled up regardless") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing forced-rollup warning: %v", a.Warnings)
	}
}

// TestMergeDualProtoAndWellKnown: tcp/53+udp/53 merge to tcpudp/53 named DNS;
// unnamed tcp/3389 gets the well-known RDP label.
func TestMergeDualProtoAndWellKnown(t *testing.T) {
	pols := []RecPolicy{{
		Src: []Entity{ent("10.0.0.1")},
		Dst: []Entity{ent("10.9.9.9")},
		Services: []ServiceSpec{
			{Key: "tcp/53", Proto: "tcp", Port: 53},
			{Key: "udp/53", Proto: "udp", Port: 53},
			{Key: "tcp/3389", Proto: "tcp", Port: 3389},
		},
	}}
	out := finalizePolicies(pols)
	keys := map[string]string{}
	for _, s := range out[0].Services {
		keys[s.Key] = s.LogName
	}
	if len(out[0].Services) != 2 {
		t.Fatalf("services = %+v", out[0].Services)
	}
	if keys["tcpudp/53"] != "DNS" {
		t.Errorf("merged spec = %v", keys)
	}
	if keys["tcp/3389"] != "RDP" {
		t.Errorf("well-known label = %v", keys)
	}
}

// TestPolicyTags: AD bundles and pure infrastructure policies get tagged.
func TestPolicyTags(t *testing.T) {
	ad := RecPolicy{Services: []ServiceSpec{
		{Key: "tcp/88", Proto: "tcp", Port: 88},
		{Key: "tcp/389", Proto: "tcp", Port: 389},
		{Key: "tcp/445", Proto: "tcp", Port: 445},
		{Key: "tcp/443", Proto: "tcp", Port: 443},
	}}
	tags := policyTags(ad)
	if len(tags) != 1 || tags[0] != "active-directory" {
		t.Errorf("ad tags = %v", tags)
	}
	infra := RecPolicy{Services: []ServiceSpec{
		{Key: "tcpudp/53", Proto: "tcpudp", Port: 53},
		{Key: "udp/123", Proto: "udp", Port: 123},
	}}
	if tags := policyTags(infra); len(tags) != 1 || tags[0] != "infrastructure" {
		t.Errorf("infra tags = %v", tags)
	}
	plain := RecPolicy{Services: []ServiceSpec{{Key: "tcp/443", Proto: "tcp", Port: 443}}}
	if tags := policyTags(plain); len(tags) != 0 {
		t.Errorf("plain tags = %v", tags)
	}
}

// TestFlagFlows: analysis-only tuples are marked new; baseline-only returned
// as stale.
func TestFlagFlows(t *testing.T) {
	current := []TrafficTuple{
		tup("10.0.0.1", "10.9.9.9", "tcp", 443, "HTTPS", 10), // established
		tup("10.0.0.2", "10.9.9.9", "tcp", 22, "SSH", 5),     // new
	}
	baseline := []TrafficTuple{
		tup("10.0.0.1", "10.9.9.9", "tcp", 443, "HTTPS", 99),
		tup("10.0.0.3", "10.7.7.7", "udp", 53, "DNS", 7), // stale
	}
	stale := flagFlows(current, baseline)
	if current[0].Flow != "" || current[1].Flow != "new" {
		t.Errorf("flow flags = %q / %q", current[0].Flow, current[1].Flow)
	}
	if len(stale) != 1 || stale[0].SrcIP != "10.0.0.3" || stale[0].Flow != "stale" {
		t.Errorf("stale = %+v", stale)
	}
}

func TestParseTupleRows(t *testing.T) {
	schema := []aggregateColumn{
		{ColumnType: "metric", Function: "count"},
		{ColumnType: "grouping", Field: "dstip"},
		{ColumnType: "grouping", Field: "srcip"},
		{ColumnType: "grouping", Field: "proto"},
		{ColumnType: "grouping", Field: "service"},
		{ColumnType: "grouping", Field: "dstport"},
		{ColumnType: "metric", Function: "latest", Field: "timestamp"},
	}
	rows := [][]any{
		{float64(42), "10.0.1.1", "10.0.0.1", float64(6), "HTTPS", float64(443), "2026-07-16T10:00:00.000Z"},
		{float64(7), "(Empty Value)", "10.0.0.1", float64(6), "x", float64(1), nil}, // dropped
	}
	tuples := parseTupleRows(schema, rows)
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple, got %d", len(tuples))
	}
	tt := tuples[0]
	if tt.SrcIP != "10.0.0.1" || tt.DstIP != "10.0.1.1" || tt.Proto != "tcp" ||
		tt.Port != 443 || tt.Service != "HTTPS" || tt.Hits != 42 || tt.LastSeen == "" {
		t.Errorf("tuple = %+v", tt)
	}
}

func TestBuildQuery(t *testing.T) {
	tmpl := `source:"%s" AND policyid:%s AND _exists_:srcip`
	q, err := buildQuery(tmpl, []string{"fw-01"}, 42)
	if err != nil {
		t.Fatal(err)
	}
	if q != `source:"fw-01" AND policyid:42 AND _exists_:srcip` {
		t.Errorf("q = %q", q)
	}
	// HA cluster: grouped OR
	q, err = buildQuery(tmpl, []string{"fw-n1", "fw-n2"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if q != `(source:"fw-n1" OR source:"fw-n2") AND policyid:7 AND _exists_:srcip` {
		t.Errorf("q = %q", q)
	}
	// template without source term gets the clause prepended
	q, err = buildQuery(`policyid:%s AND type:traffic`, []string{"fw"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if q != `source:"fw" AND (policyid:1 AND type:traffic)` {
		t.Errorf("q = %q", q)
	}
	// leftover placeholder must error
	if _, err = buildQuery(`source:"%s" AND foo:%s AND policyid:%s`, []string{"fw"}, 1); err == nil {
		t.Error("expected error for stray placeholder")
	}
	if _, err = buildQuery(tmpl, nil, 1); err == nil {
		t.Error("expected error for empty sources")
	}
}
