package fgt_polsplit

import (
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
