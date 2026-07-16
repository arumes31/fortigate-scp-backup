package fgt_polsplit

import (
	"testing"
	"time"
)

// TestSplitTimeRange: chunked loading cuts windows into contiguous absolute
// sub-windows — 1h steps, grown so long windows never exceed maxChunks calls.
func TestSplitTimeRange(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	// 24h relative → 24 × 1h covering [now-24h, now].
	chunks := splitTimeRange(timeRange{RelativeSec: 86400}, now)
	if len(chunks) != 24 {
		t.Fatalf("24h chunks = %d, want 24", len(chunks))
	}
	if chunks[0].From != "2026-07-16T12:00:00.000Z" || chunks[23].To != "2026-07-17T12:00:00.000Z" {
		t.Errorf("bounds = %s .. %s", chunks[0].From, chunks[23].To)
	}
	for i := 1; i < len(chunks); i++ {
		if chunks[i].From != chunks[i-1].To {
			t.Errorf("gap between chunk %d and %d: %s != %s", i-1, i, chunks[i-1].To, chunks[i].From)
		}
	}

	// A window within one step: nothing to split.
	if got := splitTimeRange(timeRange{RelativeSec: 3600}, now); got != nil {
		t.Errorf("1h window must not split: %v", got)
	}

	// 30 days: step grows to 15h so the count caps at maxChunks.
	chunks = splitTimeRange(timeRange{RelativeSec: 30 * 86400}, now)
	if len(chunks) != maxChunks {
		t.Errorf("30d chunks = %d, want %d", len(chunks), maxChunks)
	}

	// Absolute range with a partial trailing chunk.
	chunks = splitTimeRange(timeRange{From: "2026-07-17T00:00:00.000Z", To: "2026-07-17T03:30:00.000Z"}, now)
	if len(chunks) != 4 || chunks[3].To != "2026-07-17T03:30:00.000Z" {
		t.Errorf("3.5h chunks = %+v", chunks)
	}

	// Garbage absolute range degrades to nil (caller keeps the full window).
	if got := splitTimeRange(timeRange{From: "garbage", To: "x"}, now); got != nil {
		t.Errorf("invalid range must not split: %v", got)
	}
}

// TestMergeTuples: identical (src,dst,proto,port,service) rows across chunks
// sum hits and keep the latest timestamp; distinct rows stay separate.
func TestMergeTuples(t *testing.T) {
	a := []TrafficTuple{
		{SrcIP: "10.0.0.1", DstIP: "10.9.9.9", Proto: "tcp", Port: 443, Hits: 10, LastSeen: "2026-07-17T01:00:00.000Z"},
		{SrcIP: "10.0.0.1", DstIP: "10.9.9.9", Proto: "udp", Port: 53, Hits: 5, LastSeen: "2026-07-17T01:00:00.000Z"},
	}
	b := []TrafficTuple{
		{SrcIP: "10.0.0.1", DstIP: "10.9.9.9", Proto: "tcp", Port: 443, Hits: 7, LastSeen: "2026-07-17T02:00:00.000Z"},
		{SrcIP: "10.0.0.2", DstIP: "10.9.9.9", Proto: "tcp", Port: 443, Hits: 1, LastSeen: "2026-07-17T02:00:00.000Z"},
	}
	out := mergeTuples(a, b)
	if len(out) != 3 {
		t.Fatalf("merged = %+v", out)
	}
	byKey := map[string]TrafficTuple{}
	for _, tt := range out {
		byKey[tt.SrcIP+"/"+tt.Proto] = tt
	}
	if m := byKey["10.0.0.1/tcp"]; m.Hits != 17 || m.LastSeen != "2026-07-17T02:00:00.000Z" {
		t.Errorf("merged tuple = %+v", m)
	}
	if m := byKey["10.0.0.1/udp"]; m.Hits != 5 {
		t.Errorf("udp tuple = %+v", m)
	}
}
