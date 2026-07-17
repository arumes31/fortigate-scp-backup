package fgt_polsplit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

// newStubExtension wires an Extension to a fake Graylog that answers
// /api/search/aggregate with handler-produced rows.
func newStubExtension(t *testing.T, handler http.HandlerFunc) *Extension {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Extension{
		cfg:          &config.Config{GraylogURL: srv.URL, GraylogToken: "tok"},
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		progressByID: map[string]*progressState{},
	}
}

// aggResponse builds one Graylog aggregate response with the tuple schema and
// the given (srcip,dstip,proto,dstport,count,latest) rows.
func aggResponse(rows [][]any) []byte {
	body := map[string]any{
		"schema": []map[string]any{
			{"column_type": "grouping", "field": "srcip"},
			{"column_type": "grouping", "field": "dstip"},
			{"column_type": "grouping", "field": "proto"},
			{"column_type": "grouping", "field": "dstport"},
			{"column_type": "metric", "function": "count"},
			{"column_type": "metric", "function": "latest"},
		},
		"datarows": rows,
	}
	b, _ := json.Marshal(body)
	return b
}

// TestRunChunksConcurrentMerge: every sub-window is queried, results merge by
// (src,dst,proto,port) summing hits, and concurrency stays within the bound.
func TestRunChunksConcurrentMerge(t *testing.T) {
	var inFlight, maxInFlight, calls int32
	e := newStubExtension(t, func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxInFlight)
			if cur <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, cur) {
				break
			}
		}
		atomic.AddInt32(&calls, 1)
		time.Sleep(15 * time.Millisecond) // widen the concurrency window
		atomic.AddInt32(&inFlight, -1)
		// Every chunk reports the same flow, so hits must sum across chunks.
		_, _ = w.Write(aggResponse([][]any{
			{"10.0.0.1", "10.9.9.9", "6", "443", float64(2), "2026-07-17T00:00:00.000Z"},
		}))
	})

	chunks := make([]timeRange, 12)
	for i := range chunks {
		chunks[i] = timeRange{From: fmt.Sprintf("2026-07-17T%02d:00:00.000Z", i), To: fmt.Sprintf("2026-07-17T%02d:00:00.000Z", i+1)}
	}
	out, err := e.runChunks(context.Background(), aggregateRequest{}, chunks, "test")
	if err != nil {
		t.Fatalf("runChunks: %v", err)
	}
	if calls != 12 {
		t.Errorf("expected 12 sub-window calls, got %d", calls)
	}
	if len(out) != 1 || out[0].Hits != 24 { // 12 chunks × 2 hits
		t.Errorf("merged tuples = %+v (want one tuple, 24 hits)", out)
	}
	if maxInFlight < 2 {
		t.Errorf("expected concurrent execution, max in-flight was %d", maxInFlight)
	}
	if maxInFlight > chunkConcurrency {
		t.Errorf("concurrency %d exceeded the bound %d", maxInFlight, chunkConcurrency)
	}
}

// TestRunChunksFirstErrorCancels: one failing sub-window aborts the batch with
// an error, and the failure stops further work.
func TestRunChunksFirstErrorCancels(t *testing.T) {
	var calls int32
	e := newStubExtension(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		atomic.AddInt32(&calls, 1)
		// Fail the sub-window covering hour 05.
		if strings.Contains(string(body), "2026-07-17T05:00:00.000Z") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		time.Sleep(10 * time.Millisecond)
		_, _ = w.Write(aggResponse(nil))
	})
	chunks := make([]timeRange, 12)
	for i := range chunks {
		chunks[i] = timeRange{From: fmt.Sprintf("2026-07-17T%02d:00:00.000Z", i), To: fmt.Sprintf("2026-07-17T%02d:00:00.000Z", i+1)}
	}
	_, err := e.runChunks(context.Background(), aggregateRequest{}, chunks, "test")
	if err == nil {
		t.Fatal("expected an error from the failing sub-window")
	}
	// The returned error must be the root-cause HTTP 500, not the
	// context.Canceled fallout of the cancellation it triggered.
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error must carry the HTTP 500 root cause, got: %v", err)
	}
}

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
