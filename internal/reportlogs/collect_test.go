package reportlogs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

var observationTime = time.Date(2026, 11, 3, 12, 0, 0, 123000000, time.UTC)

func observationInput() (reportmodel.Source, reportmodel.Assessment, reportmodel.Profile) {
	p := reportmodel.DefaultProfile("en")
	p.Filters.VDOMs = []string{"root"}
	return reportmodel.Source{FirewallID: 1, Firewall: "firewall.example.test"}, reportmodel.Assessment{Hostname: "fgt-node", VDOMs: []string{"root"}}, p
}

func testCollector(t *testing.T, handler http.HandlerFunc) *Collector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return New(&config.Config{GraylogURL: server.URL, GraylogToken: "PRIVATE_API_TOKEN", AllowInsecureHTTPIntegrations: true}, t.TempDir())
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

func fixtureTotal(query string) int64 {
	if strings.Count(query, "timestamp:[") == 2 {
		return 10
	}
	if strings.Contains(query, "logid:") {
		return 12
	}
	if strings.Contains(query, `type:"utm"`) {
		return 12
	}
	if strings.Contains(query, `type:"event"`) {
		return 5
	}
	if strings.Contains(query, `type:"traffic"`) {
		if strings.Contains(query, "_exists_:app") {
			return 100
		}
		return 120
	}
	return 150
}

func fixtureAggregation(request aggregateRequest) aggregateResponse {
	response := aggregateResponse{Schema: []aggregateColumn{}, Datarows: [][]any{}}
	for _, group := range request.GroupBy {
		response.Schema = append(response.Schema, aggregateColumn{ColumnType: "grouping", Field: group.Field})
	}
	for _, metric := range request.Metrics {
		response.Schema = append(response.Schema, aggregateColumn{ColumnType: "metric", Function: metric.Function, Field: metric.Field})
	}
	if len(request.GroupBy) == 0 {
		response.Datarows = [][]any{{12, json.Number("180000.0"), json.Number("1.2e5")}}
		return response
	}
	switch request.GroupBy[0].Field {
	case "action":
		response.Datarows = [][]any{{"accept", 100}, {"deny", 20}}
	case "app":
		response.Datarows = [][]any{{"HTTPS", 60}, {"DNS", 20}}
	case "srcip":
		response.Datarows = [][]any{{"10.10.0.5", 120}}
	case "dstip":
		response.Datarows = [][]any{{"203.0.113.10", 120}}
	case "vd":
		response.Datarows = [][]any{{"root", 42, 120}}
	case "subtype":
		response.Datarows = [][]any{{"ips", "blocked", 12}}
	case "vpntunnel":
		response.Datarows = [][]any{{"branch-office", "tunnel-up", 5}}
	}
	return response
}

func TestCollectUsesPinnedAggregatesCoverageAndNonoverlappingBuckets(t *testing.T) {
	var calls, inFlight, peak atomic.Int32
	var lock sync.Mutex
	queries := []string{}
	c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(time.Millisecond)
		user, password, ok := r.BasicAuth()
		if !ok || user != "PRIVATE_API_TOKEN" || password != "token" {
			t.Error("unexpected authentication contract")
		}
		var query, from, to string
		if r.Method == http.MethodGet {
			if r.URL.Path != "/api/search/universal/absolute" || r.URL.Query().Get("limit") != "1" {
				t.Errorf("unexpected count endpoint: %s", r.URL.Path)
			}
			query, from, to = r.URL.Query().Get("query"), r.URL.Query().Get("from"), r.URL.Query().Get("to")
			writeJSON(t, w, map[string]any{"total_results": fixtureTotal(query), "messages": []any{map[string]string{"message": "PRIVATE_RAW_LOG_SECRET"}}})
		} else {
			if r.URL.Path != "/api/search/aggregate" || r.Header.Get("X-Requested-By") == "" {
				t.Error("unexpected aggregation request")
			}
			var request aggregateRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			query, from, to = request.Query, request.Timerange.From, request.Timerange.To
			for _, group := range request.GroupBy {
				if group.Limit != 20 {
					t.Error("aggregation grouping was not bounded")
				}
			}
			writeJSON(t, w, fixtureAggregation(request))
		}
		if !strings.Contains(query, `source:"fgt-node"`) || !strings.Contains(query, `vd:"root"`) || !strings.Contains(query, "timestamp:[") {
			t.Errorf("query lost source/VDOM/window scope: %s", query)
		}
		if from != observationTime.Add(-24*time.Hour).Format(time.RFC3339Nano) || to != observationTime.Format(time.RFC3339Nano) {
			t.Errorf("request changed the absolute window: %s..%s", from, to)
		}
		lock.Lock()
		queries = append(queries, query)
		lock.Unlock()
	})
	source, a, p := observationInput()
	result := c.Collect(context.Background(), source, a, p, observationTime)
	if result.Status != "partial" || len(result.Datasets) != 9 || calls.Load() > 40 || peak.Load() > 2 || peak.Load() < 2 {
		t.Fatalf("status/dataset/resource bounds: %+v calls=%d peak=%d", result, calls.Load(), peak.Load())
	}
	byID := map[string]reportmodel.TelemetryDataset{}
	for _, dataset := range result.Datasets {
		byID[dataset.ID] = dataset
		if dataset.Status == "error" {
			t.Errorf("unexpected dataset failure %s: %s", dataset.ID, dataset.Reason)
		}
	}
	app := byID["applications"]
	if app.Total != 120 || app.Returned != 2 || !app.Truncated || len(app.MissingFields) != 1 || len(app.Rows) != 4 || app.Rows[2].Count != 20 || app.Rows[3].Count != 20 {
		t.Fatalf("coverage or remainder was lost: %+v", app)
	}
	bytes := byID["reported_bytes"]
	if bytes.Status != "available" || bytes.Total != 12 || len(bytes.Rows) != 1 || *bytes.Rows[0].Bytes != 300000 || *bytes.Rows[0].SentBytes != 180000 {
		t.Fatalf("byte counters: %+v", bytes)
	}
	trend := byID["traffic_trend"]
	if trend.Total != 120 || len(trend.Rows) != 12 || trend.Status != "available" {
		t.Fatalf("trend: %+v", trend)
	}
	for i, row := range trend.Rows {
		start := observationTime.Add(-24*time.Hour + time.Duration(i)*2*time.Hour)
		if !row.Timestamp.Equal(start) || row.Label != start.Format(time.RFC3339Nano) || row.Secondary != start.Add(2*time.Hour).Format(time.RFC3339Nano) || row.Count != 10 {
			t.Fatal("trend bucket boundaries or counts are wrong")
		}
	}
	lock.Lock()
	defer lock.Unlock()
	buckets := map[string]bool{}
	for _, query := range queries {
		if strings.Count(query, "timestamp:[") == 2 {
			buckets[query[strings.LastIndex(query, "timestamp:["):]] = true
		}
		if strings.Contains(query, "sentbyte") && !strings.Contains(query, `logid:"0000000013"`) {
			t.Fatal("byte counts included start/stat records")
		}
	}
	if len(buckets) != 12 {
		t.Fatalf("trend bucket query count = %d", len(buckets))
	}
	for i := 0; i < 12; i++ {
		start := observationTime.Add(-24*time.Hour + time.Duration(i)*2*time.Hour)
		if !buckets[halfOpenWindow(start, start.Add(2*time.Hour))] {
			t.Fatal("trend must use adjacent half-open intervals")
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "PRIVATE_") {
		t.Fatal("raw messages or credentials escaped the collector")
	}
}

func TestNoDataMissingFieldsAndErrorsRemainDistinct(t *testing.T) {
	cases := []struct{ name, status string }{{"none", "no_data"}, {"unmapped", "missing_fields"}, {"HTTP", "error"}, {"malformed", "error"}, {"oversize", "error"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
				switch tc.name {
				case "none":
					writeJSON(t, w, map[string]any{"total_results": 0})
				case "unmapped":
					n := 10
					if strings.Contains(r.URL.Query().Get("query"), "_exists_:type") {
						n = 0
					}
					writeJSON(t, w, map[string]any{"total_results": n})
				case "HTTP":
					http.Error(w, "PRIVATE_RESPONSE_BODY", http.StatusForbidden)
				case "malformed":
					_, _ = w.Write([]byte(`{"total_results":1.5}`))
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat(" ", maxResponse+1)))
				}
			})
			s, a, p := observationInput()
			result := c.Collect(context.Background(), s, a, p, observationTime)
			if result.Status != tc.status || strings.Contains(result.Reason, "PRIVATE_") || len(result.Datasets) != 0 {
				t.Fatalf("unexpected state: %+v", result)
			}
		})
	}
}

func TestNoRedirectOrUnapprovedPlainHTTP(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetRequests.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	s, a, p := observationInput()
	c := New(&config.Config{GraylogURL: redirect.URL, GraylogToken: "PRIVATE_API_TOKEN", AllowInsecureHTTPIntegrations: true}, "")
	result := c.Collect(context.Background(), s, a, p, observationTime)
	if result.Status != "error" || targetRequests.Load() != 0 || strings.Contains(result.Reason, redirect.URL) {
		t.Fatalf("redirect was followed or leaked a URL: %+v", result)
	}
	for _, address := range []string{target.URL, "https://user:pass@example.test", "https://example.test?token=private", "https://example.test#fragment"} {
		result = New(&config.Config{GraylogURL: address, GraylogToken: "PRIVATE_API_TOKEN"}, "").Collect(context.Background(), s, a, p, observationTime)
		if result.Status != "error" {
			t.Errorf("unapproved endpoint accepted: %s", address)
		}
	}
	p.Traffic = false
	if result = c.Collect(context.Background(), s, a, p, observationTime); result.Status != "disabled" {
		t.Fatal("profile-disabled collection still contacted integration")
	}
	p.Traffic = true
	if result = New(nil, "").Collect(context.Background(), s, a, p, observationTime); result.Status != "not_configured" {
		t.Fatal("missing integration was misrepresented")
	}
}

func TestExactNumbersAndAdversarialAggregation(t *testing.T) {
	valid := map[string]int64{"9007199254740993": 9007199254740993, "9223372036854775807": math.MaxInt64, "12.0": 12, "1.2e3": 1200, "0": 0}
	for text, want := range valid {
		if got, err := nonnegativeInteger(json.Number(text)); err != nil || got != want {
			t.Errorf("%s -> %d %v", text, got, err)
		}
	}
	for _, value := range []any{json.Number("-1"), json.Number("0.1"), json.Number("9223372036854775808"), json.Number("1e999999999"), json.Number(""), "123", float64(3)} {
		if _, err := nonnegativeInteger(value); err == nil {
			t.Errorf("unsafe numeric value accepted: %v", value)
		}
	}
	schema := []aggregateColumn{{ColumnType: "metric", Function: "count"}, {ColumnType: "grouping", Field: "action"}}
	rows, err := groupedRows(aggregateResponse{Schema: schema, Datarows: [][]any{{json.Number("9007199254740993"), "accept"}}}, []string{"action"})
	if err != nil || rows[0].Count != 9007199254740993 || rows[0].Label != "accept" {
		t.Fatal("column binding or integer precision was lost")
	}
	for _, data := range [][][]any{{{json.Number("1"), "accept"}, {json.Number("1"), "accept"}}, {{json.Number("-1"), "accept"}}, {{json.Number("1")}}, {{json.Number("1"), nil}}} {
		if _, err := groupedRows(aggregateResponse{Schema: schema, Datarows: data}, []string{"action"}); err == nil {
			t.Fatal("malformed or duplicate aggregation accepted")
		}
	}
}

func TestMappingExactPrecedenceAmbiguityAndFallback(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err = db.Exec(`CREATE TABLE vpn_config (dns_name_full TEXT, dns_name TEXT, firewallname TEXT, cluster_hostnames TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][4]string{{"fw.customer-a.test", "fw", "fw", "a-secondary,a-primary"}, {"fw.customer-b.test", "fw", "fw", "b-node"}, {"alias.test", "fw.customer-a.test", "other", "wrong-alias"}} {
		if _, err = db.Exec(`INSERT INTO vpn_config VALUES (?,?,?,?)`, row[0], row[1], row[2], row[3]); err != nil {
			t.Fatal(err)
		}
	}
	c := New(nil, dir)
	source := reportmodel.Source{Firewall: "fw.customer-a.test"}
	hosts, err := c.sources(context.Background(), source, reportmodel.Assessment{Hostname: "ignored-config-host"})
	if err != nil || strings.Join(hosts, ",") != "a-primary,a-secondary" {
		t.Fatalf("canonical identity did not win: %v %v", hosts, err)
	}
	source.Firewall = "fw.unknown.test"
	if _, err = c.sources(context.Background(), source, reportmodel.Assessment{Hostname: "must-not-bypass-ambiguity"}); err == nil {
		t.Fatal("ambiguous short name fell back to a wider binding")
	}
	source.Firewall = "unique.test"
	hosts, err = c.sources(context.Background(), source, reportmodel.Assessment{Hostname: "config-host"})
	if err != nil || strings.Join(hosts, ",") != "config-host" {
		t.Fatalf("configuration hostname fallback: %v %v", hosts, err)
	}
	hosts, err = c.sources(context.Background(), source, reportmodel.Assessment{})
	if err != nil || strings.Join(hosts, ",") != "unique" {
		t.Fatalf("short firewall fallback: %v %v", hosts, err)
	}
	if _, err = db.Exec(`INSERT INTO vpn_config VALUES (?,?,?,?)`, "fw.customer-a.test", "duplicate", "duplicate", "bad-node"); err != nil {
		t.Fatal(err)
	}
	source.Firewall = "fw.customer-a.test"
	if _, err = c.sources(context.Background(), source, reportmodel.Assessment{}); err == nil {
		t.Fatal("duplicate canonical identity was accepted")
	}
}

func TestScopeEscapesQueriesAndNeverDropsVDOM(t *testing.T) {
	window := timeWindow{start: observationTime.Add(-time.Hour), end: observationTime}
	query := scopeQuery([]string{`source" OR *:*`, "ha-peer"}, []string{`vdom" OR *:*`}, window)
	if !strings.Contains(query, `source:"source\" OR *:*"`) || !strings.Contains(query, `vd:"vdom\" OR *:*"`) || !strings.Contains(query, `source:"ha-peer"`) {
		t.Fatalf("literal values escaped their query scope: %s", query)
	}
	var calls atomic.Int32
	c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.Contains(r.URL.Query().Get("query"), `vd:"root"`) {
			t.Error("VDOM scope was removed")
		}
		writeJSON(t, w, map[string]any{"total_results": 0})
	})
	s, a, p := observationInput()
	if got := c.Collect(context.Background(), s, a, p, observationTime); got.Status != "no_data" || calls.Load() != 1 {
		t.Fatalf("empty scoped result must not retry unscoped: %+v calls=%d", got, calls.Load())
	}
}

func TestCancellationAndQueryBudget(t *testing.T) {
	var calls atomic.Int32
	c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(t, w, map[string]any{"total_results": 1})
	})
	s, a, p := observationInput()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := c.Collect(ctx, s, a, p, observationTime); got.Status != "error" || calls.Load() != 0 {
		t.Fatalf("canceled collection did work: %+v", got)
	}
	r := &run{collector: c, window: timeWindow{observationTime.Add(-time.Hour), observationTime}, sem: make(chan struct{}, 2), counts: map[string]*countResult{}}
	for i := 0; i < maxQueries; i++ {
		if _, err := r.count(context.Background(), fmt.Sprintf("source:test AND unique:%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.count(context.Background(), "beyond:budget"); err == nil || calls.Load() != maxQueries {
		t.Fatal("query budget did not prevent the extra HTTP request")
	}
}

func TestServerAdjustedEffectiveWindowIsRejected(t *testing.T) {
	r := &run{window: timeWindow{observationTime.Add(-24 * time.Hour), observationTime}}
	for _, offset := range []time.Duration{0, time.Hour, -time.Hour} {
		metadata := responseMetadata{EffectiveTimerange: aggregateTimerange{Type: "absolute", From: r.window.start.Add(offset).Format(time.RFC3339Nano), To: r.window.end.Format(time.RFC3339Nano)}}
		if err := r.validateEffectiveWindow(metadata); (err != nil) != (offset != 0) {
			t.Fatalf("offset=%s window-validation=%v", offset, err)
		}
	}
	c := testCollector(t, func(w http.ResponseWriter, req *http.Request) {
		writeJSON(t, w, map[string]any{"total_results": 0, "metadata": responseMetadata{EffectiveTimerange: aggregateTimerange{Type: "absolute", From: observationTime.Add(-time.Hour).Format(time.RFC3339Nano), To: observationTime.Format(time.RFC3339Nano)}}})
	})
	source, a, p := observationInput()
	if result := c.Collect(context.Background(), source, a, p, observationTime); result.Status != "error" {
		t.Fatalf("server-adjusted range was presented as an empty requested window: %+v", result)
	}
}
