package fgtconftail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testGraylogFields = []string{
	"timestamp",
	"gl2_message_id",
	"eventtime",
	"type",
	"subtype",
	"source",
	"devname",
	"devid",
	"vd",
	"user",
	"ui",
	"action",
	"cfgtid",
	"cfgpath",
	"cfgobj",
	"cfgattr",
	"logid",
	"logdesc",
	"msg",
	"uuid",
}

type capturedGraylogRequest struct {
	Query     string   `json:"query"`
	Fields    []string `json:"fields"`
	From      int      `json:"from"`
	Size      int      `json:"size"`
	Sort      string   `json:"sort"`
	SortOrder string   `json:"sort_order"`
	Timerange struct {
		Type string `json:"type"`
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"timerange"`
}

func TestGraylogFetchPaginatesAndDecodesSchemaOrder(t *testing.T) {
	t.Parallel()

	firstSchema := []string{
		"eventtime", "type", "subtype", "user", "gl2_message_id", "timestamp", "cfgpath",
		"source", "devname", "devid", "vd", "ui", "action", "cfgtid",
		"cfgobj", "cfgattr", "logid", "logdesc", "msg", "uuid",
	}
	secondSchema := []string{
		"uuid", "msg", "timestamp", "source", "gl2_message_id", "eventtime", "type", "subtype",
		"user", "devname", "devid", "vd", "ui", "action", "cfgtid",
		"cfgpath", "cfgobj", "cfgattr", "logid", "logdesc",
	}
	pages := []struct {
		schema  []string
		records []map[string]any
	}{
		{
			schema: firstSchema,
			records: []map[string]any{
				{
					"timestamp":      "2026-03-29T00:30:00.123456789Z",
					"gl2_message_id": "message-b",
					"eventtime":      json.Number("1700000000000000000"),
					"type":           "event",
					"subtype":        "system",
					"source":         "branch-east",
					"devname":        "FGT-A",
					"devid":          "FG100FTK123",
					"vd":             "root",
					"user":           "alice",
					"ui":             "GUI(10.0.0.8)",
					"action":         "Add",
					"cfgtid":         json.Number("42"),
					"cfgpath":        "firewall.policy",
					"cfgobj":         "17",
					"cfgattr":        "name[test]",
					"logid":          "0100044545",
					"logdesc":        "Object attribute configured",
					"msg":            "Edited policy",
					"uuid":           "event-b",
				},
				{
					"timestamp":      "2026-03-29T00:30:00.123456789Z",
					"gl2_message_id": "message-a",
					"eventtime":      json.Number("17000000000000000000"),
					"type":           "event",
					"subtype":        "system",
					"source":         "branch-east",
					"user":           "alice",
					"action":         "Edit",
					"cfgpath":        "system.interface",
				},
			},
		},
		{
			schema: secondSchema,
			records: []map[string]any{
				{
					"timestamp":      "2026-03-29T00:31:00Z",
					"gl2_message_id": "message-c",
					"eventtime":      json.Number("1700000000000000001"),
					"type":           "event",
					"subtype":        "system",
					"source":         "branch-west",
					"user":           "bob",
					"action":         "Delete",
				},
			},
		},
	}

	var requests []capturedGraylogRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/search/messages" {
			t.Errorf("path = %q, want /api/search/messages", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if username, password, ok := r.BasicAuth(); !ok || username != "token-value" || password != "token" {
			t.Errorf("BasicAuth = (%q, %q, %v), want (token-value, token, true)", username, password, ok)
		}
		if got := r.Header.Get("X-Requested-By"); got != "fortisafe" {
			t.Errorf("X-Requested-By = %q, want fortisafe", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q, want application/json", got)
		}

		var request capturedGraylogRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		requests = append(requests, request)
		page := request.From / request.Size
		if page < 0 || page >= len(pages) {
			t.Errorf("unexpected page offset %d", request.From)
			http.Error(w, "unexpected page", http.StatusInternalServerError)
			return
		}
		writeGraylogPage(w, pages[page].schema, pages[page].records)
	}))
	t.Cleanup(server.Close)

	client, err := newGraylogClient(server.URL, "token-value", server.Client())
	if err != nil {
		t.Fatalf("newGraylogClient: %v", err)
	}
	client.pageSize = 2

	fromZone := time.FixedZone("CET", 60*60)
	toZone := time.FixedZone("CEST", 2*60*60)
	from := time.Date(2026, 3, 29, 1, 30, 0, 0, fromZone)
	to := time.Date(2026, 3, 29, 5, 30, 0, 0, toZone)
	events, stats, err := client.fetch(
		context.Background(),
		"logid:(0100044544 OR 0100044545)",
		[]string{`branch\west`, `Branch"East`, `branch\west`},
		from,
		to,
	)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if stats != (FetchStats{Pages: 2, Rows: 3}) {
		t.Fatalf("stats = %+v, want 2 pages and 3 rows", stats)
	}
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3", len(events))
	}

	// Equal timestamps are ordered by the stable Graylog message ID, even if a
	// malformed or inconsistent upstream page sends them in the opposite order.
	if got := []string{events[0].MessageID, events[1].MessageID, events[2].MessageID}; !reflect.DeepEqual(got, []string{"message-a", "message-b", "message-c"}) {
		t.Errorf("message order = %v", got)
	}
	if got := events[0].EventTime.String(); got != "17000000000000000000" {
		t.Errorf("20-digit eventtime = %q", got)
	}
	if got := events[1].EventTime.String(); got != "1700000000000000000" {
		t.Errorf("19-digit eventtime = %q", got)
	}
	if got := events[1].ConfigTransactionID; got != "42" {
		t.Errorf("numeric cfgtid = %q, want 42", got)
	}
	if events[1].DeviceName != "FGT-A" || events[1].ConfigPath != "firewall.policy" {
		t.Errorf("schema-based decode lost fields: %+v", events[1])
	}

	if len(requests) != 2 {
		t.Fatalf("request count = %d, want 2", len(requests))
	}
	wantQuery := `(logid:(0100044544 OR 0100044545)) AND (source:"Branch\"East" OR source:"branch\\west")`
	for i, request := range requests {
		if request.Query != wantQuery {
			t.Errorf("request %d query = %q, want %q", i, request.Query, wantQuery)
		}
		if !reflect.DeepEqual(request.Fields, testGraylogFields) {
			t.Errorf("request %d fields = %v, want %v", i, request.Fields, testGraylogFields)
		}
		if request.From != i*2 || request.Size != 2 {
			t.Errorf("request %d pagination = from %d size %d", i, request.From, request.Size)
		}
		if request.Sort != "gl2_message_id" || request.SortOrder != "asc" {
			t.Errorf("request %d sort = %q %q, want gl2_message_id asc", i, request.Sort, request.SortOrder)
		}
		if request.Timerange.Type != "absolute" ||
			request.Timerange.From != "2026-03-29T00:30:00Z" ||
			request.Timerange.To != "2026-03-29T03:30:00Z" {
			t.Errorf("request %d timerange = %+v", i, request.Timerange)
		}
	}
}

func TestGraylogFetchPaginatesMoreThanOneThousandResults(t *testing.T) {
	t.Parallel()

	const resultCount = 1001
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request capturedGraylogRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		requestCount.Add(1)
		end := min(request.From+request.Size, resultCount)
		records := make([]map[string]any, 0, max(0, end-request.From))
		for index := request.From; index < end; index++ {
			records = append(records, map[string]any{
				"timestamp":      "2026-09-01T12:00:00Z",
				"gl2_message_id": fmt.Sprintf("message-%04d", index),
			})
		}
		writeGraylogPage(w, testGraylogFields, records)
	}))
	t.Cleanup(server.Close)

	client, err := newGraylogClient(server.URL, "token-value", server.Client())
	if err != nil {
		t.Fatalf("newGraylogClient: %v", err)
	}
	client.pageSize = graylogMaxPageSize
	events, stats, err := client.fetch(
		context.Background(),
		"logid:0100044544",
		[]string{"branch-east"},
		time.Date(2026, time.September, 1, 11, 0, 0, 0, time.UTC),
		time.Date(2026, time.September, 1, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if stats != (FetchStats{Pages: 2, Rows: resultCount}) {
		t.Fatalf("stats = %+v, want 2 pages and %d rows", stats, resultCount)
	}
	if len(events) != resultCount {
		t.Fatalf("len(events) = %d, want %d", len(events), resultCount)
	}
	if events[0].MessageID != "message-0000" || events[resultCount-1].MessageID != "message-1000" {
		t.Fatalf("result boundaries = (%q, %q)", events[0].MessageID, events[resultCount-1].MessageID)
	}
	if requestCount.Load() != 2 {
		t.Fatalf("request count = %d, want 2", requestCount.Load())
	}
}

func TestGraylogFetchRejectsUntrustedResponses(t *testing.T) {
	t.Parallel()

	validRecord := map[string]any{
		"timestamp":      "2026-08-01T00:00:00Z",
		"gl2_message_id": "message-1",
	}
	tests := []struct {
		name         string
		status       int
		body         func(http.ResponseWriter)
		bodyLimit    int64
		wantContains string
	}{
		{
			name:         "client status",
			status:       http.StatusBadRequest,
			body:         func(w http.ResponseWriter) { _, _ = io.WriteString(w, "invalid query") },
			wantContains: "HTTP 400",
		},
		{
			name:         "server status",
			status:       http.StatusInternalServerError,
			body:         func(w http.ResponseWriter) { _, _ = io.WriteString(w, "failed upstream") },
			wantContains: "HTTP 500",
		},
		{
			name:         "malformed JSON",
			status:       http.StatusOK,
			body:         func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"schema":`) },
			wantContains: "decode",
		},
		{
			name:   "trailing JSON",
			status: http.StatusOK,
			body: func(w http.ResponseWriter) {
				writeGraylogPage(w, testGraylogFields, []map[string]any{validRecord})
				_, _ = io.WriteString(w, `{}`)
			},
			wantContains: "trailing",
		},
		{
			name:         "oversized body",
			status:       http.StatusOK,
			body:         func(w http.ResponseWriter) { _, _ = io.WriteString(w, strings.Repeat("x", 65)) },
			bodyLimit:    64,
			wantContains: "exceeds",
		},
		{
			name:   "missing requested schema field",
			status: http.StatusOK,
			body: func(w http.ResponseWriter) {
				writeGraylogPage(w, []string{"timestamp"}, []map[string]any{validRecord})
			},
			wantContains: "schema",
		},
		{
			name:   "row width mismatch",
			status: http.StatusOK,
			body: func(w http.ResponseWriter) {
				schema := make([]map[string]any, 0, len(testGraylogFields))
				for _, field := range testGraylogFields {
					schema = append(schema, map[string]any{"column_type": "field", "field": field})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"schema":   schema,
					"datarows": [][]any{{"too", "short"}},
				})
			},
			wantContains: "columns",
		},
		{
			name:   "invalid eventtime type",
			status: http.StatusOK,
			body: func(w http.ResponseWriter) {
				bad := map[string]any{
					"timestamp":      "2026-08-01T00:00:00Z",
					"gl2_message_id": "message-1",
					"eventtime":      map[string]any{"value": 1},
				}
				writeGraylogPage(w, testGraylogFields, []map[string]any{bad})
			},
			wantContains: "eventtime",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				test.body(w)
			}))
			t.Cleanup(server.Close)

			client, err := newGraylogClient(server.URL, "token", server.Client())
			if err != nil {
				t.Fatalf("newGraylogClient: %v", err)
			}
			if test.bodyLimit != 0 {
				client.maxResponseBytes = test.bodyLimit
			}
			events, stats, err := client.fetch(
				context.Background(),
				"logid:0100044544",
				nil,
				time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
				time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC),
			)
			if err == nil || !strings.Contains(err.Error(), test.wantContains) {
				t.Fatalf("error = %v, want substring %q", err, test.wantContains)
			}
			if events != nil {
				t.Errorf("events = %#v, want nil on invalid response", events)
			}
			if stats != (FetchStats{}) {
				t.Errorf("stats = %+v, want zero before a valid page", stats)
			}
		})
	}
}

func TestGraylogFetchCancellation(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	defer close(release)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	client, err := newGraylogClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatalf("newGraylogClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	events, stats, err := client.fetch(
		ctx,
		"logid:0100044544",
		nil,
		time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC),
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
	if events != nil || stats != (FetchStats{}) {
		t.Errorf("partial result on cancellation: events=%v stats=%+v", events, stats)
	}
}

func TestGraylogFetchIntermediatePageFailureIsAllOrNothing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request capturedGraylogRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if request.From == 0 {
			writeGraylogPage(w, testGraylogFields, []map[string]any{
				{"timestamp": "2026-08-01T00:00:00Z", "gl2_message_id": "message-1"},
				{"timestamp": "2026-08-01T00:01:00Z", "gl2_message_id": "message-2"},
			})
			return
		}
		http.Error(w, "temporary Graylog outage", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client, err := newGraylogClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatalf("newGraylogClient: %v", err)
	}
	client.pageSize = 2

	events, stats, err := client.fetch(
		context.Background(),
		"logid:0100044544",
		nil,
		time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC),
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("error = %v, want HTTP 503", err)
	}
	if events != nil {
		t.Errorf("events = %#v, want nil when a later page fails", events)
	}
	if stats != (FetchStats{Pages: 1, Rows: 2}) {
		t.Errorf("stats = %+v, want the one completed page and its two rows", stats)
	}
}

func TestGraylogFetchDoesNotExposeErrorResponseBody(t *testing.T) {
	t.Parallel()
	const untrustedBody = "customer-secret-value\nforged_log_field=true"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, untrustedBody, http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := newGraylogClient(server.URL, "test-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.fetch(
		context.Background(),
		"type:event",
		[]string{"fw-a"},
		time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 1, 8, 15, 0, 0, time.UTC),
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("fetch error = %v, want only the HTTP status", err)
	}
	if strings.Contains(err.Error(), "customer-secret") || strings.Contains(err.Error(), "forged_log_field") {
		t.Fatalf("fetch error exposed the untrusted response body: %v", err)
	}
}

func TestGraylogFetchBoundsDecodedDataAcrossPages(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeGraylogPage(w, graylogSelectedFields, []map[string]any{{
			"timestamp":      "2026-09-01T08:01:00Z",
			"gl2_message_id": "message-1",
			"source":         "fw-a",
			"logid":          "0100044544",
			"msg":            strings.Repeat("x", 128),
		}})
	}))
	defer server.Close()
	client, err := newGraylogClient(server.URL, "test-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.maxDecodedBytes = 64
	events, _, err := client.fetch(
		context.Background(),
		"type:event",
		[]string{"fw-a"},
		time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 1, 8, 15, 0, 0, time.UTC),
	)
	if err == nil || !strings.Contains(err.Error(), "decoded data") {
		t.Fatalf("fetch error = %v, want decoded-data limit", err)
	}
	if events != nil {
		t.Fatalf("fetch returned partial events after exceeding the decoded-data limit")
	}
}

func TestGraylogFetchValidatesConfigurationAndInput(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		baseURL string
		token   string
	}{
		{name: "empty URL", token: "token"},
		{name: "empty token", baseURL: "https://graylog.example"},
		{name: "invalid scheme", baseURL: "file:///etc/passwd", token: "token"},
		{name: "embedded credentials", baseURL: "https://user:pass@graylog.example", token: "token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newGraylogClient(test.baseURL, test.token, nil); err == nil {
				t.Fatal("newGraylogClient succeeded, want validation error")
			}
		})
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeGraylogPage(w, testGraylogFields, nil)
	}))
	t.Cleanup(server.Close)
	client, err := newGraylogClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatalf("newGraylogClient: %v", err)
	}
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	tests := []struct {
		name    string
		query   string
		sources []string
		from    time.Time
		to      time.Time
	}{
		{name: "blank query", query: " ", from: from, to: to},
		{name: "zero start", query: "logid:*", to: to},
		{name: "inverted window", query: "logid:*", from: to, to: from},
		{name: "blank source", query: "logid:*", sources: []string{"branch-a", " "}, from: from, to: to},
		{name: "control character in source", query: "logid:*", sources: []string{"branch\nall"}, from: from, to: to},
		{name: "too many sources", query: "logid:*", sources: repeatedStrings("branch", graylogMaxSourceAliases+1), from: from, to: to},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events, stats, err := client.fetch(context.Background(), test.query, test.sources, test.from, test.to)
			if err == nil {
				t.Fatal("fetch succeeded, want validation error")
			}
			if events != nil || stats != (FetchStats{}) {
				t.Errorf("invalid input returned events=%v stats=%+v", events, stats)
			}
		})
	}
	if calls.Load() != 0 {
		t.Errorf("Graylog called %d times for invalid input", calls.Load())
	}
}

func writeGraylogPage(w http.ResponseWriter, schemaFields []string, records []map[string]any) {
	schema := make([]map[string]any, 0, len(schemaFields))
	for _, field := range schemaFields {
		schema = append(schema, map[string]any{
			"column_type": "field",
			"type":        "unknown",
			"field":       field,
			"name":        "field: " + field,
		})
	}
	rows := make([][]any, 0, len(records))
	for _, record := range records {
		row := make([]any, len(schemaFields))
		for i, field := range schemaFields {
			row[i] = record[field]
		}
		rows = append(rows, row)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema":   schema,
		"datarows": rows,
		"metadata": map[string]any{"ignored": true},
	})
}

func repeatedStrings(value string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = value
	}
	return values
}
