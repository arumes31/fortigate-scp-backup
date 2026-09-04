package fgtconftail

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestSessionExportJSONAndCSVAreStableSafeAndGraylogIndependent(t *testing.T) {
	s, chainID := seededExportStore(t)
	var graylogCalls atomic.Int32
	extension := &Extension{
		store:        s,
		exportLimits: sessionExportLimits{MaxRows: 10, MaxBytes: 1 << 20, PageSize: 2, Timeout: time.Second},
		graylog: &graylogClient{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			graylogCalls.Add(1)
			return nil, context.Canceled
		})}},
	}

	jsonResponse := serveSessionExport(t, extension, chainID, sessionExportJSON, context.Background())
	if jsonResponse.Code != http.StatusOK {
		t.Fatalf("JSON export status = %d, body = %q", jsonResponse.Code, jsonResponse.Body.String())
	}
	if got := jsonResponse.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("JSON content type = %q", got)
	}
	if got := jsonResponse.Header().Get("Content-Disposition"); got != `attachment; filename="fortisafe-conftail-`+chainID+`.json"` {
		t.Fatalf("JSON disposition = %q", got)
	}
	var document struct {
		SchemaVersion int `json:"schema_version"`
		Session       struct {
			ID            string `json:"id"`
			ExportedCount int    `json:"exported_count"`
		} `json:"session"`
		Events []struct {
			EventID int64  `json:"event_id"`
			EventAt string `json:"event_at"`
			Source  string `json:"source"`
			Message string `json:"message"`
		} `json:"events"`
	}
	if err := json.Unmarshal(jsonResponse.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode JSON export: %v\n%s", err, jsonResponse.Body.String())
	}
	if document.SchemaVersion != sessionExportSchemaVersion || document.Session.ID != chainID ||
		document.Session.ExportedCount != 3 || len(document.Events) != 3 {
		t.Fatalf("JSON export metadata = %+v / events %d", document, len(document.Events))
	}
	if document.Events[1].EventAt != document.Events[2].EventAt || document.Events[1].EventID >= document.Events[2].EventID {
		t.Fatalf("equal-time events are not in stored ID order: %+v", document.Events)
	}
	if !strings.Contains(jsonResponse.Body.String(), redactedValue) || graylogCalls.Load() != 0 {
		t.Fatalf("JSON redaction/Graylog calls = %t/%d", strings.Contains(jsonResponse.Body.String(), redactedValue), graylogCalls.Load())
	}

	csvResponse := serveSessionExport(t, extension, chainID, sessionExportCSV, context.Background())
	if csvResponse.Code != http.StatusOK || csvResponse.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("CSV response = %d/%q", csvResponse.Code, csvResponse.Header().Get("Content-Type"))
	}
	records, err := csv.NewReader(strings.NewReader(csvResponse.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 || strings.Join(records[0], ",") != strings.Join(sessionExportCSVHeader, ",") {
		t.Fatalf("CSV records/header = %d/%v", len(records), records[0])
	}
	if records[1][sessionExportCSVSourceColumn] != "'=formula-source" {
		t.Fatalf("CSV formula source was not neutralized: %q", records[1][sessionExportCSVSourceColumn])
	}
	if graylogCalls.Load() != 0 {
		t.Fatalf("export made %d Graylog calls", graylogCalls.Load())
	}
}

func TestSessionExportLimitsCancellationAndMalformedDataReturnNoPartialFile(t *testing.T) {
	s, chainID := seededExportStore(t)
	tests := []struct {
		name   string
		limits sessionExportLimits
		ctx    func() context.Context
		want   int
	}{
		{name: "row limit", limits: sessionExportLimits{MaxRows: 1, MaxBytes: 1 << 20, Timeout: time.Second, PageSize: 10}, ctx: context.Background, want: http.StatusRequestEntityTooLarge},
		{name: "byte limit", limits: sessionExportLimits{MaxRows: 10, MaxBytes: 128, Timeout: time.Second, PageSize: 10}, ctx: context.Background, want: http.StatusRequestEntityTooLarge},
		{name: "cancelled", limits: defaultSessionExportLimits(), ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, want: http.StatusRequestTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extension := &Extension{store: s, exportLimits: test.limits}
			response := serveSessionExport(t, extension, chainID, sessionExportJSON, test.ctx())
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, test.want, response.Body.String())
			}
			if response.Header().Get("Content-Disposition") != "" || strings.Contains(response.Body.String(), "payload-log-sentinel") ||
				!strings.Contains(response.Body.String(), "no partial file was returned") {
				t.Fatalf("limit response looks partial: headers=%v body=%q", response.Header(), response.Body.String())
			}
		})
	}

	if _, err := s.db.Exec(`UPDATE events SET event_at_ns = 'legacy-not-a-timestamp' WHERE chain_id = ?`, chainID); err != nil {
		t.Fatal(err)
	}
	malformed := serveSessionExport(t, &Extension{store: s}, chainID, sessionExportCSV, context.Background())
	if malformed.Code != http.StatusInternalServerError || malformed.Header().Get("Content-Disposition") != "" ||
		!strings.Contains(malformed.Body.String(), "cannot be exported safely") {
		t.Fatalf("malformed export = %d/%v/%q", malformed.Code, malformed.Header(), malformed.Body.String())
	}
}

func TestSessionExportSupportsEmptyStoredSession(t *testing.T) {
	s := newTestStore(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC))
	const chainID = "11111111-2222-3333-4444-555555555555"
	if _, err := s.db.Exec(`INSERT INTO chains (
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed, sealed_at_ns, created_at_ns
	) VALUES (?, 1, 'edge.example.test', 'operator', 1, 2, 1, 'sealed', 0, 0, 2, 2)`, chainID); err != nil {
		t.Fatal(err)
	}
	response := serveSessionExport(t, &Extension{store: s}, chainID, sessionExportJSON, context.Background())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"exported_count":0`) ||
		!strings.Contains(response.Body.String(), `"events":[]`) {
		t.Fatalf("empty export = %d/%q", response.Code, response.Body.String())
	}
}

func TestSessionExportLogsOnlyBoundedMetadata(t *testing.T) {
	s, chainID := seededExportStore(t)
	var logs bytes.Buffer
	var activity string
	extension := &Extension{
		store: s, logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		exportLimits: sessionExportLimits{MaxRows: 10, MaxBytes: 1 << 20, PageSize: 2, Timeout: time.Second},
		currentUser:  func(*http.Request) string { return "export-operator" },
		logActivity:  func(_, _, details string) { activity = details },
	}
	response := serveSessionExport(t, extension, chainID, sessionExportJSON, context.Background())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	for _, output := range []string{logs.String(), activity} {
		for _, want := range []string{chainID, "json", "rows", "pages", "duration_ms", "success"} {
			if !strings.Contains(output, want) {
				t.Errorf("export audit metadata missing %q: %s", want, output)
			}
		}
		if !strings.Contains(output, "pages=2") && !strings.Contains(output, `"pages":2`) {
			t.Errorf("export audit metadata has the wrong page count: %s", output)
		}
		for _, forbidden := range []string{"payload-log-sentinel", "=formula-source", redactedValue} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("export log leaked event value %q: %s", forbidden, output)
			}
		}
	}
}

func seededExportStore(t *testing.T) (*store, string) {
	t.Helper()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	first := testEvent(7, "edge.example.test", "operator", "export-event-1", base)
	first.Source = "=formula-source"
	first.Message = "payload-log-sentinel"
	first.ConfigAttribute = "password=" + redactedValue
	first.SemanticHash = semanticHash(first)
	if _, err := s.applyPoll(context.Background(), pollBatch{EndedAt: base.Add(time.Minute), Events: []Event{first}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	second := testEvent(7, "edge.example.test", "operator", "export-event-2", base.Add(time.Minute))
	second.Message = "second"
	second.SemanticHash = semanticHash(second)
	third := testEvent(7, "edge.example.test", "operator", "export-event-3", base.Add(time.Minute))
	third.Message = "third"
	third.Action = "Delete"
	third.SemanticHash = semanticHash(third)
	if _, err := s.applyPoll(context.Background(), pollBatch{EndedAt: base.Add(2 * time.Minute), Events: []Event{second, third}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{EndedAt: base.Add(32 * time.Minute)}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	return s, chainIDForUser(t, s, "operator")
}

func serveSessionExport(t *testing.T, extension *Extension, chainID, format string, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	router.Get("/chain/{chainID}/export/{format}", extension.exportSession)
	request := httptest.NewRequest(http.MethodGet, "/chain/"+chainID+"/export/"+format, nil).WithContext(ctx)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
