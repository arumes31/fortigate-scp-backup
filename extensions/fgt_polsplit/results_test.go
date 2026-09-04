package fgt_polsplit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func resultFixture() analysisResult {
	strategy := Strategy{
		Key: "per_service", Label: "One policy per service", Recommended: true,
		Policies:   []RecPolicy{{ID: 100, Name: "PS42_HTTPS"}},
		NewObjects: []NewObject{{Kind: "address", Name: "PS42_DST", Value: "203.0.113.10/32"}},
		Config:     "config firewall policy\n    edit 100\nend\n",
	}
	return analysisResult{
		Firewall:   FirewallRef{ID: 7, FQDN: "edge.example.test"},
		Policy:     &OrigPolicy{ID: 42, Name: "Synthetic open policy", VDOM: "root"},
		BackupTime: "2026-09-02 10:30", TotalMessages: 24, TupleCount: 1,
		SrcCount: 1, DstCount: 1, ServiceCount: 1,
		Warnings: []string{"Review one unresolved object."},
		Traffic: trafficResultPanel{
			Tuples: []TrafficTuple{{SrcIP: "10.0.0.10", DstIP: "203.0.113.10", Proto: "tcp", Port: 443, Service: "=unsafe", Hits: 24}},
		},
		Strategies: []Strategy{strategy},
	}
}

func resultRouter(e *Extension) http.Handler {
	router := chi.NewRouter()
	router.Get("/results/{resultID}/panels/{panelKey}", e.resultPanel)
	router.Get("/results/{resultID}/export/{exportType}", e.exportResult)
	return router
}

func TestResultPanelsAreOrderedBoundedAndOwnerScoped(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 30, 0, 0, time.UTC)
	e := &Extension{
		logger:      slog.New(slog.DiscardHandler),
		currentUser: func(r *http.Request) string { return r.Header.Get("X-Test-User") },
		resultNow:   func() time.Time { return now },
		results:     map[string]*storedAnalysisResult{},
	}
	resultID, response, err := e.storeResult("alice", resultFixture())
	if err != nil {
		t.Fatal(err)
	}
	if response.ResultID != resultID || response.WarningCount != 1 || response.UnresolvedCount != 1 || response.ArtifactCount != 1 {
		t.Fatalf("summary = %+v", response)
	}
	summaryJSON, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(summaryJSON), "config firewall") || strings.Contains(string(summaryJSON), "10.0.0.10") {
		t.Fatalf("initial summary contains a lazy payload: %s", summaryJSON)
	}
	wantOrder := []string{"traffic", "per_service"}
	for index, want := range wantOrder {
		if response.Panels[index].Key != want {
			t.Fatalf("panel order = %+v", response.Panels)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/results/"+resultID+"/panels/per_service", nil)
	request.Header.Set("X-Test-User", "alice")
	recorder := httptest.NewRecorder()
	resultRouter(e).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "PS42_HTTPS") {
		t.Fatalf("owner panel status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/results/"+resultID+"/panels/per_service", nil)
	request.Header.Set("X-Test-User", "bob")
	recorder = httptest.NewRecorder()
	resultRouter(e).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("cross-user status = %d, want 404", recorder.Code)
	}

	huge := resultFixture()
	huge.Strategies[0].Config = strings.Repeat("x", maxStoredResultBytes+1)
	if _, _, err := e.storeResult("alice", huge); err == nil {
		t.Fatal("oversized result must be rejected")
	}
}

func TestResultPanelExpiresAndReturnsJSONError(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 30, 0, 0, time.UTC)
	e := &Extension{
		logger:      slog.New(slog.DiscardHandler),
		currentUser: func(*http.Request) string { return "alice" },
		resultNow:   func() time.Time { return now },
		results:     map[string]*storedAnalysisResult{},
	}
	resultID, _, err := e.storeResult("alice", resultFixture())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(resultTTL + time.Second)
	recorder := httptest.NewRecorder()
	resultRouter(e).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/results/"+resultID+"/panels/traffic", nil))
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expired status=%d content-type=%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}

func TestExportResultTypesUseSafeMetadata(t *testing.T) {
	var activity []string
	e := &Extension{
		logger:      slog.New(slog.DiscardHandler),
		currentUser: func(*http.Request) string { return "alice" },
		logActivity: func(_, action, details string) { activity = append(activity, action+" "+details) },
		results:     map[string]*storedAnalysisResult{},
	}
	resultID, _, err := e.storeResult("alice", resultFixture())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		path        string
		contentType string
		filename    string
		body        string
	}{
		{name: "summary", path: "/results/" + resultID + "/export/summary", contentType: "application/json", filename: `filename="polsplit-policy-42-summary.json"`, body: `"tuple_count": 1`},
		{name: "traffic", path: "/results/" + resultID + "/export/traffic", contentType: "text/csv", filename: `filename="polsplit-policy-42-traffic.csv"`, body: "'=unsafe"},
		{name: "config", path: "/results/" + resultID + "/export/config?strategy=per_service", contentType: "text/plain", filename: `filename="polsplit-policy-42-per_service.conf"`, body: "config firewall policy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			resultRouter(e).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
			if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), test.contentType) {
				t.Fatalf("status=%d content-type=%q body=%q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
			}
			if !strings.Contains(recorder.Header().Get("Content-Disposition"), test.filename) || !strings.Contains(recorder.Body.String(), test.body) {
				t.Fatalf("disposition=%q body=%q", recorder.Header().Get("Content-Disposition"), recorder.Body.String())
			}
		})
	}
	logs, err := json.Marshal(activity)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logs), "config firewall") || !strings.Contains(string(logs), "bytes=") {
		t.Fatalf("activity log must contain metadata, not config: %s", logs)
	}
}
