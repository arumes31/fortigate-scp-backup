package fgtconftail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestDashboardChainPageProvidesCompletePaginatedTimeline(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	events := make([]Event, 0, dashboardEventPageSize+5)
	for index := 0; index < dashboardEventPageSize+5; index++ {
		event := testEvent(
			1,
			"fw-a",
			"alice",
			fmt.Sprintf("message-%03d", index),
			base.Add(time.Duration(index)*time.Second),
		)
		event.VDOM = fmt.Sprintf("vdom-%02d", index%3)
		if index == dashboardEventPageSize {
			event.Path = `<script>alert("timeline")</script>`
			event.SemanticHash = semanticHash(event)
		}
		events = append(events, event)
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(32 * time.Minute),
		Events:  events,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	chainID := chainIDForUser(t, s, "alice")
	if err := s.markDeliveryFailure(
		context.Background(),
		chainID,
		deliveryStateRetry,
		base.Add(45*time.Minute),
		errors.New("temporary <retry-error>"),
		base.Add(32*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	first, totalPages, err := s.dashboardChainPage(context.Background(), chainID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != dashboardEventPageSize || totalPages != 2 {
		t.Fatalf("first detail page = %d events / %d pages", len(first.Events), totalPages)
	}
	second, totalPages, err := s.dashboardChainPage(context.Background(), chainID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != 5 || totalPages != 2 {
		t.Fatalf("second detail page = %d events / %d pages", len(second.Events), totalPages)
	}
	if !first.Events[len(first.Events)-1].EventAt.Before(second.Events[0].EventAt) {
		t.Fatal("detail pages do not preserve the complete chronological order")
	}
	if len(first.VDOMs) != 3 || first.VDOMsOmitted != 0 {
		t.Fatalf("detail VDOMs = %v omitted=%d", first.VDOMs, first.VDOMsOmitted)
	}
	if _, _, err := s.dashboardChainPage(context.Background(), chainID, 3); !errors.Is(err, errDashboardPageRange) {
		t.Fatalf("out-of-range detail page error = %v", err)
	}

	tmpl, err := parseDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	extension := &Extension{
		cfg:         &config.Config{ExtFgtConfTail: true, FgtConfTailIdleSeconds: 1800},
		logger:      slog.New(slog.NewJSONHandler(&logs, nil)),
		store:       s,
		tmpl:        tmpl,
		currentUser: func(*http.Request) string { return "reviewer" },
	}
	router := chi.NewRouter()
	router.Get("/chain/{chainID}", extension.dashboardChain)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/chain/"+chainID+"?page=2", nil),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("detail status = %d, body = %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("detail page did not autoescape the stored timeline: %q", body)
	}
	if strings.Contains(body, "<retry-error>") || !strings.Contains(body, "&lt;retry-error&gt;") ||
		!strings.Contains(body, "Delivery attempts") {
		t.Fatalf("detail page did not safely render delivery retry state: %q", body)
	}
	if strings.Contains(body, `method="post"`) {
		t.Fatal("detail page contains a state-changing form")
	}
	for _, want := range []string{
		`class="ct-attribute-diff"`, "<del>before</del>", "<ins>after</ins>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page does not contain structured cfgattr diff %q", want)
		}
	}
	for _, want := range []string{
		`"msg":"conftail session queried"`,
		`"actor":"reviewer"`,
		`"chain_id":"` + chainID + `"`,
		`"page":2`,
		`"total_pages":2`,
		`"event_rows":5`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("ConfTail session log does not contain %q:\n%s", want, logs.String())
		}
	}

	if err := s.markAccepted(
		context.Background(),
		chainID,
		"hookwise-<request-id>",
		base.Add(46*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	accepted := httptest.NewRecorder()
	router.ServeHTTP(
		accepted,
		httptest.NewRequest(http.MethodGet, "/chain/"+chainID+"?page=2", nil),
	)
	acceptedBody := accepted.Body.String()
	if accepted.Code != http.StatusOK || strings.Contains(acceptedBody, "<request-id>") ||
		!strings.Contains(acceptedBody, "hookwise-&lt;request-id&gt;") ||
		!strings.Contains(acceptedBody, "2026-09-01 10:46:00 UTC") {
		t.Fatalf("detail page did not safely render accepted delivery state: %d/%q", accepted.Code, acceptedBody)
	}

	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/chain/not-a-uuid", nil))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid chain status = %d, want 400", invalid.Code)
	}
}

func TestDashboardChainErrorsDoNotRequireLogger(t *testing.T) {
	t.Run("query failure", func(t *testing.T) {
		s := newTestStore(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC))
		if err := s.db.Close(); err != nil {
			t.Fatal(err)
		}
		tmpl, err := parseDashboardTemplate()
		if err != nil {
			t.Fatal(err)
		}
		extension := &Extension{store: s, tmpl: tmpl}
		response := serveDashboardChain(
			t,
			extension,
			"11111111-2222-3333-4444-555555555555",
		)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", response.Code)
		}
	})

	t.Run("template failure", func(t *testing.T) {
		base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
		s := newTestStore(t, base)
		if _, err := s.applyPoll(context.Background(), pollBatch{
			EndedAt: base.Add(time.Minute),
			Events:  []Event{testEvent(1, "fw-a", "alice", "m-1", base.Add(time.Second))},
		}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
			t.Fatal(err)
		}
		extension := &Extension{
			cfg:   &config.Config{ExtFgtConfTail: true},
			store: s,
			tmpl:  template.New("root"),
		}
		response := serveDashboardChain(t, extension, chainIDForUser(t, s, "alice"))
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", response.Code)
		}
	})
}

func TestDashboardCoverageIsGatedAndCollapsedByDefault(t *testing.T) {
	tmpl, err := parseDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	page := dashboardPageData{
		Base:      conftailBaseData{ExtAdmVPNEnabled: true},
		Dashboard: dashboardData{TotalPages: 1},
		Filters:   dashboardFilterView{State: dashboardStateAll, Page: 1},
		Coverage: []sourceCoverage{{
			FirewallID:   1,
			FirewallName: "fw-a.example.com",
			Aliases:      []string{"fw-a"},
		}},
	}
	var output bytes.Buffer
	if err := tmpl.ExecuteTemplate(&output, "index.html", page); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	if !strings.Contains(body, `<details class="card ct-coverage">`) {
		t.Fatalf("coverage is not rendered as a disclosure: %q", body)
	}
	if strings.Contains(body, `<details class="card ct-coverage" open`) {
		t.Fatal("coverage disclosure is open by default")
	}

	page.Base.ExtAdmVPNEnabled = false
	output.Reset()
	if err := tmpl.ExecuteTemplate(&output, "index.html", page); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "Graylog source coverage") {
		t.Fatal("coverage is shown while ADM VPN Config is disabled")
	}
}

func serveDashboardChain(t *testing.T, extension *Extension, chainID string) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	router.Get("/chain/{chainID}", extension.dashboardChain)
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/chain/"+chainID, nil),
	)
	return response
}

func TestDashboardVDOMsReportsAllDistinctOmittedVDOMs(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	events := make([]Event, 0, dashboardVDOMLimit+4)
	for index := 0; index < dashboardVDOMLimit+3; index++ {
		event := testEvent(
			1,
			"fw-a",
			"alice",
			fmt.Sprintf("message-%02d", index),
			base.Add(time.Duration(index)*time.Second),
		)
		event.VDOM = fmt.Sprintf("vdom-%02d", index)
		event.SemanticHash = semanticHash(event)
		events = append(events, event)
	}
	duplicate := testEvent(
		1,
		"fw-a",
		"alice",
		"duplicate-vdom",
		base.Add(time.Duration(dashboardVDOMLimit+3)*time.Second),
	)
	duplicate.VDOM = "vdom-00"
	duplicate.SemanticHash = semanticHash(duplicate)
	events = append(events, duplicate)

	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(time.Minute),
		Events:  events,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	vdoms, omitted, err := s.dashboardVDOMs(context.Background(), chainIDForUser(t, s, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(vdoms) != dashboardVDOMLimit {
		t.Fatalf("visible VDOM count = %d, want %d", len(vdoms), dashboardVDOMLimit)
	}
	if omitted != 3 {
		t.Fatalf("omitted distinct VDOM count = %d, want 3", omitted)
	}
}

func TestDashboardShowsPollLifecycleAndNextRun(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	started := base.Add(time.Minute)
	failed := started.Add(2 * time.Minute)
	if err := s.markPollStarted(context.Background(), started); err != nil {
		t.Fatal(err)
	}
	if err := s.markPollFailed(context.Background(), started, failed, errors.New("Graylog unavailable")); err != nil {
		t.Fatal(err)
	}
	tmpl, err := parseDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	extension := &Extension{
		cfg:    &config.Config{ExtFgtConfTail: true, FgtConfTailPollSeconds: 900},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  s,
		tmpl:   tmpl,
	}
	response := httptest.NewRecorder()
	extension.dashboard(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, body = %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		"Last poll start",
		"2026-09-01 10:01:00 UTC",
		"failure: 2026-09-01 10:03:00 UTC",
		"Next poll run",
		"2026-09-01 10:16:00 UTC",
		`id="ct-next-poll-countdown"`,
		`src="/fgt-conftail/static/conftail.js"`,
		"Firewall name or ID",
		"Graylog source contains",
		"Device name contains",
		"Serial contains",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard body does not contain %q", want)
		}
	}
}

func TestDashboardNextPollRunUsesFirstDelayBeforeInitialPoll(t *testing.T) {
	activation := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	got := dashboardNextPollRun(PollState{ActivationAt: activation}, 15*time.Minute)
	if want := activation.Add(conftailPollFirstDelay); !got.Equal(want) {
		t.Fatalf("next initial poll = %s, want %s", got, want)
	}
}

func TestDashboardPollHealthIncludesActionableRemediation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		lastError  string
		wantAction string
	}{
		{name: "authentication", lastError: "graylog returned HTTP 401", wantAction: "Verify the Graylog token"},
		{name: "schema", lastError: "decode graylog response: schema missing requested field", wantAction: "Check the Graylog field mapping"},
		{name: "catalog", lastError: "conftail source catalog has no queryable aliases", wantAction: "Enable Graylog for at least one ADM VPN firewall"},
		{name: "fallback", lastError: "graylog network request failed", wantAction: "Check Graylog connectivity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := dashboardPollHealth(PollState{
				LastFailureAt: now,
				LastError:     test.lastError,
			}, now, 15*time.Minute)
			if health.State != "failed" || !strings.Contains(health.Action, test.wantAction) {
				t.Fatalf("health = %+v, want action containing %q", health, test.wantAction)
			}
		})
	}
}

func TestDashboardDeliveryHealthIsIndependentFromCollector(t *testing.T) {
	t.Parallel()

	health := dashboardDeliveryHealth(dashboardCounts{Failed: 2, Retry: 3})
	if health.State != "failed" || !strings.Contains(health.Detail, "2 failed") ||
		!strings.Contains(health.Action, "Hookwise") {
		t.Fatalf("delivery health = %+v", health)
	}
}

func TestParseConfigAttributeDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		value      string
		wantName   string
		wantBefore string
		wantAfter  string
		wantOK     bool
	}{
		{name: "change", value: "type[fortimanager->normal]", wantName: "type", wantBefore: "fortimanager", wantAfter: "normal", wantOK: true},
		{name: "empty old value", value: "comments[->managed]", wantName: "comments", wantAfter: "managed", wantOK: true},
		{name: "no diff", value: "comments[managed]"},
		{name: "free text", value: "Attribute configured"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diff, ok := parseConfigAttributeDiff(test.value)
			if ok != test.wantOK || diff.Name != test.wantName ||
				diff.Before != test.wantBefore || diff.After != test.wantAfter {
				t.Fatalf("parseConfigAttributeDiff(%q) = (%+v, %t)", test.value, diff, ok)
			}
		})
	}
}

func TestParseDashboardFiltersAcceptsBoundedReadFilters(t *testing.T) {
	values := url.Values{
		"firewall": {"7"},
		"user":     {" team%_ops "},
		"source":   {" branch-east "},
		"device":   {" FGT-EDGE "},
		"serial":   {" FG100F123 "},
		"state":    {deliveryStateRetry},
		"from":     {"2026-09-01T10:15"},
		"to":       {"2026-09-02T11:45Z"},
		"page":     {"3"},
	}

	got, err := parseDashboardFilters(values)
	if err != nil {
		t.Fatal(err)
	}
	if got.FirewallID != 7 || got.User != "team%_ops" || got.Source != "branch-east" ||
		got.Device != "FGT-EDGE" || got.Serial != "FG100F123" ||
		got.State != deliveryStateRetry || got.Page != 3 {
		t.Fatalf("filters = %+v", got)
	}
	if want := time.Date(2026, 9, 1, 10, 15, 0, 0, time.UTC); !got.From.Equal(want) {
		t.Fatalf("from = %s, want %s", got.From, want)
	}
	if want := time.Date(2026, 9, 2, 11, 45, 0, 0, time.UTC); !got.To.Equal(want) {
		t.Fatalf("to = %s, want %s", got.To, want)
	}
}

func TestParseDashboardFiltersRejectsInvalidOrUnboundedValues(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
	}{
		{name: "unknown state", values: url.Values{"state": {"drop table chains"}}},
		{name: "negative firewall", values: url.Values{"firewall": {"-1"}}},
		{name: "page zero", values: url.Values{"page": {"0"}}},
		{name: "page too large", values: url.Values{"page": {"10001"}}},
		{name: "bad time", values: url.Values{"from": {"yesterday"}}},
		{
			name: "inverted range",
			values: url.Values{
				"from": {"2026-09-02T10:00Z"},
				"to":   {"2026-09-01T10:00Z"},
			},
		},
		{name: "user too long", values: url.Values{"user": {strings.Repeat("x", maxIdentityRunes+1)}}},
		{name: "source too long", values: url.Values{"source": {strings.Repeat("x", maxIdentityRunes+1)}}},
		{name: "device control character", values: url.Values{"device": {"fw\nname"}}},
		{name: "serial control character", values: url.Values{"serial": {"serial\x00value"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDashboardFilters(test.values); err == nil {
				t.Fatal("invalid filters unexpectedly accepted")
			}
		})
	}
}

func TestQueryDashboardPaginatesAndTreatsUserWildcardsLiterally(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)

	events := make([]Event, 0, dashboardPageSize+2)
	for i := 0; i < dashboardPageSize+2; i++ {
		user := "user-" + string(rune('a'+i))
		switch i {
		case 0:
			user = "team%_ops"
		case 1:
			user = "teamZZops"
		}
		event := testEvent(1+(i%2), "fw", user, user, base)
		if i == 0 {
			event.Source = "branch-east"
			event.DeviceName = "FGT-EDGE"
			event.DeviceID = "FG100F123"
			event.CorrelationHash = attributionCorrelationHash(event)
			event.SemanticHash = semanticHash(event)
		}
		events = append(events, event)
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(31 * time.Minute),
		Events:  events,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	acceptedID := chainIDForUser(t, s, "team%_ops")
	if err := s.markAccepted(context.Background(), acceptedID, "request-1", base.Add(32*time.Minute)); err != nil {
		t.Fatal(err)
	}
	active := testEvent(2, "fw-b", "active-admin", "active", base.Add(39*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(40 * time.Minute),
		Events:  []Event{active},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	data, err := s.queryDashboard(context.Background(), dashboardFilters{State: dashboardStateAll, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if data.Counts.Active != 1 || data.Counts.Sealed != dashboardPageSize+2 ||
		data.Counts.Accepted != 1 || data.Counts.Pending != dashboardPageSize+1 {
		t.Fatalf("counts = %+v", data.Counts)
	}
	if len(data.Active) != 1 || len(data.History) != dashboardPageSize ||
		data.HistoryTotal != dashboardPageSize+2 || data.TotalPages != 2 {
		t.Fatalf("dashboard = active:%d history:%d total:%d pages:%d",
			len(data.Active), len(data.History), data.HistoryTotal, data.TotalPages)
	}

	secondPage, err := s.queryDashboard(context.Background(), dashboardFilters{
		State: dashboardStateAll,
		Page:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.History) != 2 {
		t.Fatalf("second page history = %d, want 2", len(secondPage.History))
	}

	literal, err := s.queryDashboard(context.Background(), dashboardFilters{
		User:  "%_",
		State: dashboardStateAll,
		Page:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if literal.HistoryTotal != 1 || len(literal.History) != 1 ||
		literal.History[0].User != "team%_ops" {
		t.Fatalf("literal wildcard filter returned %+v", literal.History)
	}

	accepted, err := s.queryDashboard(context.Background(), dashboardFilters{
		State: deliveryStateAccepted,
		Page:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted.Active) != 0 || accepted.HistoryTotal != 1 ||
		accepted.History[0].DeliveryState != deliveryStateAccepted {
		t.Fatalf("accepted filter returned %+v", accepted)
	}

	eventFiltered, err := s.queryDashboard(context.Background(), dashboardFilters{
		Source: "branch-east",
		Device: "FGT-EDGE",
		Serial: "FG100F123",
		State:  dashboardStateAll,
		Page:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if eventFiltered.HistoryTotal != 1 || eventFiltered.History[0].User != "team%_ops" {
		t.Fatalf("event filters returned %+v", eventFiltered.History)
	}
}

func TestQueryDashboardKeepsEventDetailsOffOverview(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	const eventCount = 30
	events := make([]Event, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		event := testEvent(1, "fw-a", "alice", "message-"+string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute))
		event.ConfigAttribute = "attribute-" + string(rune('a'+i))
		event.SemanticHash = semanticHash(event)
		events = append(events, event)
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(90 * time.Minute),
		Events:  events,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	data, err := s.queryDashboard(context.Background(), dashboardFilters{
		State: chainStateSealed,
		Page:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data.History) != 1 {
		t.Fatalf("history = %d, want 1", len(data.History))
	}
	chain := data.History[0]
	if chain.EventCount != eventCount || len(chain.Events) != 0 {
		t.Fatalf("overview chain = %d event count / %d loaded details", chain.EventCount, len(chain.Events))
	}
}

func TestDashboardHandlerRendersEscapedReadOnlyPage(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	event := testEvent(1, "fw-a", `<script>alert("fw")</script>`, "message", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	tmpl, err := parseDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	extension := &Extension{
		cfg:         &config.Config{ExtFgtConfTail: true},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:       s,
		tmpl:        tmpl,
		currentUser: func(*http.Request) string { return `<img src=x onerror=alert(1)>` },
	}

	request := httptest.NewRequest(http.MethodGet, "/fgt-conftail/?user=script", nil)
	response := httptest.NewRecorder()
	extension.dashboard(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	body := response.Body.String()
	for _, unsafe := range []string{"<script>", "<img src=x", `method="post"`, "Accept new key", "Retry delivery"} {
		if strings.Contains(body, unsafe) {
			t.Fatalf("read-only page contains unsafe or mutating content %q", unsafe)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img src=x"} {
		if !strings.Contains(body, escaped) {
			t.Fatalf("escaped content %q missing from response", escaped)
		}
	}

	post := httptest.NewRecorder()
	extension.dashboard(post, httptest.NewRequest(http.MethodPost, "/fgt-conftail/", bytes.NewReader(nil)))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", post.Code)
	}
}

func TestDashboardHandlerLogsSuccessfulQueries(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	tmpl, err := parseDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	extension := &Extension{
		cfg:         &config.Config{ExtFgtConfTail: true},
		logger:      slog.New(slog.NewJSONHandler(&output, nil)),
		store:       s,
		tmpl:        tmpl,
		currentUser: func(*http.Request) string { return "operator" },
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"/?firewall=7&user=alice&source=branch&device=FGT&serial=FG100&state=all&from=2026-09-01T09%3A00Z&to=2026-09-01T10%3A00Z",
		nil,
	)
	response := httptest.NewRecorder()
	extension.dashboard(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	logs := output.String()
	for _, want := range []string{
		`"msg":"conftail dashboard queried"`,
		`"actor":"operator"`,
		`"firewall_id":7`,
		`"user_filter_set":true`,
		`"source_filter_set":true`,
		`"device_filter_set":true`,
		`"serial_filter_set":true`,
		`"state":"all"`,
		`"from":"2026-09-01T09:00:00Z"`,
		`"to":"2026-09-01T10:00:00Z"`,
		`"page":1`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("ConfTail dashboard log does not contain %q:\n%s", want, logs)
		}
	}
}

func TestDashboardHandlerRejectsInvalidFilters(t *testing.T) {
	s := newTestStore(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC))
	tmpl, err := parseDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	extension := &Extension{
		cfg:    &config.Config{ExtFgtConfTail: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  s,
		tmpl:   tmpl,
	}
	response := httptest.NewRecorder()
	extension.dashboard(response, httptest.NewRequest(http.MethodGet, "/?state=not-valid", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}
