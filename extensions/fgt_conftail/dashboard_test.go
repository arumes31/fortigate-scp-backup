package fgtconftail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

func TestDashboardPagesUseIndependentSharedShellRenderers(t *testing.T) {
	t.Parallel()

	indexPage, chainPage, err := parseDashboardPages()
	if err != nil {
		t.Fatalf("parseDashboardPages() error = %v", err)
	}
	base := webui.BaseData{
		Title: "Configuration Change Tail", Username: "reviewer", Lang: "de", Active: "conftail",
		ReturnTo: "/fgt-conftail/", Shell: webui.ShellText("de"),
		Navigation: webui.Navigation(webui.NavigationOptions{Lang: "de", Active: "conftail", ConfTail: true}),
	}
	tests := []struct {
		name     string
		renderer *webui.Renderer
		data     any
		want     string
	}{
		{
			name: "index", renderer: indexPage,
			data: dashboardPageData{
				Base: base, Dashboard: dashboardData{TotalPages: 1},
				Filters: dashboardFilterView{State: dashboardStateAll, Page: 1},
			},
			want: "Configuration Change Tail",
		},
		{
			name: "chain", renderer: chainPage,
			data: dashboardChainPageData{
				Base: base, Chain: dashboardChain{ID: "fixture-chain", FirewallName: "edge.example.test"},
				Page: 1, TotalPages: 1,
			},
			want: "Complete Redacted Timeline",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := test.renderer.Render(&output, test.data); err != nil {
				t.Fatalf("Render() error = %v", err)
			}
			body := output.String()
			for _, want := range []string{
				`<html lang="de">`, `class="app-rail"`, `aria-current="page"`,
				`class="page conftail-page"`, test.want,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("rendered %s page missing %q", test.name, want)
				}
			}
			for _, asset := range []string{"/fgt-conftail/static/conftail.css", "/fgt-conftail/static/conftail.js"} {
				if count := strings.Count(body, asset); count != 1 {
					t.Errorf("%s asset %q rendered %d times, want exactly once", test.name, asset, count)
				}
			}
			for _, unwanted := range []string{`class="topbar"`, `class="sysfooter"`, "FORTISAFE_SYS"} {
				if strings.Contains(body, unwanted) {
					t.Errorf("standalone ConfTail shell remains on %s page: %q", test.name, unwanted)
				}
			}
		})
	}
}

func testDashboardRenderers(t *testing.T) (*webui.Renderer, *webui.Renderer) {
	t.Helper()
	indexPage, chainPage, err := parseDashboardPages()
	if err != nil {
		t.Fatal(err)
	}
	return indexPage, chainPage
}

func testDashboardPageBase(username string) func(*http.Request, string, string) webui.BaseData {
	return func(r *http.Request, title, active string) webui.BaseData {
		return webui.BaseData{
			Title: title, Username: username, Lang: "en", Active: active, ReturnTo: r.URL.RequestURI(),
			Shell: webui.ShellText("en"),
			Navigation: webui.Navigation(webui.NavigationOptions{
				Lang: "en", Active: active, AdmVPN: true, ConfGen: true, PolSplit: true,
				ConfConv: true, ConfTail: true,
			}),
		}
	}
}

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
	if _, _, err := s.createGlobalIgnoreRule(
		context.Background(),
		storedEventID(t, s, "message-000"),
		ignoreRuleKindAttribute,
		"reviewer",
		base.Add(40*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
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

	_, chainPage := testDashboardRenderers(t)
	var logs bytes.Buffer
	extension := &Extension{
		cfg:         &config.Config{ExtFgtConfTail: true, FgtConfTailIdleSeconds: 1800},
		logger:      slog.New(slog.NewJSONHandler(&logs, nil)),
		store:       s,
		chainPage:   chainPage,
		currentUser: func(*http.Request) string { return "reviewer" },
		pageBase:    testDashboardPageBase("reviewer"),
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
	if strings.Count(body, `method="post"`) != 3 ||
		!strings.Contains(body, `class="language-form"`) || !strings.Contains(body, `class="logout-form"`) ||
		!strings.Contains(body, `action="/fgt-conftail/ignore-rules"`) {
		t.Fatal("detail page does not contain exactly the shared forms and confirmed global-ignore action")
	}
	for _, want := range []string{
		`class="ct-attribute-diff"`, "<del>before</del>", "<ins>after</ins>",
		`global attribute ignore active`, `data-ct-ignore-open`, `id="ct-ignore-dialog"`, `Confirm global ignore`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page does not contain structured cfgattr diff %q", want)
		}
	}
	for _, want := range []string{
		`"msg":"conftail session queried"`,
		`"code":"CT-UI-004"`,
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
		_, chainPage := testDashboardRenderers(t)
		extension := &Extension{store: s, chainPage: chainPage, pageBase: testDashboardPageBase("")}
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
		brokenPage, err := webui.ParsePage(fstest.MapFS{
			"broken.html": &fstest.MapFile{Data: []byte(`{{define "content"}}{{.Missing}}{{end}}`)},
		}, "broken.html", nil)
		if err != nil {
			t.Fatal(err)
		}
		extension := &Extension{
			cfg:       &config.Config{ExtFgtConfTail: true},
			store:     s,
			chainPage: brokenPage,
			pageBase:  testDashboardPageBase(""),
		}
		response := serveDashboardChain(t, extension, chainIDForUser(t, s, "alice"))
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", response.Code)
		}
	})
}

func TestDashboardCoverageIsGatedAndCollapsedByDefault(t *testing.T) {
	indexPage, _ := testDashboardRenderers(t)
	page := dashboardPageData{
		Base:            testDashboardPageBase("reviewer")(httptest.NewRequest(http.MethodGet, "/fgt-conftail/", nil), "Configuration Change Tail", "conftail"),
		CoverageEnabled: true,
		Dashboard:       dashboardData{TotalPages: 1},
		Filters:         dashboardFilterView{State: dashboardStateAll, Page: 1},
		Coverage: []sourceCoverage{{
			FirewallID:   1,
			FirewallName: "fw-a.example.com",
			Aliases:      []string{"fw-a"},
		}},
	}
	var output bytes.Buffer
	if err := indexPage.Render(&output, page); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	if !strings.Contains(body, `<details class="card ct-coverage">`) {
		t.Fatalf("coverage is not rendered as a disclosure: %q", body)
	}
	if strings.Contains(body, `<details class="card ct-coverage" open`) {
		t.Fatal("coverage disclosure is open by default")
	}
	for _, want := range []string{
		"1 Graylog-enabled firewall(s)",
		"Coverage includes only firewalls with Graylog enabled in ADM VPN Config.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("coverage summary does not contain %q", want)
		}
	}

	page.CoverageEnabled = false
	output.Reset()
	if err := indexPage.Render(&output, page); err != nil {
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
	indexPage, _ := testDashboardRenderers(t)
	extension := &Extension{
		cfg:       &config.Config{ExtFgtConfTail: true, FgtConfTailPollSeconds: 900},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:     s,
		indexPage: indexPage,
		pageBase:  testDashboardPageBase(""),
	}
	response := httptest.NewRecorder()
	extension.dashboard(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, body = %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		"Graylog collector",
		"Session pipeline",
		"Hookwise delivery",
		"Evidence:",
		"Last check:",
		"2026-09-01 10:03:00 UTC",
		"CT-GL-001",
		"Next collector check",
		"2026-09-01 10:02:00 UTC",
		`id="ct-next-poll-countdown"`,
		`src="/fgt-conftail/static/conftail.js"`,
		"Firewall ID",
		`method="post" action="/fgt-conftail/"`,
		"Advanced filters",
		"Search redacted event text",
		"Graylog source contains",
		"Device name contains",
		"Serial contains",
		"Action contains",
		"Config transaction ID",
		"FortiGate log ID",
		`data-ct-time-toggle`,
		`<time data-ct-time datetime="2026-09-01T10:03:00Z">2026-09-01 10:03:00 UTC</time>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard body does not contain %q", want)
		}
	}
	if got := strings.Count(body, `class="card ct-metric `); got != 3 {
		t.Fatalf("health card count = %d, want 3", got)
	}
}

func TestDashboardShowsRunningPollAndStatusRefreshContract(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	if err := s.markPollStarted(context.Background(), base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	indexPage, _ := testDashboardRenderers(t)
	extension := &Extension{
		cfg:       &config.Config{ExtFgtConfTail: true},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:     s,
		indexPage: indexPage,
		pageBase:  testDashboardPageBase(""),
	}
	response := httptest.NewRecorder()
	extension.dashboard(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, body = %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		"Collector polling",
		`data-ct-poll-status`,
		`data-poll-running="true"`,
		`data-poll-signature=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("running dashboard does not contain %q", want)
		}
	}
}

func TestDashboardStatusReportsPollTransitions(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	started := base.Add(time.Minute)
	if err := s.markPollStarted(context.Background(), started); err != nil {
		t.Fatal(err)
	}
	extension := &Extension{store: s}

	readStatus := func() dashboardStatusResponse {
		t.Helper()
		response := httptest.NewRecorder()
		extension.dashboardStatus(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status endpoint = %d, body = %q", response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("cache control = %q, want no-store", response.Header().Get("Cache-Control"))
		}
		var status dashboardStatusResponse
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}

	running := readStatus()
	if !running.Running || running.Signature == "" {
		t.Fatalf("running status = %+v", running)
	}
	if err := s.markPollFailed(context.Background(), started, started.Add(time.Second), errors.New("temporary")); err != nil {
		t.Fatal(err)
	}
	completed := readStatus()
	if completed.Running || completed.Signature == running.Signature {
		t.Fatalf("completed status = %+v, running status = %+v", completed, running)
	}

	post := httptest.NewRecorder()
	extension.dashboardStatus(post, httptest.NewRequest(http.MethodPost, "/status", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", post.Code)
	}
}

func TestDashboardPollRunningTracksUnfinishedCycle(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		state PollState
		want  bool
	}{
		{name: "never started"},
		{name: "started", state: PollState{LastStartedAt: base}, want: true},
		{name: "failed", state: PollState{LastStartedAt: base, LastFailureAt: base.Add(time.Second)}},
		{name: "succeeded", state: PollState{LastStartedAt: base, LastSuccessAt: base.Add(time.Second)}},
		{name: "new cycle after success", state: PollState{LastStartedAt: base.Add(time.Minute), LastSuccessAt: base}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dashboardPollRunning(test.state); got != test.want {
				t.Fatalf("dashboardPollRunning(%+v) = %t, want %t", test.state, got, test.want)
			}
		})
	}
}

func TestDashboardScriptPollsStatusAndTogglesBrowserTime(t *testing.T) {
	t.Parallel()
	script, err := dashboardFS.ReadFile("static/conftail.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`fetch("/fgt-conftail/status"`,
		"2000",
		"30000",
		`root.querySelectorAll("[data-ct-time]")`,
		"Intl.DateTimeFormat",
		"fortisafe.conftail.timezone.v1",
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("ConfTail script does not contain %q", want)
		}
	}
}

func TestDashboardStylesKeepTimeToggleClearOfIntro(t *testing.T) {
	t.Parallel()
	styles, err := dashboardFS.ReadFile("static/conftail.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(styles), ".ct-page-heading + .ct-intro") {
		t.Fatal("ConfTail styles do not neutralize the intro's negative margin after the time controls")
	}
}

func TestDashboardRendersLocalColumnControlsAndProgressiveRows(t *testing.T) {
	t.Parallel()
	indexPage, _ := testDashboardRenderers(t)
	page := dashboardPageData{
		Dashboard: dashboardData{
			Active:     []dashboardChain{{ID: "chain-1", FirewallID: 1, FirewallName: "fw-a"}},
			History:    []dashboardChain{{ID: "chain-2", FirewallID: 2, FirewallName: "fw-b"}},
			TotalPages: 1,
		},
		Filters: dashboardFilterView{State: dashboardStateAll, Page: 1},
	}
	var output bytes.Buffer
	if err := indexPage.Render(&output, page); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	for _, want := range []string{
		`data-ct-column-toggle="active:administrator"`,
		`data-ct-column-toggle="history:delivery"`,
		`data-ct-table="active"`,
		`data-ct-table="history"`,
		`class="ct-virtual-row"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard does not contain %q", want)
		}
	}
}

func TestDashboardRendersGlobalIgnoreManagementSafely(t *testing.T) {
	t.Parallel()
	indexPage, _ := testDashboardRenderers(t)
	page := dashboardPageData{
		Dashboard:    dashboardData{TotalPages: 1},
		Filters:      dashboardFilterView{State: dashboardStateAll, Page: 1},
		IgnoreNotice: "Global ignore rule created.",
		IgnoreRules: []globalIgnoreRule{{
			ID:              17,
			Kind:            ignoreRuleKindAttribute,
			ConfigAttribute: `name[before-><script>alert("unsafe")</script>]`,
			Enabled:         true,
			CreatedBy:       `operator<script>`,
			CreatedAt:       time.Date(2026, 9, 4, 9, 30, 0, 0, time.UTC),
		}},
	}
	var output bytes.Buffer
	if err := indexPage.Render(&output, page); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	for _, want := range []string{
		`id="ct-global-ignores" open`,
		`name[before-&gt;&lt;script&gt;alert(&#34;unsafe&#34;)&lt;/script&gt;]`,
		`operator&lt;script&gt;`,
		`action="/fgt-conftail/ignore-rules/17/toggle"`,
		`action="/fgt-conftail/ignore-rules/17/delete"`,
		`data-ct-ignore-delete`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("global ignore management does not contain %q", want)
		}
	}
	if strings.Contains(body, `<script>alert("unsafe")</script>`) {
		t.Fatal("global ignore management rendered an unescaped match value")
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
			if health.State != "failed" || health.Code != codeGraylogPollFailed || !strings.Contains(health.Action, test.wantAction) {
				t.Fatalf("health = %+v, want action containing %q", health, test.wantAction)
			}
		})
	}
}

func TestDashboardDeliveryHealthIsIndependentFromCollector(t *testing.T) {
	t.Parallel()

	health := dashboardDeliveryHealth(dashboardCounts{Failed: 2, Retry: 3}, time.Now().UTC())
	if health.State != "failed" || health.Code != codeHookwiseDeliveryFailed || !strings.Contains(health.Evidence, "2 failed") ||
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
		"firewall":    {"7"},
		"q":           {" urgent vpn "},
		"user":        {" team%_ops "},
		"source":      {" branch-east "},
		"device":      {" FGT-EDGE "},
		"serial":      {" FG100F123 "},
		"action":      {" Edit "},
		"transaction": {" 82378752 "},
		"log_id":      {" 0100044546 "},
		"state":       {deliveryStateRetry},
		"from":        {"2026-09-01T10:15"},
		"to":          {"2026-09-02T11:45Z"},
		"page":        {"3"},
	}

	got, err := parseDashboardFilters(values)
	if err != nil {
		t.Fatal(err)
	}
	if got.FirewallID != 7 || got.Search != "urgent vpn" || got.User != "team%_ops" || got.Source != "branch-east" ||
		got.Device != "FGT-EDGE" || got.Serial != "FG100F123" ||
		got.Action != "Edit" || got.TransactionID != "82378752" || got.LogID != "0100044546" ||
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
		{name: "search too long", values: url.Values{"q": {strings.Repeat("x", maxSearchRunes+1)}}},
		{name: "too many search terms", values: url.Values{"q": {"1 2 3 4 5 6 7 8 9 10 11"}}},
		{name: "search control character", values: url.Values{"q": {"urgent\nchange"}}},
		{name: "source too long", values: url.Values{"source": {strings.Repeat("x", maxIdentityRunes+1)}}},
		{name: "device control character", values: url.Values{"device": {"fw\nname"}}},
		{name: "serial control character", values: url.Values{"serial": {"serial\x00value"}}},
		{name: "action control character", values: url.Values{"action": {"Edit\nDelete"}}},
		{name: "transaction too long", values: url.Values{"transaction": {strings.Repeat("x", maxIdentityRunes+1)}}},
		{name: "log id control character", values: url.Values{"log_id": {"0100044546\x00"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDashboardFilters(test.values); err == nil {
				t.Fatal("invalid filters unexpectedly accepted")
			}
		})
	}
}

func TestQueryDashboardFullTextSearchMatchesAllLiteralTerms(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	urgent := testEvent(1, "fw-east", "alice", "graylog-search-1", base.Add(time.Minute))
	urgent.Message = `urgent vpn "phase2" change`
	urgent.SemanticHash = semanticHash(urgent)
	other := testEvent(2, "fw-west", "bob", "graylog-search-2", base.Add(2*time.Minute))
	other.Message = "urgent routing change"
	other.SemanticHash = semanticHash(other)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(time.Hour),
		Events:  []Event{urgent, other},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	result, err := s.queryDashboard(context.Background(), dashboardFilters{
		Search: `urgent vpn "phase2"`,
		State:  dashboardStateAll,
		Page:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.HistoryTotal != 1 || len(result.History) != 1 || result.History[0].FirewallID != 1 {
		t.Fatalf("full-text result = %+v, want only fw-east", result.History)
	}
}

func TestDashboardRequestAllowsOnlyNonSensitiveGETState(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(
		http.MethodGet,
		"/fgt-conftail/?firewall=7&state=retry&from=2026-09-01T09%3A00&page=3",
		nil,
	)
	filters, err := parseDashboardRequest(httptest.NewRecorder(), request)
	if err != nil {
		t.Fatalf("safe GET filters rejected: %v", err)
	}
	if filters.FirewallID != 7 || filters.State != deliveryStateRetry || filters.Page != 3 ||
		filters.From.Format("2006-01-02T15:04") != "2026-09-01T09:00" {
		t.Fatalf("safe GET filters = %+v", filters)
	}
}

func TestDashboardRequestRequiresPOSTForSensitiveFilters(t *testing.T) {
	t.Parallel()

	get := httptest.NewRequest(http.MethodGet, "/fgt-conftail/?state=retry&q=url-secret", nil)
	if _, err := parseDashboardRequest(httptest.NewRecorder(), get); err == nil {
		t.Fatal("GET request with sensitive search filter was accepted")
	}

	body := strings.NewReader("firewall=7&state=retry&page=2&q=body-secret&user=alice&source=branch")
	post := httptest.NewRequest(http.MethodPost, "/fgt-conftail/", body)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	filters, err := parseDashboardRequest(httptest.NewRecorder(), post)
	if err != nil {
		t.Fatalf("POST filters rejected: %v", err)
	}
	if filters.FirewallID != 7 || filters.State != deliveryStateRetry || filters.Page != 2 ||
		filters.Search != "body-secret" || filters.User != "alice" || filters.Source != "branch" {
		t.Fatalf("POST filters = %+v", filters)
	}

	unknown := httptest.NewRequest(http.MethodGet, "/fgt-conftail/?token=must-not-enter-url", nil)
	if _, err := parseDashboardRequest(httptest.NewRecorder(), unknown); err == nil {
		t.Fatal("unknown GET parameter was accepted")
	}
}

func TestDashboardRequestRejectsOversizedAndAmbiguousForms(t *testing.T) {
	t.Parallel()

	oversized := httptest.NewRequest(http.MethodPost, "/fgt-conftail/", strings.NewReader(
		"q="+strings.Repeat("x", dashboardMaxFormBytes),
	))
	oversized.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := parseDashboardRequest(httptest.NewRecorder(), oversized); err == nil {
		t.Fatal("oversized dashboard form was accepted")
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/fgt-conftail/", strings.NewReader("state=all&state=failed"))
	duplicate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := parseDashboardRequest(httptest.NewRecorder(), duplicate); err == nil {
		t.Fatal("duplicate dashboard filter was accepted")
	}
}

func TestDashboardFilterChipsRemoveOneFilterAndKeepValuesInPOSTFields(t *testing.T) {
	t.Parallel()

	filters := dashboardFilters{
		FirewallID: 7,
		Search:     "body-only-search",
		User:       "body-only-operator",
		Source:     "branch-source.example.test",
		State:      deliveryStateRetry,
		Page:       4,
	}
	chips := dashboardActiveFilterChips(filters)
	var source dashboardFilterChip
	for _, chip := range chips {
		if chip.Label == "Source" {
			source = chip
			break
		}
	}
	if source.Label == "" {
		t.Fatal("source filter chip missing")
	}
	fields := make(map[string]string, len(source.Fields))
	for _, field := range source.Fields {
		fields[field.Name] = field.Value
	}
	if _, exists := fields["source"]; exists {
		t.Fatalf("source chip retained the removed filter: %+v", source.Fields)
	}
	if fields["q"] != "body-only-search" || fields["user"] != "body-only-operator" ||
		fields["firewall"] != "7" || fields["state"] != deliveryStateRetry {
		t.Fatalf("source chip did not retain the other filters: %+v", source.Fields)
	}
	if _, exists := fields["page"]; exists {
		t.Fatalf("filter removal retained stale pagination: %+v", source.Fields)
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
			event.Action = "Edit"
			event.TransactionID = "82378752"
			event.LogID = "0100044546"
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
		Source:        "branch-east",
		Device:        "FGT-EDGE",
		Serial:        "FG100F123",
		Action:        "edi",
		TransactionID: "82378752",
		LogID:         "0100044546",
		State:         dashboardStateAll,
		Page:          1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if eventFiltered.HistoryTotal != 1 || eventFiltered.History[0].User != "team%_ops" {
		t.Fatalf("event filters returned %+v", eventFiltered.History)
	}

	for _, filters := range []dashboardFilters{
		{Action: "%", State: dashboardStateAll, Page: 1},
		{TransactionID: "8237875", State: dashboardStateAll, Page: 1},
		{LogID: "010004454", State: dashboardStateAll, Page: 1},
	} {
		mismatched, err := s.queryDashboard(context.Background(), filters)
		if err != nil {
			t.Fatal(err)
		}
		if mismatched.HistoryTotal != 0 || len(mismatched.History) != 0 {
			t.Fatalf("literal/exact event filter %+v returned %+v", filters, mismatched.History)
		}
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
	indexPage, _ := testDashboardRenderers(t)
	extension := &Extension{
		cfg:         &config.Config{ExtFgtConfTail: true},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:       s,
		indexPage:   indexPage,
		currentUser: func(*http.Request) string { return `<img src=x onerror=alert(1)>` },
		pageBase:    testDashboardPageBase(`<img src=x onerror=alert(1)>`),
	}

	request := httptest.NewRequest(http.MethodPost, "/fgt-conftail/", strings.NewReader("user=script"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	extension.dashboard(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	body := response.Body.String()
	for _, unsafe := range []string{"<script>", "<img src=x", "Accept new key", "Retry delivery"} {
		if strings.Contains(body, unsafe) {
			t.Fatalf("read-only page contains unsafe or mutating content %q", unsafe)
		}
	}
	if !strings.Contains(body, `class="language-form"`) || !strings.Contains(body, `class="logout-form"`) ||
		!strings.Contains(body, `class="ct-filter"`) {
		t.Fatal("page does not contain the shared controls and POST filter form")
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img src=x"} {
		if !strings.Contains(body, escaped) {
			t.Fatalf("escaped content %q missing from response", escaped)
		}
	}

	post := httptest.NewRecorder()
	postRequest := httptest.NewRequest(http.MethodPost, "/fgt-conftail/", strings.NewReader("state=all"))
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	extension.dashboard(post, postRequest)
	if post.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", post.Code)
	}
}

func TestDashboardHandlerLogsSuccessfulQueries(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	indexPage, _ := testDashboardRenderers(t)
	var output bytes.Buffer
	extension := &Extension{
		cfg:         &config.Config{ExtFgtConfTail: true},
		logger:      slog.New(slog.NewJSONHandler(&output, nil)),
		store:       s,
		indexPage:   indexPage,
		currentUser: func(*http.Request) string { return "operator" },
		pageBase:    testDashboardPageBase("operator"),
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		"firewall=7&q=urgent+vpn&user=alice&source=branch&device=FGT&serial=FG100&action=SensitiveAction&transaction=SensitiveTransaction&log_id=SensitiveLogID&state=all&from=2026-09-01T09%3A00Z&to=2026-09-01T10%3A00Z",
	))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	extension.dashboard(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	logs := output.String()
	for _, want := range []string{
		`"msg":"conftail dashboard queried"`,
		`"code":"CT-UI-003"`,
		`"outcome":"success"`,
		`"search_filter_set":true`,
		`"user_filter_set":true`,
		`"source_filter_set":true`,
		`"device_filter_set":true`,
		`"serial_filter_set":true`,
		`"action_filter_set":true`,
		`"transaction_filter_set":true`,
		`"log_id_filter_set":true`,
		`"firewall_filter_set":true`,
		`"state_filter_set":false`,
		`"from_filter_set":true`,
		`"to_filter_set":true`,
		`"page":1`,
		`"active_rows":0`,
		`"history_rows":0`,
		`"duration_ms":`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("ConfTail dashboard log does not contain %q:\n%s", want, logs)
		}
	}
	for _, unsafe := range []string{"urgent", "vpn", "alice", "branch", "FGT", "FG100", "SensitiveAction", "SensitiveTransaction", "SensitiveLogID", "operator"} {
		if strings.Contains(logs, unsafe) {
			t.Fatalf("dashboard log contains filter value %q: %s", unsafe, logs)
		}
	}
}

func TestDashboardHandlerDoesNotLogRejectedFilterValues(t *testing.T) {
	t.Parallel()

	const sentinel = "never-log-this-filter-value"
	var output bytes.Buffer
	extension := &Extension{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	response := httptest.NewRecorder()
	extension.dashboard(response, httptest.NewRequest(http.MethodGet, "/?q="+sentinel, nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	logs := output.String()
	if strings.Contains(logs, sentinel) {
		t.Fatalf("rejected filter leaked into application log: %s", logs)
	}
	for _, want := range []string{`"outcome":"invalid"`, `"duration_ms":`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("rejected query log does not contain %q: %s", want, logs)
		}
	}
}

func TestDashboardHandlerRejectsInvalidFilters(t *testing.T) {
	s := newTestStore(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC))
	indexPage, _ := testDashboardRenderers(t)
	extension := &Extension{
		cfg:       &config.Config{ExtFgtConfTail: true},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:     s,
		indexPage: indexPage,
		pageBase:  testDashboardPageBase(""),
	}
	response := httptest.NewRecorder()
	extension.dashboard(response, httptest.NewRequest(http.MethodGet, "/?state=not-valid", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}
