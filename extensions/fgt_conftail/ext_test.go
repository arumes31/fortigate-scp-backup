package fgtconftail

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

type scheduledConftailJob struct {
	id         string
	interval   time.Duration
	firstDelay time.Duration
	fn         func()
}

func TestExtensionIdentityAndEnablement(t *testing.T) {
	t.Parallel()
	disabled := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if disabled.Name() != "fgt_conftail" || disabled.Prefix() != "/fgt-conftail" {
		t.Fatalf("extension identity = %q %q", disabled.Name(), disabled.Prefix())
	}
	if disabled.Enabled() {
		t.Fatal("extension is enabled without EXT_FGT_CONFTAIL")
	}
	enabled := New(&config.Config{ExtFgtConfTail: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !enabled.Enabled() {
		t.Fatal("extension did not reflect EXT_FGT_CONFTAIL")
	}
}

func TestExtensionMountRejectsMissingHostDependencies(t *testing.T) {
	t.Parallel()
	base := validConftailDeps(t)
	tests := []struct {
		name   string
		mutate func(*extension.Deps)
	}{
		{name: "database", mutate: func(deps *extension.Deps) { deps.DB = nil }},
		{name: "authentication", mutate: func(deps *extension.Deps) { deps.LoginRequired = nil }},
		{name: "scheduler", mutate: func(deps *extension.Deps) { deps.Schedule = nil }},
		{name: "data directory", mutate: func(deps *extension.Deps) { deps.DataDir = "" }},
		{name: "page context", mutate: func(deps *extension.Deps) { deps.PageBase = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := base
			test.mutate(&deps)
			e := New(validConftailConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err := e.Mount(chi.NewRouter(), deps); err == nil {
				t.Fatal("Mount() accepted missing required dependency")
			}
		})
	}
}

func TestExtensionMountRegistersAuthenticatedDashboardIgnoreActionsAndJobs(t *testing.T) {
	var jobs []scheduledConftailJob
	registeredHealth := map[string]func(context.Context) string{}
	authCalls := 0
	deps := validConftailDeps(t)
	deps.LoginRequired = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCalls++
			w.Header().Set("X-Test-Authenticated", "yes")
			next.ServeHTTP(w, r)
		})
	}
	deps.Schedule = func(id string, interval, firstDelay time.Duration, fn func()) {
		jobs = append(jobs, scheduledConftailJob{id: id, interval: interval, firstDelay: firstDelay, fn: fn})
	}
	deps.RegisterHealth = func(name string, probe func(context.Context) string) {
		registeredHealth[name] = probe
	}
	e := New(validConftailConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		if e.store != nil {
			_ = e.store.close()
		}
	})
	router := chi.NewRouter()
	if err := e.Mount(router, deps); err != nil {
		t.Fatalf("Mount() error = %v", err)
	}
	if e.poller == nil || e.poller.logger == nil {
		t.Fatal("mounted poll worker does not use the application logger")
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, body = %q", response.Code, response.Body.String())
	}
	if authCalls != 1 || response.Header().Get("X-Test-Authenticated") != "yes" {
		t.Fatal("dashboard route did not pass through LoginRequired")
	}
	statusResponse := httptest.NewRecorder()
	router.ServeHTTP(statusResponse, httptest.NewRequest(http.MethodGet, "/status", nil))
	if statusResponse.Code != http.StatusOK ||
		statusResponse.Header().Get("X-Test-Authenticated") != "yes" ||
		!strings.Contains(statusResponse.Body.String(), `"running":false`) {
		t.Fatalf("authenticated GET /status = %d/%q", statusResponse.Code, statusResponse.Body.String())
	}

	postResponse := httptest.NewRecorder()
	router.ServeHTTP(postResponse, httptest.NewRequest(http.MethodPost, "/", nil))
	if postResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405", postResponse.Code)
	}
	staticPostResponse := httptest.NewRecorder()
	router.ServeHTTP(
		staticPostResponse,
		httptest.NewRequest(http.MethodPost, "/static/conftail.css", nil),
	)
	if staticPostResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /static/conftail.css status = %d, want 405", staticPostResponse.Code)
	}
	parent := chi.NewRouter()
	parent.Mount(e.Prefix(), router)
	staticGetResponse := httptest.NewRecorder()
	parent.ServeHTTP(
		staticGetResponse,
		httptest.NewRequest(http.MethodGet, "/fgt-conftail/static/conftail.css", nil),
	)
	if staticGetResponse.Code != http.StatusOK ||
		!strings.Contains(staticGetResponse.Body.String(), ".ct-metrics") ||
		staticGetResponse.Header().Get("X-Test-Authenticated") != "yes" {
		t.Fatalf(
			"GET /fgt-conftail/static/conftail.css = %d/%q, want the embedded stylesheet",
			staticGetResponse.Code,
			staticGetResponse.Body.String(),
		)
	}
	chainResponse := httptest.NewRecorder()
	router.ServeHTTP(
		chainResponse,
		httptest.NewRequest(
			http.MethodGet,
			"/chain/11111111-2222-3333-4444-555555555555",
			nil,
		),
	)
	if chainResponse.Code != http.StatusNotFound ||
		chainResponse.Header().Get("X-Test-Authenticated") != "yes" {
		t.Fatalf(
			"authenticated GET /chain/{id} = %d/header %q, want 404/auth marker",
			chainResponse.Code,
			chainResponse.Header().Get("X-Test-Authenticated"),
		)
	}
	ignoreRequest := httptest.NewRequest(
		http.MethodPost,
		"/ignore-rules",
		strings.NewReader("event_id=999&kind=attribute"),
	)
	ignoreRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ignoreResponse := httptest.NewRecorder()
	router.ServeHTTP(ignoreResponse, ignoreRequest)
	if ignoreResponse.Code != http.StatusNotFound || ignoreResponse.Header().Get("X-Test-Authenticated") != "yes" {
		t.Fatalf(
			"authenticated POST /ignore-rules = %d/header %q, want 404/auth marker",
			ignoreResponse.Code,
			ignoreResponse.Header().Get("X-Test-Authenticated"),
		)
	}
	if len(jobs) != 4 {
		t.Fatalf("scheduled jobs = %d, want poll, delivery, ADM catalog refresh, and maintenance", len(jobs))
	}
	for _, name := range []string{
		"conftail.graylog", "conftail.catalog", "conftail.store", "conftail.hookwise",
	} {
		if registeredHealth[name] == nil {
			t.Errorf("health component %q was not registered", name)
		}
	}
	if jobs[0].id != conftailPollJobID || jobs[0].interval != time.Minute || jobs[0].fn == nil {
		t.Fatalf("poll job = %+v", jobs[0])
	}
	if jobs[2].id != conftailCatalogJobID || jobs[2].interval != 30*time.Second || jobs[2].fn == nil {
		t.Fatalf("catalog refresh job = %+v", jobs[2])
	}
	if jobs[1].id != conftailDeliveryJobID || jobs[1].interval != time.Minute || jobs[1].fn == nil {
		t.Fatalf("delivery job = %+v", jobs[1])
	}
	if jobs[3].id != conftailMaintenanceJobID || jobs[3].interval != 24*time.Hour || jobs[3].fn == nil {
		t.Fatalf("maintenance job = %+v", jobs[3])
	}
}

func TestExtensionMountSkipsCatalogRefreshWhenADMVPNIsDisabled(t *testing.T) {
	var jobIDs []string
	deps := validConftailDeps(t)
	deps.Schedule = func(id string, _ time.Duration, _ time.Duration, _ func()) {
		jobIDs = append(jobIDs, id)
	}
	cfg := validConftailConfig()
	cfg.ExtAdmVpnConf = false
	e := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		if e.store != nil {
			_ = e.store.close()
		}
	})
	if err := e.Mount(chi.NewRouter(), deps); err != nil {
		t.Fatalf("Mount() error = %v", err)
	}
	if len(jobIDs) != 3 || jobIDs[0] != conftailPollJobID || jobIDs[1] != conftailDeliveryJobID || jobIDs[2] != conftailMaintenanceJobID {
		t.Fatalf("scheduled jobs = %v, want poll, delivery, and maintenance", jobIDs)
	}
}

func TestRunCatalogRefreshPublishesChangesAndPreservesLastGoodCatalog(t *testing.T) {
	first := sourceCatalog{
		aliases: []string{"fw-a"},
		byID: map[int]firewallRef{
			1: {ID: 1, Name: "fw-a.example"},
		},
		coverageRows: []sourceCoverage{{FirewallID: 1, FirewallName: "fw-a.example"}},
	}
	second := sourceCatalog{
		aliases: []string{"fw-b"},
		byID: map[int]firewallRef{
			2: {ID: 2, Name: "fw-b.example"},
		},
		coverageRows: []sourceCoverage{{FirewallID: 2, FirewallName: "fw-b.example"}},
	}
	calls := 0
	e := &Extension{
		ctx:    context.Background(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		catalogLoader: func(context.Context) (sourceCatalog, error) {
			calls++
			switch calls {
			case 1:
				return first, nil
			case 2:
				return second, nil
			default:
				return sourceCatalog{}, context.DeadlineExceeded
			}
		},
	}

	e.runCatalogRefresh()
	e.runCatalogRefresh()
	if firewall, ok := e.catalog.firewall(2); !ok || firewall.Name != "fw-b.example" {
		t.Fatalf("refreshed catalog = %+v, want firewall 2", e.catalog)
	}
	e.runCatalogRefresh()
	if firewall, ok := e.catalog.firewall(2); !ok || firewall.Name != "fw-b.example" {
		t.Fatalf("failed refresh replaced last good catalog: %+v", e.catalog)
	}
	if e.catalogLastError == "" || e.catalogHealth(context.Background()) != "failed" {
		t.Fatalf("failed refresh health = %q / %q", e.catalogLastError, e.catalogHealth(context.Background()))
	}
}

func TestRunPollLogsSkippedGraylogRows(t *testing.T) {
	activation := time.Now().UTC().Add(-time.Hour)
	s := newTestStore(t, activation)
	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 1, Name: "fw-a.example.com"}},
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worker := &pollWorker{
		store: s,
		graylog: &scriptedGraylogFetcher{fn: func(_ int, _ []string) ([]RawEvent, FetchStats, error) {
			return []RawEvent{
				rawConfigEvent("unknown", "not-registered", "admin-a", "tx-1", activation.Add(time.Minute)),
			}, FetchStats{Pages: 1, Rows: 1}, nil
		}},
		loadCatalog:         func(context.Context) (sourceCatalog, error) { return catalog, nil },
		query:               "type:event",
		overlap:             time.Hour,
		idle:                30 * time.Minute,
		maxDescriptionBytes: 60_000,
		missingUserWindow:   5 * time.Minute,
	}
	var output bytes.Buffer
	e := &Extension{
		cfg:      &config.Config{FgtConfTailRetentionDays: 365},
		logger:   slog.New(slog.NewJSONHandler(&output, nil)),
		ctx:      context.Background(),
		store:    s,
		hookwise: &hookwiseClient{},
		poller:   worker,
	}
	e.runPoll()
	for _, want := range []string{
		`"msg":"conftail poll completed"`,
		`"code":"CT-GL-002"`,
		`"skipped":1`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("poll completion log does not contain %q:\n%s", want, output.String())
		}
	}
}

func validConftailConfig() *config.Config {
	return &config.Config{
		ExtAdmVpnConf:             true,
		ExtFgtConfTail:            true,
		GraylogURL:                "https://graylog.example",
		GraylogToken:              "graylog-token",
		FgtConfTailHookwiseURL:    "https://hookwise.example/w/config-tail",
		FgtConfTailHookwiseToken:  "hookwise-token",
		FgtConfTailPollSeconds:    900,
		FgtConfTailIdleSeconds:    1800,
		FgtConfTailOverlapSeconds: 3600,
		FgtConfTailRetentionDays:  365,
		FgtConfTailTicketMaxBytes: 60_000,
		FgtConfTailGraylogQuery:   "type:event AND logid:0100044544",
	}
}

func validConftailDeps(t *testing.T) extension.Deps {
	t.Helper()
	return extension.Deps{
		Context:       context.Background(),
		DB:            &pgxpool.Pool{},
		LoginRequired: func(next http.Handler) http.Handler { return next },
		CurrentUser:   func(*http.Request) string { return "admin" },
		Schedule:      func(string, time.Duration, time.Duration, func()) {},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		TZ:            time.UTC,
		DataDir:       t.TempDir(),
		PageBase: func(r *http.Request, title, active string) webui.BaseData {
			return webui.BaseData{
				Title: title, Username: "admin", Lang: "en", Active: active, ReturnTo: r.URL.RequestURI(),
				Shell: webui.ShellText("en"),
				Navigation: webui.Navigation(webui.NavigationOptions{
					Lang: "en", Active: active, AdmVPN: true, ConfGen: true, PolSplit: true,
					ConfConv: true, ConfTail: true,
				}),
			}
		},
	}
}
