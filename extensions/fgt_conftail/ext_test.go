package fgtconftail

import (
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

func TestExtensionMountRegistersAuthenticatedReadOnlyDashboardAndJobs(t *testing.T) {
	var jobs []scheduledConftailJob
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

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, body = %q", response.Code, response.Body.String())
	}
	if authCalls != 1 || response.Header().Get("X-Test-Authenticated") != "yes" {
		t.Fatal("dashboard route did not pass through LoginRequired")
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
	if len(jobs) != 2 {
		t.Fatalf("scheduled jobs = %d, want poll and delivery", len(jobs))
	}
	if jobs[0].id != conftailPollJobID || jobs[0].interval != 15*time.Minute || jobs[0].fn == nil {
		t.Fatalf("poll job = %+v", jobs[0])
	}
	if jobs[1].id != conftailDeliveryJobID || jobs[1].interval != time.Minute || jobs[1].fn == nil {
		t.Fatalf("delivery job = %+v", jobs[1])
	}
}

func validConftailConfig() *config.Config {
	return &config.Config{
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
	}
}
