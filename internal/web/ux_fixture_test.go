package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

type uxScenario string

const (
	uxScenarioFull    uxScenario = "full"
	uxScenarioEmpty   uxScenario = "empty"
	uxScenarioWarning uxScenario = "warning"
	uxScenarioError   uxScenario = "error"
	uxScenarioLoading uxScenario = "loading"
)

var uxFixtureNow = time.Date(2026, 9, 2, 10, 30, 0, 0, time.UTC)

type uxFixtureOptions struct {
	Address         string
	DefaultScenario uxScenario
}

type uxFixtureServer struct {
	url  string
	done <-chan error
}

func (s *uxFixtureServer) URL() string        { return s.url }
func (s *uxFixtureServer) Done() <-chan error { return s.done }

func startUXFixture(ctx context.Context, options uxFixtureOptions) (*uxFixtureServer, error) {
	if ctx == nil {
		return nil, errors.New("fixture context is required")
	}
	if options.Address == "" {
		options.Address = "127.0.0.1:0"
	}
	if options.DefaultScenario == "" {
		options.DefaultScenario = uxScenarioFull
	}
	if !validUXScenario(options.DefaultScenario) {
		return nil, errors.New("invalid default fixture scenario")
	}

	webServer := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := webServer.parseTemplates(); err != nil {
		return nil, err
	}
	handler := newUXFixtureHandler(webServer, options.DefaultScenario)
	listener, err := net.Listen("tcp", options.Address)
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveDone := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveDone <- err
	}()
	go func() {
		defer close(done)
		select {
		case err := <-serveDone:
			done <- err
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			shutdownErr := httpServer.Shutdown(shutdownCtx)
			cancel()
			done <- errors.Join(shutdownErr, <-serveDone)
		}
	}()

	return &uxFixtureServer{
		url:  "http://" + listener.Addr().String(),
		done: done,
	}, nil
}

func newUXFixtureHandler(webServer *Server, defaultScenario uxScenario) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		webServer.render(w, "dashboard.html", uxDashboardFixture(scenario))
	})
	return mux
}

func uxScenarioFromRequest(r *http.Request, fallback uxScenario) (uxScenario, bool) {
	value := uxScenario(strings.TrimSpace(r.URL.Query().Get("scenario")))
	if value == "" {
		value = fallback
	}
	return value, validUXScenario(value)
}

func validUXScenario(scenario uxScenario) bool {
	switch scenario {
	case uxScenarioFull, uxScenarioEmpty, uxScenarioWarning, uxScenarioError, uxScenarioLoading:
		return true
	default:
		return false
	}
}

func uxDashboardFixture(scenario uxScenario) dashboardData {
	data := dashboardData{
		Base: BaseData{
			Title: "Dashboard", Username: "reviewer", Lang: "en", Active: "dashboard",
			ExtEnabled: true, ExtFgtConfGenEnabled: true, ExtFgtPolSplitEnabled: true,
			ExtFgtConfConvEnabled: true, ExtFgtConfTailEnabled: true,
		},
		Stats: models.DashboardStats{
			TotalFirewalls: 3,
			Healthy:        3,
			BackupsLast24h: 12,
			TotalBackups:   240,
		},
		NextBackupISO: uxFixtureNow.Add(10 * time.Minute).Format(time.RFC3339),
	}
	if scenario == uxScenarioWarning || scenario == uxScenarioError {
		data.Stats.Healthy = 2
		data.Stats.Failed = 1
		data.Failures = []failureView{{
			ID:          12,
			FQDN:        "branch.example.test",
			LastSuccess: uxFixtureNow.Add(-8 * time.Hour),
			Error:       "synthetic connection timeout",
		}}
	}
	if scenario == uxScenarioLoading {
		data.Running = []runningView{{
			Kind:     "backup",
			FwID:     7,
			FQDN:     "edge.example.test",
			Detail:   "Downloading synthetic configuration",
			Step:     2,
			Total:    4,
			SinceISO: uxFixtureNow.Add(-time.Minute).Format(time.RFC3339),
		}}
	}
	return data
}

func TestUXFixtureLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fixture, err := startUXFixture(ctx, uxFixtureOptions{
		Address:         "127.0.0.1:0",
		DefaultScenario: uxScenarioFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	client := &http.Client{Timeout: 2 * time.Second}

	response, err := client.Get(fixture.URL() + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatalf("read /readyz: %v", readErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := strings.TrimSpace(string(body)); got != "ready" {
		t.Fatalf("GET /readyz body = %q, want ready", got)
	}

	response, err = client.Get(fixture.URL() + "/dashboard?scenario=warning")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /dashboard status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	cancel()
	select {
	case err := <-fixture.Done():
		if err != nil {
			t.Fatalf("fixture shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not shut down after context cancellation")
	}
}

func TestUXFixtureRejectsUnknownScenario(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fixture, err := startUXFixture(ctx, uxFixtureOptions{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	client := &http.Client{Timeout: 2 * time.Second}

	response, err := client.Get(fixture.URL() + "/dashboard?scenario=production")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /dashboard status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}
