package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestErrorsShowsActionableFailureContext(t *testing.T) {
	srv := testServer(t)
	lastAttempt := time.Date(2026, 9, 2, 10, 30, 0, 0, time.UTC)
	srv.store = fakeStore{errors: []models.BackupError{{
		ID:          12,
		FQDN:        "branch.example.test",
		LastAttempt: lastAttempt,
		LastSuccess: time.Date(2026, 9, 2, 7, 30, 0, 0, time.UTC),
		Reason:      "synthetic connection timeout while reading configuration",
	}}}
	srv.sched.Schedule(BackupJobID(12), time.Hour, 30*time.Minute, func() {})
	t.Cleanup(srv.sched.Stop)

	rr := httptest.NewRecorder()
	srv.handleErrors(rr, httptest.NewRequest(http.MethodGet, "/errors", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"synthetic connection timeout while reading configuration",
		"Last attempt", "Last success", "Next scheduled",
		`href="/#firewall-12"`, `href="/backups/12"`,
		`method="post"`, `action="/backup_now/12"`, `name="return_to" value="/errors"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q", want)
		}
	}
	if strings.Contains(body, `title="synthetic connection timeout`) {
		t.Error("failure reason must be visible, not hidden in a title-only status pill")
	}
}

func TestErrorsDistinguishesHealthyFromLoadError(t *testing.T) {
	tests := []struct {
		name      string
		store     fakeStore
		want      string
		notWanted string
	}{
		{name: "healthy", store: fakeStore{}, want: "Everything is healthy", notWanted: "Could not load backup failures"},
		{name: "database error", store: fakeStore{errorsErr: errors.New("synthetic database outage")}, want: "Could not load backup failures", notWanted: "Everything is healthy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServer(t)
			srv.store = tt.store
			rr := httptest.NewRecorder()
			srv.handleErrors(rr, httptest.NewRequest(http.MethodGet, "/errors", nil))
			if !strings.Contains(rr.Body.String(), tt.want) {
				t.Errorf("response missing %q", tt.want)
			}
			if strings.Contains(rr.Body.String(), tt.notWanted) {
				t.Errorf("response unexpectedly contains %q", tt.notWanted)
			}
		})
	}
}

func TestRetryRejectsUnknownFirewallAndReturnsToErrors(t *testing.T) {
	activity := []string{}
	srv := testServer(t)
	srv.store = fakeStore{activity: &activity}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/backup_now/999", strings.NewReader("return_to=%2Ferrors"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("fwID", "999")
	req = req.WithContext(contextWithRoute(req.Context(), routeCtx))
	srv.handleBackupNow(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/errors" {
		t.Fatalf("Location = %q, want /errors", got)
	}
	if len(activity) != 1 || !strings.Contains(activity[0], "Backup Now Failed") {
		t.Fatalf("activity = %#v, want one rejected-retry record", activity)
	}
}

func TestRetryDoesNotAcceptExternalReturnTarget(t *testing.T) {
	srv := testServer(t)
	srv.store = fakeStore{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/backup_now/not-an-id", strings.NewReader("return_to=https%3A%2F%2Fevil.example.test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("fwID", "not-an-id")
	req = req.WithContext(contextWithRoute(req.Context(), routeCtx))

	srv.handleBackupNow(rr, req)

	if got := rr.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want safe root redirect", got)
	}
}

func contextWithRoute(ctx context.Context, routeCtx *chi.Context) context.Context {
	return context.WithValue(ctx, chi.RouteCtxKey, routeCtx)
}
