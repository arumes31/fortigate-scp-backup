package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func TestRequestIDOnErrorPageMatchesStructuredAccessLog(t *testing.T) {
	srv := testServer(t)
	var logs bytes.Buffer
	srv.logger = slog.New(slog.NewJSONHandler(&logs, nil))

	recorder := httptest.NewRecorder()
	srv.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/missing-page", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	requestID := recorder.Header().Get("X-Request-Id")
	if requestID == "" {
		t.Fatal("response is missing X-Request-Id")
	}
	if !strings.Contains(recorder.Body.String(), requestID) {
		t.Fatal("error page does not show its request ID")
	}
	if !strings.Contains(logs.String(), `"reqid":"`+requestID+`"`) {
		t.Fatalf("structured access log does not contain page request ID %q: %s", requestID, logs.String())
	}
}

func TestErrorPageIsLocalizedAccessibleAndUsesSafeNavigation(t *testing.T) {
	srv := testServer(t)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.test/fehlt", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "de"})
	req.Header.Set("Referer", "https://outside.example.test/private?token=secret")
	srv.Routes().ServeHTTP(recorder, req)

	body := recorder.Body.String()
	for _, want := range []string{
		`role="alert"`, "Seite nicht gefunden", "Anfrage-ID", `href="/dashboard"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("localized 404 missing %q", want)
		}
	}
	for _, forbidden := range []string{"outside.example.test", "token=secret", `data-error-retry`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("localized 404 contains unsafe/unexpected value %q", forbidden)
		}
	}
}

func TestErrorPageBackLinkKeepsOnlySafeLocalPath(t *testing.T) {
	srv := testServer(t)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.test/missing", nil)
	req.Header.Set("Referer", "https://app.example.test/activity_log?private=discard-me")
	srv.Routes().ServeHTTP(recorder, req)

	if body := recorder.Body.String(); !strings.Contains(body, `href="/activity_log"`) || strings.Contains(body, "private=discard-me") {
		t.Fatalf("back link did not retain only the safe local path: %s", body)
	}
}

func TestErrorPageRecovers500WithoutExposingInternalDetail(t *testing.T) {
	srv := testServer(t)
	var logs bytes.Buffer
	srv.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(srv.accessLog)
	router.Use(securityHeaders(false))
	router.Use(srv.recoverer)
	router.Get("/synthetic-failure", func(http.ResponseWriter, *http.Request) {
		panic("sensitive internal stack detail")
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/synthetic-failure", nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("500 response security header = %q, want nosniff", got)
	}
	for _, want := range []string{`role="alert"`, "Something went wrong", `data-error-retry`, `href="/synthetic-failure"`} {
		if !strings.Contains(body, want) {
			t.Errorf("500 page missing %q", want)
		}
	}
	if strings.Contains(body, "sensitive internal stack detail") || strings.Contains(body, "goroutine") {
		t.Fatal("500 page exposed panic or stack detail")
	}
	requestID := recorder.Header().Get("X-Request-Id")
	if requestID == "" || !strings.Contains(logs.String(), `"reqid":"`+requestID+`"`) {
		t.Fatalf("500 log/page correlation missing for %q", requestID)
	}
}

func TestErrorPageDoesNotRetryUnsafeRequest(t *testing.T) {
	srv := testServer(t)
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(srv.recoverer)
	router.Post("/synthetic-failure", func(http.ResponseWriter, *http.Request) { panic("synthetic") })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/synthetic-failure", strings.NewReader("secret=value")))
	if strings.Contains(recorder.Body.String(), `data-error-retry`) {
		t.Fatal("500 page offered retry for an unsafe POST request")
	}
}
