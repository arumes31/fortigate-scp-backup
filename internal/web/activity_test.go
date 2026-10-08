package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

type activityTestStore struct {
	fakeStore
	total        int
	logs         []models.ActivityLog
	countErr     error
	listErr      error
	countFilters []models.ActivityLogFilter
	listFilters  []models.ActivityLogFilter
	offsets      []int
}

func (s *activityTestStore) CountActivityLogs(_ context.Context, filter models.ActivityLogFilter) (int, error) {
	s.countFilters = append(s.countFilters, filter)
	return s.total, s.countErr
}

func (s *activityTestStore) ListActivityLogs(_ context.Context, filter models.ActivityLogFilter, _, offset int) ([]models.ActivityLog, error) {
	s.listFilters = append(s.listFilters, filter)
	s.offsets = append(s.offsets, offset)
	return s.logs, s.listErr
}

func TestParseActivityLogRequestValidatesAndNormalizesFilters(t *testing.T) {
	t.Parallel()
	location, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"/activity_log?q=%20needle%20&user=%20operator%20&action=Config&from=2026-09-01&to=2026-09-02&page=3", nil)
	parsed, err := parseActivityLogRequest(request, location)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Page != 3 || parsed.Filter.Query != "needle" || parsed.Filter.Username != "operator" || parsed.Filter.Action != "Config" {
		t.Fatalf("parsed activity request = %+v", parsed)
	}
	if parsed.Filter.From.Format(time.RFC3339) != "2026-09-01T00:00:00+02:00" ||
		parsed.Filter.To.Format(time.RFC3339) != "2026-09-03T00:00:00+02:00" {
		t.Fatalf("activity date bounds = %s to %s", parsed.Filter.From, parsed.Filter.To)
	}

	for _, path := range []string{
		"/activity_log?from=invalid",
		"/activity_log?to=2026-13-01",
		"/activity_log?from=2026-09-03&to=2026-09-02",
		"/activity_log?q=" + strings.Repeat("x", activityQueryMaxRunes+1),
	} {
		if _, err := parseActivityLogRequest(httptest.NewRequest(http.MethodGet, path, nil), location); err == nil {
			t.Errorf("parseActivityLogRequest(%q) accepted invalid input", path)
		}
	}
}

func TestActivityLogPageURLPreservesValidatedFilters(t *testing.T) {
	t.Parallel()
	view := activityLogFilterView{Query: "config change", User: "operator", Action: "Edit", From: "2026-09-01", To: "2026-09-02"}
	pageURL, err := url.Parse(activityLogPageURL(view, 2))
	if err != nil {
		t.Fatal(err)
	}
	values := pageURL.Query()
	for key, want := range map[string]string{
		"q": "config change", "user": "operator", "action": "Edit", "from": "2026-09-01", "to": "2026-09-02", "page": "2",
	} {
		if got := values.Get(key); got != want {
			t.Errorf("pagination %s = %q, want %q", key, got, want)
		}
	}
}

func TestHandleActivityLogUsesSameFilterForCountAndPage(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	store := &activityTestStore{
		total: 151,
		logs: []models.ActivityLog{{
			Username: "operator", Action: "Configuration Change", Details: "deep synthetic match",
			Timestamp: time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC),
		}},
	}
	srv.store = store
	request := httptest.NewRequest(http.MethodGet,
		"/activity_log?q=deep&user=operator&action=Configuration&from=2026-09-01&to=2026-09-02&page=2", nil)
	response := httptest.NewRecorder()
	srv.handleActivityLog(response, request)

	if len(store.countFilters) != 1 || len(store.listFilters) != 1 || store.countFilters[0] != store.listFilters[0] {
		t.Fatalf("count/list filters differ: count=%+v list=%+v", store.countFilters, store.listFilters)
	}
	if len(store.offsets) != 1 || store.offsets[0] != 100 {
		t.Fatalf("activity offsets = %v, want [100]", store.offsets)
	}
	body := response.Body.String()
	for _, want := range []string{"deep synthetic match", "Page 2 of 2", `rel="prev"`, "q=deep", "user=operator", "action=Configuration"} {
		if !strings.Contains(body, want) {
			t.Errorf("activity page missing %q", want)
		}
	}
}

func TestHandleActivityLogShowsValidationAndDatabaseErrors(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		countErr  error
		listErr   error
		want      string
		wantCount int
		wantList  int
	}{
		{name: "invalid date", path: "/activity_log?from=bad", want: "invalid from date", wantCount: 0, wantList: 0},
		{name: "count error", path: "/activity_log?q=needle", countErr: errors.New("count failed"), want: "Failed to load activity-log count", wantCount: 1, wantList: 0},
		{name: "list error", path: "/activity_log?q=needle", listErr: errors.New("list failed"), want: "Failed to load activity logs", wantCount: 1, wantList: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := testServer(t)
			t.Cleanup(srv.hub.shutdown)
			store := &activityTestStore{total: 1, countErr: test.countErr, listErr: test.listErr}
			srv.store = store
			response := httptest.NewRecorder()
			srv.handleActivityLog(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			body := response.Body.String()
			if !strings.Contains(body, test.want) {
				t.Fatalf("activity error body missing %q: %s", test.want, response.Body.String())
			}
			if strings.Contains(body, "No activity matches these filters") || strings.Contains(body, "No activity recorded yet") {
				t.Fatalf("activity error masquerades as an empty result: %s", body)
			}
			if len(store.countFilters) != test.wantCount || len(store.listFilters) != test.wantList {
				t.Fatalf("activity DB calls = count %d/list %d", len(store.countFilters), len(store.listFilters))
			}
		})
	}
}
