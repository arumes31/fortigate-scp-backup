package fgtadmvpnconf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestGraylogStatusResponse(t *testing.T) {
	for _, tt := range []struct {
		name, body, want string
	}{
		{"logs found", `{"total_results":3}`, "online"},
		{"no logs", `{"total_results":0}`, "offline"},
		{"missing count", `{"messages":[]}`, "error"},
		{"null count", `{"total_results":null}`, "error"},
		{"negative count", `{"total_results":-1}`, "error"},
		{"invalid response", `not JSON`, "error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("query"); got != `source:"FGT_BRANCH-A"` {
					t.Errorf("query = %q", got)
				}
				if got := r.URL.Query().Get("range"); got != "86400" {
					t.Errorf("range = %q", got)
				}
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			e := &Extension{cfg: &config.Config{GraylogURL: server.URL, GraylogToken: "synthetic-token"}}
			if got := e.getGraylogStatus("FGT_BRANCH-A"); got != tt.want {
				t.Fatalf("status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGraylogDisplayedQueriesMatchRequests(t *testing.T) {
	for _, tt := range []struct {
		name, hosts, timeframe string
		want                   []string
	}{
		{"single", "", "300", []string{`source:"FGT_BRANCH-A"`}},
		{"cluster", " node-a, node-b ", "", []string{`source:"node-a"`, `source:"node-b"`}},
		{"escaped", `node"a\b`, "600", []string{`source:"node\"a\\b"`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &VpnConfig{Firewallname: "FGT_BRANCH-A", ClusterHostnames: tt.hosts}
			row := makeConfigRow(c, time.UTC)
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests >= len(tt.want) {
					t.Error("unexpected extra request")
					return
				}
				query := r.URL.Query()
				if got := query.Get("query"); got != tt.want[requests] || got != row.GraylogQueries[requests] {
					t.Errorf("requested query %q differs from expected/displayed query", got)
				}
				wantRange := tt.timeframe
				if wantRange == "" {
					wantRange = "86400"
				}
				if query.Get("range") != wantRange || query.Get("limit") != "1" {
					t.Errorf("unexpected search parameters: %v", query)
				}
				if r.URL.Path != "/api/search/universal/relative" {
					t.Errorf("unexpected endpoint: %s", r.URL.Path)
				}
				requests++
				_, _ = fmt.Fprint(w, `{"total_results":1}`)
			}))
			defer server.Close()
			e := &Extension{cfg: &config.Config{GraylogURL: server.URL, GraylogToken: "synthetic-token", GraylogSearchTimeframe: tt.timeframe}}
			if got := e.computeStatus(c); got != "online" {
				t.Errorf("status = %q", got)
			}
			if requests != len(tt.want) || len(row.GraylogQueries) != len(tt.want) {
				t.Errorf("got %d requests, %d displayed queries; want %d", requests, len(row.GraylogQueries), len(tt.want))
			}
		})
	}
}
