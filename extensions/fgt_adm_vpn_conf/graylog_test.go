package fgtadmvpnconf

import (
	"encoding/json"
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

func TestGraylogRecoveryPersistsWhenHookwiseFails(t *testing.T) {
	e, ids := newBulkTestExtension(t, 1)
	if _, err := e.db.Exec(`UPDATE vpn_config SET last_graylog_status = 'offline',
		graylog_unhealthy_since = '2026-01-01 00:00:00' WHERE id = ?`, ids[0]); err != nil {
		t.Fatal(err)
	}
	graylog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"total_results":1}`)
	}))
	defer graylog.Close()
	hookwise := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "synthetic delivery failure", http.StatusServiceUnavailable)
	}))
	defer hookwise.Close()
	e.cfg = &config.Config{GraylogURL: graylog.URL, GraylogToken: "synthetic-token",
		HookwiseURL: hookwise.URL, HookwiseToken: "synthetic-token"}
	c, err := e.getConfig(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := e.checkGraylogConfig(c); err != nil {
		t.Fatal(err)
	}
	c, err = e.getConfig(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.LastGraylogStatus != "online" || c.LastGraylogUnhealthySince != nil || c.LastGraylogCheck == nil {
		t.Fatalf("recovery not persisted: status=%q unhealthySince=%v checkedAt=%v",
			c.LastGraylogStatus, c.LastGraylogUnhealthySince, c.LastGraylogCheck)
	}
	if c.PendingHookwiseStatus != "online" {
		t.Fatalf("failed recovery notification not queued: %q", c.PendingHookwiseStatus)
	}
}

func TestGraylogNotificationRetriesDoNotChangeHealth(t *testing.T) {
	e, ids := newBulkTestExtension(t, 1)
	var dbPath string
	if err := e.db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&dbPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.db.Close() })
	for _, step := range []struct {
		name, observation, notification, pending string
		failDelivery                             bool
	}{
		{"first observation is not a transition", "offline", "", "", false},
		{"recovery delivery fails", "online", "UP", "online", true},
		{"retry survives restart", "online", "UP", "", false},
		{"stable state does not resend", "online", "", "", false},
		{"outage delivery fails", "offline", "DOWN", "offline", true},
		{"check error pauses pending delivery", "error", "", "offline", false},
		{"recovery supersedes pending outage", "online", "UP", "", false},
		{"new outage delivers normally", "offline", "DOWN", "", false},
		{"check error is not an outage notification", "error", "", "", false},
		{"recovery from error alone does not notify", "online", "", "", false},
	} {
		t.Run(step.name, func(t *testing.T) {
			// Reopen the database and worker between checks to simulate a restart.
			if err := e.db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := openDB(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			e.db = db
			worker := &Extension{db: e.db, logger: e.logger}
			messages := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					switch step.observation {
					case "online":
						_, _ = fmt.Fprint(w, `{"total_results":1}`)
					case "offline":
						_, _ = fmt.Fprint(w, `{"total_results":0}`)
					default:
						http.Error(w, "synthetic query failure", http.StatusServiceUnavailable)
					}
					return
				}
				var payload hookwisePayload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				messages <- payload.Status
				if step.failDelivery {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					w.WriteHeader(http.StatusAccepted)
				}
			}))
			defer server.Close()
			worker.cfg = &config.Config{GraylogURL: server.URL, GraylogToken: "synthetic-token",
				HookwiseURL: server.URL, HookwiseToken: "synthetic-token"}
			before, err := worker.getConfig(ids[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.checkGraylogConfig(before); err != nil {
				t.Fatal(err)
			}
			after, err := worker.getConfig(ids[0])
			if err != nil {
				t.Fatal(err)
			}
			if after.LastGraylogStatus != step.observation || after.PendingHookwiseStatus != step.pending {
				t.Fatalf("stored status/pending = %s/%s; want %s/%s", after.LastGraylogStatus,
					after.PendingHookwiseStatus, step.observation, step.pending)
			}
			if (after.LastGraylogUnhealthySince != nil) != graylogStatusUnhealthy(step.observation) {
				t.Fatal("unhealthy streak disagrees with observed state")
			}
			if before.LastGraylogUnhealthySince != nil && after.LastGraylogUnhealthySince != nil &&
				!before.LastGraylogUnhealthySince.Equal(*after.LastGraylogUnhealthySince) {
				t.Fatal("ongoing unhealthy streak was reset")
			}
			got := ""
			select {
			case got = <-messages:
			default:
			}
			if got != step.notification || len(messages) != 0 {
				t.Fatalf("notification = %q, want %q", got, step.notification)
			}
		})
	}
}

func TestGraylogPersistenceFailureDoesNotSendNotification(t *testing.T) {
	e, ids := newBulkTestExtension(t, 1)
	c, err := e.getConfig(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	c.LastGraylogStatus = "offline"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("notification sent before the check was durably recorded")
		}
		_, _ = fmt.Fprint(w, `{"total_results":1}`)
	}))
	defer server.Close()
	e.cfg = &config.Config{GraylogURL: server.URL, GraylogToken: "synthetic-token",
		HookwiseURL: server.URL, HookwiseToken: "synthetic-token"}
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.checkGraylogConfig(c); err == nil {
		t.Fatal("database failure was ignored")
	}
}

func TestPendingHookwiseMigrationPreservesHealth(t *testing.T) {
	e, ids := newBulkTestExtension(t, 1)
	if _, err := e.db.Exec("ALTER TABLE vpn_config DROP COLUMN pending_hookwise_status"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec("UPDATE vpn_config SET last_graylog_status = 'offline' WHERE id = ?", ids[0]); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.runMigrations(); err != nil {
			t.Fatal(err)
		}
	}
	c, err := e.getConfig(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.LastGraylogStatus != "offline" || c.PendingHookwiseStatus != "" || c.CompanyName != "101" {
		t.Fatal("migration changed existing monitoring or company data")
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
