package web

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

func TestUXAuditPreview(t *testing.T) {
	if os.Getenv("FORTISAFE_UX_AUDIT_PREVIEW") != "1" {
		t.Skip("UX audit preview is opt-in")
	}
	s := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	base := func(title, active string) BaseData {
		return BaseData{
			Title: title, Username: "reviewer", Lang: "en", Active: active,
			ExtEnabled: true, ExtFgtConfGenEnabled: true, ExtFgtPolSplitEnabled: true,
			ExtFgtConfConvEnabled: true, ExtFgtConfTailEnabled: true,
		}
	}
	now := time.Date(2026, 9, 2, 10, 30, 0, 0, time.UTC)
	firewalls := []models.Firewall{
		{ID: 7, FQDN: "edge-vienna.example", Username: "backup", IntervalMin: 360, RetentionCount: 30, LastBackup: now.Add(-20 * time.Minute), Status: "Success", SSHPort: 22},
		{ID: 12, FQDN: "branch-graz.example", Username: "backup", IntervalMin: 60, RetentionCount: 14, LastBackup: now.Add(-8 * time.Hour), Status: "Failed: connection timeout", SSHPort: 22},
	}
	mux := http.NewServeMux()
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "login.html", loginData{TOTPEnabled: true, RadiusEnabled: true})
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "dashboard.html", dashboardData{
			Base: base("Dashboard", "dashboard"),
			Stats: models.DashboardStats{TotalFirewalls: 12, Healthy: 9, Failed: 2, New: 1, BackupsLast24h: 46, TotalBackups: 4182},
			Failures: []failureView{{ID: 12, FQDN: "branch-graz.example", LastSuccess: now.Add(-8 * time.Hour), Error: "connection timeout"}},
			Stale: []staleBackup{{ID: 21, FQDN: "warehouse-linz.example", LastSuccess: now.Add(-72 * time.Hour), AgeHours: 72, Cadence: "6h"}},
			Running: []runningView{{Kind: "backup", FwID: 7, FQDN: "edge-vienna.example", Detail: "Downloading configuration", Step: 2, Total: 4, SinceISO: now.Add(-time.Minute).Format(time.RFC3339)}},
			StorageBytes: 8 << 30, StorageWeek: 300 << 20, LargestBytes: 6 << 20, SmallestBytes: 900 << 10,
			AvgDuration: "4.8s", BackupsRun: 46, NextBackupISO: now.Add(10 * time.Minute).Format(time.RFC3339),
			BlockedPorts: []blockedPortIssue{{FwID: 7, FQDN: "edge-vienna.example", Switch: "SW-01", Port: "port12", Reason: "BPDU guard", Since: now.Add(-time.Hour).Format(time.RFC3339)}},
			GraylogIssues: []graylogIssue{{Firewall: "branch-graz.example", Site: "Graz", Status: "offline", LastCheck: now.Add(-5 * time.Minute).Format(time.RFC3339)}},
			DNSIssues: []dnsIssue{{Firewall: "edge-vienna.example", Site: "Vienna", DNSName: "edge-vienna.example", Expected: "203.0.113.8", Resolved: "203.0.113.9", Status: "mismatch", LastCheck: now.Format(time.RFC3339)}},
			LicenseIssues: []licenseIssue{{FwID: 12, FQDN: "branch-graz.example", Serial: "FGT-SAMPLE-12", Service: "FortiCare", Expiry: "2026-09-12", DaysLeft: 10, Level: "warn"}},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "index.html", indexData{Base: base("Firewalls", "firewalls"), Firewalls: firewalls, NextRuns: map[int]time.Time{7: now.Add(10 * time.Minute), 12: now.Add(20 * time.Minute)}})
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "search.html", searchData{Base: base("Search", "search"), Query: "config system admin", Results: []searchResult{{FQDN: "edge-vienna.example", Filename: "edge-vienna.conf", Line: "config system admin"}}})
	})
	mux.HandleFunc("/audit", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "audit.html", auditData{Base: base("Audit", "audit"), Firewalls: []models.FirewallRef{{ID: 7, FQDN: "edge-vienna.example"}, {ID: 12, FQDN: "branch-graz.example"}}})
	})
	mux.HandleFunc("/audit/results/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","score":73,"findings":[{"severity":"critical","text":"Administrative account has no MFA","remediation":"Enable two-factor authentication."}]}`))
	})
	mux.HandleFunc("/licenses", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "licenses.html", licensesData{Base: base("Licenses", "licenses"), Unknown: 2})
	})
	mux.HandleFunc("/licenses/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"running":false}`))
	})
	mux.HandleFunc("/ipam", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "ipam.html", ipamData{Base: base("IPAM", "ipam")})
	})
	mux.HandleFunc("/ipam/data", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"running":false,"snapshot":{"entries":[],"overlaps":[],"prefixes":0}}`))
	})
	mux.HandleFunc("/topology", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "topology.html", topologyData{Base: base("Topology", "topology"), Firewalls: []models.FirewallRef{{ID: 7, FQDN: "edge-vienna.example"}, {ID: 12, FQDN: "branch-graz.example"}}})
	})
	mux.HandleFunc("/activity_log", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "activity_log.html", activityLogData{Base: base("Activity log", "activity"), Logs: []models.ActivityLog{{Username: "reviewer", Action: "Backup completed", Details: "edge-vienna.example", Timestamp: now}}, Page: 1, TotalPages: 1})
	})
	mux.HandleFunc("/errors", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "errors.html", errorsData{Base: base("Backup errors", "errors"), Errors: firewalls[1:]})
	})
	mux.HandleFunc("/backups/7", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "backups.html", backupsData{Base: base("Backups", "firewalls"), FwID: 7, Backups: []models.Backup{{ID: 1, FwID: 7, Timestamp: now, Filename: "edge-vienna_20260902.conf", SizeBytes: 214000}}})
	})
	mux.HandleFunc("/change_password", func(w http.ResponseWriter, _ *http.Request) {
		s.render(w, "change_password.html", changePasswordData{Base: base("Change password", "password")})
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:18901")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	go func() { _ = server.Serve(listener) }()
	fmt.Println("FORTISAFE_UX_AUDIT_PREVIEW=http://127.0.0.1:18901/dashboard")
	time.Sleep(180 * time.Second)
}
