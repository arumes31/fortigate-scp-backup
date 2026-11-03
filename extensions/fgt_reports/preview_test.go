package fgt_reports

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/extensions/fgt_reports/renderpdf"
	"github.com/arumes31/fortigate-scp-backup/internal/fortiosconfig"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

// TestReportsBrowserPreview is an opt-in, loopback-only synthetic fixture for
// browser review. It uses production templates, assets, analyzer, rendering,
// encrypted storage and handlers, with no production account or backup access.
// Run with FORTISAFE_REPORTS_PREVIEW=1 and stop via POST /__fixture/stop.
func TestReportsBrowserPreview(t *testing.T) {
	if os.Getenv("FORTISAFE_REPORTS_PREVIEW") != "1" {
		t.Skip("set FORTISAFE_REPORTS_PREVIEW=1 for local browser review")
	}
	const addr = "127.0.0.1:18906"
	plain := []byte(reportsBrowserConfig)
	hash := fmt.Sprintf("%x", sha256.Sum256(plain))
	first, second := source(81), source(82)
	first.Firewall = "north-europe-production-firewall-with-a-deliberately-long-inventory-name.example.test"
	second.FirewallID, second.Firewall = 8, "Branch Berlin"
	first.Checksum, second.Checksum = hash, hash
	f := &sourceFixture{}
	f.set(first, second)
	e := testExtension(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx, e.done = ctx, make(chan struct{})
	workerStarted := false
	t.Cleanup(func() {
		cancel()
		if workerStarted {
			select {
			case <-e.done:
			case <-time.After(10 * time.Second):
				t.Error("synthetic report worker did not stop")
			}
		}
	})
	e.analyze, e.render, e.renderProfile = fortiosconfig.Analyze, nil, renderpdf.RenderWithProfile
	e.collectTelemetry = reportsBrowserTelemetry
	// These values only exercise readiness presentation. The collector above
	// is synthetic and no network request or external credential is used.
	e.cfg.GraylogURL, e.cfg.GraylogToken = "https://graylog.example.test", "synthetic-preview-token"
	e.readSource = func(ctx context.Context, fw, backup int) (reportmodel.Source, []byte, error) {
		if err := ctx.Err(); err != nil {
			return reportmodel.Source{}, nil, err
		}
		for _, s := range []reportmodel.Source{first, second} {
			if s.FirewallID == fw && s.BackupID == backup {
				return s, append([]byte(nil), plain...), nil
			}
		}
		return reportmodel.Source{}, nil, sql.ErrNoRows
	}
	profile := reportmodel.DefaultProfile("en")
	profile.Name, profile.Organization, profile.Customer = "Managed Europe review", "Example Services", "Example Customer"
	profile.Subtitle, profile.Intro = "{{report_title}} · {{customer}}", "Saved configuration {{backup_id}} and a separate observed log window. Synthetic review fixture."
	profile.Filters.VDOMs = []string{"root"}
	profile.Sections = []string{"policies", "interfaces", "logging"}
	profile.Charts = []string{"geo", "type", "priority", "outcome"}
	profile.Schedule = reportmodel.Schedule{Frequency: "weekly", Timezone: "Europe/Berlin", Hour: 3, Weekday: 1, MonthDay: 1}
	if err := e.saveProfile(ctx, first, profile, "", false); err != nil {
		t.Fatal(err)
	}
	branchProfile := reportmodel.DefaultProfile("de")
	branchProfile.Name, branchProfile.Customer, branchProfile.TimeRange = "Berliner Niederlassung", "Beispielkunde Berlin", "last7d"
	if err := e.saveProfile(ctx, second, branchProfile, "", false); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		e.generate(claim(t, e))
	}
	var ready int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM report_latest").Scan(&ready); err != nil || ready != 2 {
		t.Fatalf("synthetic report generation: count=%d error=%v", ready, err)
	}
	pending := source(83)
	pending.FirewallID, pending.Firewall, pending.Checksum = 9, "Unavailable source Frankfurt", hash
	f.set(first, second, pending)
	if err := e.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.pageBase = func(r *http.Request, title, active string) webui.BaseData {
		lang := "en"
		if cookie, err := r.Cookie("preview_language"); err == nil && cookie.Value == "de" {
			lang = "de"
		}
		return webui.BaseData{Title: title, Username: "Synthetic review", Active: active, Lang: lang,
			ReturnTo: r.URL.Path, CSRFToken: "synthetic-preview-token", Shell: webui.ShellText(lang),
			Navigation: webui.Navigation(webui.NavigationOptions{Lang: lang, Active: active, Reports: true})}
	}
	var err error
	for _, page := range []struct {
		name string
		into **webui.Renderer
	}{{"index", &e.page}, {"detail", &e.detailPage}, {"profile", &e.profilePage}, {"catalog", &e.catalogPage}, {"calendar", &e.calendarPage}} {
		*page.into, err = webui.ParsePage(assets, "templates/"+page.name+".html", template.FuncMap{"R": reportText})
		if err != nil {
			t.Fatal(err)
		}
	}
	static, err := fs.Sub(assets, "static")
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready")) })
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("../../internal/web/static"))))
	r.Get("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(": synthetic preview\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	})
	r.Post("/lang", func(w http.ResponseWriter, r *http.Request) {
		lang := "en"
		if r.FormValue("lang") == "de" {
			lang = "de"
		}
		http.SetCookie(w, &http.Cookie{Name: "preview_language", Value: lang, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/reports/", http.StatusSeeOther)
	})
	r.Route("/reports", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-Test-Role", "operator")
				next.ServeHTTP(w, r)
			})
		}, e.authorized)
		r.Get("/", e.index)
		r.Get("/catalog", e.catalog)
		r.Get("/calendar", e.calendar)
		r.Get("/{firewallID}", e.detail)
		r.Get("/{firewallID}/data", e.data)
		r.Get("/{firewallID}/{kind}.pdf", e.download)
		r.Get("/{firewallID}/{kind}.html", e.exportHTML)
		r.Get("/{firewallID}/{kind}.csv", e.exportCSV)
		r.Get("/{firewallID}/{kind}.json", e.exportJSON)
		r.Get("/{firewallID}/{kind}.xml", e.exportXML)
		r.Get("/{firewallID}/profile", e.profile)
		r.Post("/{firewallID}/profile", e.updateProfile)
		r.Get("/{firewallID}/profile.json", e.exportProfile)
		r.Post("/{firewallID}/profile/import", e.importProfile)
		r.Post("/{firewallID}/profile/copy", e.copyProfile)
		r.Post("/{firewallID}/profile/reset", e.resetProfile)
		r.Post("/{firewallID}/regenerate", e.regenerate)
		r.Handle("/static/*", http.StripPrefix("/reports/static/", http.FileServer(http.FS(static))))
	})
	stop := make(chan struct{})
	var once sync.Once
	r.Post("/__fixture/stop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		once.Do(func() { close(stop) })
	})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = server.Close() })
	workerStarted = true
	go e.run()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Printf("Reports browser fixture: http://%s/reports/\n", addr)
	select {
	case <-stop:
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Minute):
		t.Fatal("browser fixture timed out")
	}
}

func reportsBrowserTelemetry(ctx context.Context, source reportmodel.Source, _ reportmodel.Assessment, profile reportmodel.Profile, now time.Time) reportmodel.Telemetry {
	if ctx.Err() != nil {
		return reportmodel.Telemetry{Status: "error", Reason: "Synthetic collection canceled."}
	}
	duration := 24 * time.Hour
	switch profile.TimeRange {
	case "last7d":
		duration *= 7
	case "last30d":
		duration *= 30
	}
	end := now.UTC().Truncate(time.Millisecond)
	telemetry := reportmodel.Telemetry{Status: "partial", WindowStart: end.Add(-duration), WindowEnd: end, RetrievedAt: end,
		DeviceIdentity: source.Firewall, Sources: []string{"preview-edge-a", "preview-edge-b"},
		Reason: "Synthetic observations: some groups are bounded and some terminal-session records lack byte fields. Dataset totals overlap and must not be added together."}
	if !profile.Traffic {
		telemetry.Status, telemetry.Reason = "disabled", "Log observations are disabled in the captured profile."
		return telemetry
	}
	if source.FirewallID == 8 {
		telemetry.Status, telemetry.Reason, telemetry.Sources = "no_data", "No synthetic records match this source and window. This is not evidence of zero activity.", []string{"preview-berlin"}
		return telemetry
	}
	telemetry.Datasets = []reportmodel.TelemetryDataset{
		{ID: "traffic_actions", Title: "Forward traffic records by action", TitleDE: "Forward-Verkehrslogs nach Aktion", Status: "available", Total: 1250, Returned: 2, Limit: 20, Rows: []reportmodel.TelemetryRow{{Label: "accept", Count: 1000}, {Label: "deny", Count: 250}}},
		{ID: "applications", Title: "Applications in forward traffic records", TitleDE: "Anwendungen in Forward-Verkehrslogs", Status: "partial", Total: 1250, Returned: 20, Limit: 20, Truncated: true},
		{ID: "source_ips", Title: "Source addresses", TitleDE: "Quelladressen", Status: "available", Total: 1250, Returned: 2, Limit: 20, Rows: []reportmodel.TelemetryRow{{Label: "192.0.2.10", Count: 750}, {Label: "192.0.2.20", Count: 500}}},
		{ID: "destination_ips", Title: "Destination addresses", TitleDE: "Zieladressen", Status: "available", Total: 1250, Returned: 2, Limit: 20, Rows: []reportmodel.TelemetryRow{{Label: "203.0.113.20", Count: 900}, {Label: "203.0.113.21", Count: 350}}},
		{ID: "policies", Title: "Policies referenced by traffic", TitleDE: "Regelreferenzen im Verkehr", Status: "available", Total: 1250, Returned: 2, Limit: 20, Rows: []reportmodel.TelemetryRow{{Label: "root", Secondary: "20", Count: 1000}, {Label: "root", Secondary: "900", Count: 250}}},
		{ID: "security_events", Title: "Received UTM events", TitleDE: "Empfangene UTM-Ereignisse", Status: "available", Total: 15, Returned: 2, Limit: 20, Rows: []reportmodel.TelemetryRow{{Label: "ips", Secondary: "blocked", Count: 10}, {Label: "virus", Secondary: "blocked", Count: 5}}},
		{ID: "vpn_events", Title: "Received VPN events", TitleDE: "Empfangene VPN-Ereignisse", Status: "no_data", Reason: "No matching synthetic VPN records.", Limit: 20},
	}
	for i := range 20 {
		telemetry.Datasets[1].Rows = append(telemetry.Datasets[1].Rows, reportmodel.TelemetryRow{Label: fmt.Sprintf("Example application %02d", i+1), Count: 50})
	}
	telemetry.Datasets[1].Rows = append(telemetry.Datasets[1].Rows, reportmodel.TelemetryRow{Label: "Other / not returned", Count: 250})
	sent, received, combined := int64(200000), int64(3000000), int64(3200000)
	telemetry.Datasets = append(telemetry.Datasets, reportmodel.TelemetryDataset{ID: "reported_bytes", Title: "Reported terminal-session byte counters", TitleDE: "Gemeldete Bytezähler bei Sitzungsende", Status: "partial", Total: 100, Returned: 1, Limit: 1, MissingFields: []string{"sentbyte", "rcvdbyte"}, Reason: "Synthetic terminal-session counters are not unique transferred traffic, throughput, or billing evidence.", Rows: []reportmodel.TelemetryRow{{Label: "Reported terminal-session counters", Count: 90, Bytes: &combined, SentBytes: &sent, ReceivedBytes: &received}, {Label: "Missing required fields", Count: 10}}})
	trend := reportmodel.TelemetryDataset{ID: "traffic_trend", Title: "Received forward-traffic records over time", TitleDE: "Empfangene Forward-Verkehrslogs im Zeitverlauf", Status: "available", Total: 1250, Returned: 12, Limit: 12}
	step := duration / 12
	for i := range 12 {
		start := telemetry.WindowStart.Add(time.Duration(i) * step)
		count := int64(100)
		if i >= 10 {
			count = 125
		}
		trend.Rows = append(trend.Rows, reportmodel.TelemetryRow{Label: start.Format(time.RFC3339Nano), Secondary: start.Add(step).Format(time.RFC3339Nano), Timestamp: start, Count: count})
	}
	telemetry.Datasets = append(telemetry.Datasets, trend)
	return telemetry
}

const reportsBrowserConfig = `#config-version=FG100F-7.4.7-FW-build2731-241205:opmode=0:vdom=0
config system global
 set hostname "preview-edge"
end
config system interface
 edit "wan1"
  set ip 198.51.100.2 255.255.255.0
  set allowaccess ping https ssh
 next
 edit "dmz"
  set ip 10.10.20.1 255.255.255.0
 next
end
config firewall address
 edit "GeoCN"
  set type geography
  set country CN
 next
end
config firewall vip
 edit "Customer portal"
  set extip 203.0.113.20
  set mappedip "10.10.20.15"
  set extintf "wan1"
  set portforward enable
  set protocol tcp
  set extport 8443
  set mappedport 443
 next
 edit "LongUnbrokenVIPNameForResponsiveBoundaryValidation0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  set extip 203.0.113.21
  set mappedip "10.10.20.16"
  set extintf "wan1"
  set portforward enable
  set protocol tcp
  set extport 443
  set mappedport 443
 next
 edit "Application cluster"
  set type server-load-balance
  set extip 203.0.113.22
  set extintf "wan1"
  set server-type https
  set extport 443
  config realservers
   edit 1
    set ip 10.10.20.30
    set port 8443
   next
   edit 2
    set ip 10.10.20.31
    set port 8443
   next
  end
 next
end
config firewall policy
 edit 900
  set name "Geographic restriction"
  set srcintf "wan1"
  set dstintf "dmz"
  set action deny
  set srcaddr "GeoCN"
  set dstaddr "all"
  set schedule "always"
  set service "ALL"
  set match-vip enable
 next
 edit 20
  set name "Publish customer services"
  set srcintf "wan1"
  set dstintf "dmz"
  set action accept
  set srcaddr "all"
  set dstaddr "Customer portal" "LongUnbrokenVIPNameForResponsiveBoundaryValidation0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" "Application cluster"
  set schedule "always"
  set service "ALL"
  set logtraffic all
 next
end
`
