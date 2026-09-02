package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
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
	listenHost, _, err := net.SplitHostPort(options.Address)
	if err != nil {
		return nil, errors.New("invalid fixture listen address")
	}
	listenIP := net.ParseIP(listenHost)
	if listenIP == nil || !listenIP.IsLoopback() {
		return nil, errors.New("fixture listen address must be a literal loopback IP")
	}
	if options.DefaultScenario == "" {
		options.DefaultScenario = uxScenarioFull
	}
	if !validUXScenario(options.DefaultScenario) {
		return nil, errors.New("invalid default fixture scenario")
	}

	serverCtx, stopServer := context.WithCancel(ctx)
	webServer := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := webServer.parseTemplates(); err != nil {
		stopServer()
		return nil, err
	}
	extensionTemplates, err := loadUXExtensionTemplates()
	if err != nil {
		stopServer()
		return nil, err
	}
	handler := newUXFixtureHandler(webServer, extensionTemplates, options.DefaultScenario, stopServer)
	listener, err := net.Listen("tcp", options.Address)
	if err != nil {
		stopServer()
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
		defer stopServer()
		defer close(done)
		select {
		case err := <-serveDone:
			done <- err
		case <-serverCtx.Done():
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

func newUXFixtureHandler(webServer *Server, extensionTemplates *uxExtensionTemplates, defaultScenario uxScenario, stopServer context.CancelFunc) http.Handler {
	mux := http.NewServeMux()
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/__fixture/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "fixture shutdown is local-only", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go stopServer()
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		webServer.render(w, "dashboard.html", uxDashboardFixture(scenario))
	})
	mux.HandleFunc("/__ux/shell/de", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		data := uxDashboardFixture(scenario)
		data.Base = uxBaseLang("Dashboard", "dashboard", "de")
		webServer.render(w, "dashboard.html", data)
	})
	registerUXCoreRoutes(mux, webServer, defaultScenario)
	registerUXExtensionRoutes(mux, extensionTemplates, defaultScenario)
	return mux
}

type uxExtensionTemplates struct {
	root     string
	admVPN   *template.Template
	confGen  *template.Template
	polSplit *template.Template
	confConv *template.Template
	confTail *template.Template
}

func loadUXExtensionTemplates() (*uxExtensionTemplates, error) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("locate UX fixture source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	parse := func(relativePath string) (*template.Template, error) {
		return template.ParseFiles(filepath.Join(root, relativePath))
	}

	admVPN, err := parse("extensions/fgt_adm_vpn_conf/templates/fgt_adm_vpn_conf_index.html")
	if err != nil {
		return nil, err
	}
	confGen, err := parse("extensions/fgt_confgen/templates/fgt_confgen_index.html")
	if err != nil {
		return nil, err
	}
	polSplit, err := parse("extensions/fgt_polsplit/templates/fgt_polsplit_index.html")
	if err != nil {
		return nil, err
	}
	confConv, err := parse("extensions/fgt_confconv/templates/fgt_confconv_index.html")
	if err != nil {
		return nil, err
	}
	confTail, err := template.New("index.html").Funcs(template.FuncMap{
		"fmtTime":        uxFormatTemplateTime,
		"fmtMachineTime": uxFormatTemplateMachineTime,
		"fmtDuration":    uxFormatTemplateDuration,
	}).ParseGlob(filepath.Join(root, "extensions/fgt_conftail/templates/*.html"))
	if err != nil {
		return nil, err
	}
	return &uxExtensionTemplates{
		root: root, admVPN: admVPN, confGen: confGen, polSplit: polSplit,
		confConv: confConv, confTail: confTail,
	}, nil
}

func uxFormatTemplateTime(value any) string {
	if timestamp, ok := value.(time.Time); ok && !timestamp.IsZero() {
		return timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return "-"
}

func uxFormatTemplateMachineTime(value any) string {
	if timestamp, ok := value.(time.Time); ok && !timestamp.IsZero() {
		return timestamp.UTC().Format(time.RFC3339)
	}
	return ""
}

func uxFormatTemplateDuration(value any) string {
	if duration, ok := value.(time.Duration); ok {
		return duration.Round(time.Millisecond).String()
	}
	return "0s"
}

func registerUXExtensionRoutes(mux *http.ServeMux, templates *uxExtensionTemplates, defaultScenario uxScenario) {
	render := func(tmpl *template.Template, name string, data func(uxScenario) any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			scenario, ok := uxScenarioFromRequest(r, defaultScenario)
			if !ok {
				http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
				return
			}
			var output bytes.Buffer
			if err := tmpl.ExecuteTemplate(&output, name, data(scenario)); err != nil {
				http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = output.WriteTo(w)
		}
	}
	jsonResponse := func(payload string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, payload)
		}
	}
	serveStatic := func(prefix, relativeDirectory string) {
		directory := filepath.Join(templates.root, relativeDirectory)
		mux.Handle("GET "+prefix, http.StripPrefix(prefix, http.FileServer(http.Dir(directory))))
	}

	mux.HandleFunc("GET /fgt-adm-vpn-conf/{$}", render(templates.admVPN, "fgt_adm_vpn_conf_index.html", uxADMVPNFixture))
	mux.HandleFunc("GET /fgt-adm-vpn-conf/graylog_dsv", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "edge.example.test|203.0.113.7|synthetic-site\n")
	})
	mux.HandleFunc("GET /fgt-confgen/{$}", render(templates.confGen, "fgt_confgen_index.html", uxConfGenFixture))
	mux.HandleFunc("GET /fgt-confgen/list_firewalls", jsonResponse(`[{"id":7,"fqdn":"edge.example.test"}]`))
	mux.HandleFunc("GET /fgt-confgen/load_templates", jsonResponse(`{"templates":["Synthetic baseline"]}`))
	mux.HandleFunc("POST /fgt-confgen/log", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /fgt-polsplit/{$}", render(templates.polSplit, "fgt_polsplit_index.html", uxSimpleExtensionFixture))
	mux.HandleFunc("GET /fgt-polsplit/list_firewalls", jsonResponse(`[{"id":7,"fqdn":"edge.example.test"}]`))
	mux.HandleFunc("GET /fgt-polsplit/progress", jsonResponse(`{"state":"complete","progress":100}`))
	mux.HandleFunc("GET /fgt-confconv/{$}", render(templates.confConv, "fgt_confconv_index.html", uxSimpleExtensionFixture))
	mux.HandleFunc("GET /fgt-confconv/list_firewalls", jsonResponse(`[{"id":7,"fqdn":"edge.example.test"}]`))
	mux.HandleFunc("GET /fgt-confconv/config_summary", jsonResponse(`{"fqdn":"edge.example.test","version":"synthetic","interfaces":[]}`))
	mux.HandleFunc("GET /fgt-conftail/{$}", render(templates.confTail, "index.html", uxConfTailFixture))
	mux.HandleFunc("GET /fgt-conftail/status", jsonResponse(`{"running":false,"signature":"fixture"}`))
	mux.HandleFunc("GET /fgt-conftail/chain/{chainID}", render(templates.confTail, "chain.html", uxConfTailChainFixture))

	serveStatic("/fgt-confgen/static/", "extensions/fgt_confgen/static")
	serveStatic("/fgt-polsplit/static/", "extensions/fgt_polsplit/static")
	serveStatic("/fgt-confconv/static/", "extensions/fgt_confconv/static")
	serveStatic("/fgt-conftail/static/", "extensions/fgt_conftail/static")
}

func uxExtensionBase() map[string]any {
	return map[string]any{
		"Username": "reviewer", "ExtEnabled": true, "ExtAdmVPNEnabled": true,
		"ExtConfigGenEnabled": true, "ExtPolSplitEnabled": true,
		"ExtConfConvEnabled": true, "ExtConfTailEnabled": true,
	}
}

func uxADMVPNFixture(scenario uxScenario) any {
	configs := []any{}
	if scenario != uxScenarioEmpty {
		configs = append(configs, map[string]any{"ID": 7, "Firewallname": "edge.example.test"})
	}
	return map[string]any{
		"Base": uxExtensionBase(), "Configs": configs,
		"AvailableIPsCount": 42, "AvailableIPsPercentage": "84.0",
	}
}

func uxConfGenFixture(scenario uxScenario) any {
	data := uxSimpleExtensionFixture(scenario).(map[string]any)
	data["Templates"] = []string{"Synthetic baseline"}
	data["PreselectedTemplate"] = ""
	return data
}

func uxSimpleExtensionFixture(scenario uxScenario) any {
	firewalls := []any{}
	if scenario != uxScenarioEmpty {
		firewalls = append(firewalls, map[string]any{"ID": 7, "FQDN": "edge.example.test"})
	}
	return map[string]any{"Base": uxExtensionBase(), "Firewalls": firewalls}
}

func uxConfTailFixture(scenario uxScenario) any {
	health := map[string]any{"State": "healthy", "Label": "Healthy", "Detail": "Synthetic fixture data"}
	if scenario == uxScenarioWarning {
		health = map[string]any{"State": "warning", "Label": "Warning", "Detail": "Synthetic delayed poll", "Action": "Review collector"}
	}
	if scenario == uxScenarioError {
		health = map[string]any{"State": "failed", "Label": "Failed", "Detail": "Synthetic Graylog failure", "Action": "Retry poll"}
	}
	return map[string]any{
		"Base": uxExtensionBase(), "Health": health, "SessionHealth": health, "DeliveryHealth": health,
		"Dashboard": map[string]any{
			"Poll":   map[string]any{"LastStartedAt": uxFixtureNow.Add(-time.Minute), "LastSuccessAt": uxFixtureNow.Add(-time.Minute), "LastDuration": 250 * time.Millisecond, "Watermark": uxFixtureNow, "LastPages": 1, "LastFetched": 6, "LastInserted": 6},
			"Counts": map[string]any{}, "Active": []any{}, "ActiveTotal": 0,
			"History": []any{}, "HistoryTotal": 0, "TotalPages": 1,
		},
		"Filters": map[string]any{"State": "all", "Page": 1}, "NextPollRun": uxFixtureNow.Add(time.Minute),
		"PollRunning": scenario == uxScenarioLoading, "PollSignature": "fixture", "Coverage": []any{}, "Firewalls": []any{}, "Warnings": []string{},
	}
}

func uxConfTailChainFixture(uxScenario) any {
	return map[string]any{
		"Base": uxExtensionBase(), "Page": 1, "TotalPages": 1,
		"Chain": map[string]any{
			"ID": "fixture-chain", "FirewallID": 7, "FirewallName": "edge.example.test",
			"User": "synthetic-admin", "State": "sealed", "DeliveryState": "accepted",
			"FirstEventAt": uxFixtureNow.Add(-time.Minute), "LastEventAt": uxFixtureNow,
			"EventCount": 0, "VDOMs": []string{"root"}, "Events": []any{}, "AcceptedAt": uxFixtureNow,
		},
	}
}

func registerUXCoreRoutes(mux *http.ServeMux, webServer *Server, defaultScenario uxScenario) {
	render := func(name string, data func(uxScenario) any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			scenario, ok := uxScenarioFromRequest(r, defaultScenario)
			if !ok {
				http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
				return
			}
			webServer.render(w, name, data(scenario))
		}
	}
	jsonResponse := func(payload string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, payload)
		}
	}

	mux.HandleFunc("GET /login", render("login.html", func(uxScenario) any {
		return loginData{TOTPEnabled: true, RadiusEnabled: true}
	}))
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /{$}", render("index.html", uxFirewallFixture))
	mux.HandleFunc("GET /search", render("search.html", uxSearchFixture))
	mux.HandleFunc("POST /search", render("search.html", uxSearchFixture))
	mux.HandleFunc("GET /audit", render("audit.html", uxAuditFixture))
	mux.HandleFunc("GET /audit/results/{fwID}", jsonResponse(`{"status":"ok","score":73,"findings":[{"severity":"critical","text":"Synthetic administrative account has no MFA","remediation":"Enable two-factor authentication."}]}`))
	mux.HandleFunc("GET /licenses", render("licenses.html", func(scenario uxScenario) any {
		data := licensesData{Base: uxBase("Licenses", "licenses")}
		if scenario != uxScenarioEmpty {
			data.Unknown = 2
		}
		return data
	}))
	mux.HandleFunc("GET /licenses/status", jsonResponse(`{"running":false}`))
	mux.HandleFunc("GET /ipam", render("ipam.html", func(uxScenario) any {
		return ipamData{Base: uxBase("IPAM", "ipam")}
	}))
	mux.HandleFunc("GET /ipam/data", jsonResponse(`{"running":false,"snapshot":{"entries":[],"overlaps":[],"prefixes":0}}`))
	mux.HandleFunc("GET /topology", render("topology.html", uxTopologyFixture))
	mux.HandleFunc("GET /topology/data/{fwID}", jsonResponse(`{"fw_id":7,"fqdn":"edge.example.test","has_config":true,"model":"FortiGate-VM","interfaces":[]}`))
	mux.HandleFunc("GET /topology/shares", jsonResponse(`[]`))
	mux.HandleFunc("GET /graylog-devices/data/{fwID}", jsonResponse(`{"devices":[]}`))
	mux.HandleFunc("GET /topology/shared/{token}", render("topology_shared.html", func(uxScenario) any {
		return topologySharedPage{Token: "fixture-token", Lang: "en", IncludeDevices: true}
	}))
	mux.HandleFunc("GET /topology/shared/{token}/data", jsonResponse(`{"fw_id":7,"fqdn":"edge.example.test","has_config":true,"interfaces":[]}`))
	mux.HandleFunc("GET /topology/shared/{token}/devices", jsonResponse(`{"devices":[]}`))
	mux.HandleFunc("GET /activity_log", render("activity_log.html", uxActivityFixture))
	mux.HandleFunc("GET /errors", render("errors.html", uxErrorsFixture))
	mux.HandleFunc("GET /backups/{fwID}", render("backups.html", uxBackupsFixture))
	mux.HandleFunc("GET /change_password", render("change_password.html", func(uxScenario) any {
		return changePasswordData{Base: uxBase("Change password", "password")}
	}))
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = io.WriteString(w, "event: ping\ndata: {}\n\n")
	})
	mux.HandleFunc("GET /download/{filename}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="fixture.conf"`)
		_, _ = io.WriteString(w, "# synthetic FortiSafe UX fixture\n")
	})
	mux.HandleFunc("GET /dashboard/stats", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		payload := map[string]any{
			"total": 3, "healthy": 3, "failed": 0, "new": 0,
			"backups24h": 12, "totalBackups": 240, "storageBytes": 8 << 30,
			"storageWeek": 300 << 20, "largestBytes": 6 << 20, "smallestBytes": 900 << 10,
			"avgDuration": "4.8s", "backupsRun": 46, "prunedTotal": 0,
			"nextBackup":   uxFixtureNow.Add(10 * time.Minute).Format(time.RFC3339),
			"clusterAlert": "", "running": []runningView{}, "stale": []staleBackup{},
			"blockedPorts": []blockedPortIssue{}, "graylogIssues": []graylogIssue{},
			"dnsIssues": []dnsIssue{}, "licenseIssues": []licenseIssue{},
		}
		switch scenario {
		case uxScenarioEmpty:
			payload["total"] = 0
			payload["healthy"] = 0
			payload["backups24h"] = 0
		case uxScenarioWarning, uxScenarioError:
			payload["healthy"] = 2
			payload["failed"] = 1
		case uxScenarioLoading:
			payload["running"] = []runningView{{
				Kind: "backup", FwID: 7, FQDN: "edge.example.test",
				Detail: "Downloading synthetic configuration", Step: 2, Total: 4,
				SinceISO: uxFixtureNow.Add(-time.Minute).Format(time.RFC3339),
			}}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(payload)
	})
}

func uxBase(title, active string) BaseData {
	return uxBaseLang(title, active, "en")
}

func uxBaseLang(title, active, lang string) BaseData {
	returnTo := "/" + active
	if active == "firewalls" {
		returnTo = "/"
	}
	return BaseData{
		Title: title, Username: "reviewer", Lang: lang, Active: active, ReturnTo: returnTo,
		Shell: webui.ShellText(lang),
		Navigation: webui.Navigation(webui.NavigationOptions{
			Lang: lang, Active: active, AdmVPN: true, ConfGen: true, PolSplit: true, ConfConv: true, ConfTail: true,
		}),
		ExtEnabled: true, ExtFgtConfGenEnabled: true, ExtFgtPolSplitEnabled: true,
		ExtFgtConfConvEnabled: true, ExtFgtConfTailEnabled: true,
	}
}

func uxFirewalls() []models.Firewall {
	return []models.Firewall{
		{ID: 7, FQDN: "edge.example.test", Username: "backup", IntervalMin: 360, RetentionCount: 30, LastBackup: uxFixtureNow.Add(-20 * time.Minute), Status: "Success", SSHPort: 22},
		{ID: 12, FQDN: "branch.example.test", Username: "backup", IntervalMin: 60, RetentionCount: 14, LastBackup: uxFixtureNow.Add(-8 * time.Hour), Status: "Failed: synthetic connection timeout", SSHPort: 22},
	}
}

func uxFirewallFixture(scenario uxScenario) any {
	data := indexData{Base: uxBase("Firewalls", "firewalls")}
	if scenario != uxScenarioEmpty {
		data.Firewalls = uxFirewalls()
		data.NextRuns = map[int]time.Time{7: uxFixtureNow.Add(10 * time.Minute), 12: uxFixtureNow.Add(20 * time.Minute)}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic firewall inventory failure."
	}
	return data
}

func uxSearchFixture(scenario uxScenario) any {
	data := searchData{Base: uxBase("Search", "search"), Query: "config system admin"}
	if scenario != uxScenarioEmpty {
		data.Results = []searchResult{{FQDN: "edge.example.test", Filename: "edge.conf", Line: "config system admin"}}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic search failure."
	}
	return data
}

func uxAuditFixture(scenario uxScenario) any {
	data := auditData{Base: uxBase("Audit", "audit")}
	if scenario != uxScenarioEmpty {
		data.Firewalls = []models.FirewallRef{{ID: 7, FQDN: "edge.example.test"}, {ID: 12, FQDN: "branch.example.test"}}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic audit failure."
	}
	return data
}

func uxTopologyFixture(scenario uxScenario) any {
	data := topologyData{Base: uxBase("Topology", "topology")}
	if scenario != uxScenarioEmpty {
		data.Firewalls = []models.FirewallRef{{ID: 7, FQDN: "edge.example.test"}, {ID: 12, FQDN: "branch.example.test"}}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic topology failure."
	}
	return data
}

func uxActivityFixture(scenario uxScenario) any {
	data := activityLogData{Base: uxBase("Activity log", "activity"), Page: 1, TotalPages: 1}
	if scenario != uxScenarioEmpty {
		data.Logs = []models.ActivityLog{{Username: "reviewer", Action: "Backup completed", Details: "edge.example.test", Timestamp: uxFixtureNow}}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic activity-log failure."
	}
	return data
}

func uxErrorsFixture(scenario uxScenario) any {
	data := errorsData{Base: uxBase("Backup errors", "errors")}
	if scenario != uxScenarioEmpty {
		data.Errors = uxFirewalls()[1:]
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic backup-error query failure."
	}
	return data
}

func uxBackupsFixture(scenario uxScenario) any {
	data := backupsData{Base: uxBase("Backups", "firewalls"), FwID: 7}
	if scenario != uxScenarioEmpty {
		data.Backups = []models.Backup{{ID: 1, FwID: 7, Timestamp: uxFixtureNow, Filename: "edge_20260902.conf", SizeBytes: 214000}}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic backup-list failure."
	}
	return data
}

func uxScenarioFromRequest(r *http.Request, fallback uxScenario) (uxScenario, bool) {
	rawValue := strings.TrimSpace(r.URL.Query().Get("scenario"))
	if rawValue == "" && r.Referer() != "" {
		if refererURL, err := url.Parse(r.Referer()); err == nil {
			rawValue = strings.TrimSpace(refererURL.Query().Get("scenario"))
		}
	}
	value := uxScenario(rawValue)
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
		Base: uxBase("Dashboard", "dashboard"),
		Stats: models.DashboardStats{
			TotalFirewalls: 3,
			Healthy:        3,
			BackupsLast24h: 12,
			TotalBackups:   240,
		},
		StorageBytes: 8 << 30, StorageWeek: 300 << 20,
		LargestBytes: 6 << 20, SmallestBytes: 900 << 10,
		AvgDuration: "4.8s", BackupsRun: 46,
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

	shutdownRequest, err := http.NewRequest(http.MethodPost, fixture.URL()+"/__fixture/shutdown", nil)
	if err != nil {
		t.Fatalf("create fixture shutdown request: %v", err)
	}
	response, err = client.Do(shutdownRequest)
	if err != nil {
		t.Fatalf("POST /__fixture/shutdown: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /__fixture/shutdown status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
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

func TestUXFixtureRejectsNonLoopbackAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture, err := startUXFixture(ctx, uxFixtureOptions{Address: "0.0.0.0:0"})
	if err == nil {
		cancel()
		<-fixture.Done()
		t.Fatal("startUXFixture accepted a non-loopback listen address")
	}
}

func TestUXFixtureScenarios(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fixture, err := startUXFixture(ctx, uxFixtureOptions{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	client := &http.Client{Timeout: 2 * time.Second}

	tests := []struct {
		name       string
		path       string
		contains   string
		notContain string
	}{
		{name: "full inventory", path: "/?scenario=full", contains: "edge.example.test"},
		{name: "empty inventory", path: "/?scenario=empty", notContain: "edge.example.test"},
		{name: "inventory error", path: "/?scenario=error", contains: "Synthetic firewall inventory failure."},
		{name: "dashboard warning", path: "/dashboard?scenario=warning", contains: "synthetic connection timeout"},
		{name: "dashboard loading", path: "/dashboard/stats?scenario=loading", contains: "Downloading synthetic configuration"},
		{name: "extension full", path: "/fgt-confgen/?scenario=full", contains: "edge.example.test"},
		{name: "extension empty", path: "/fgt-confgen/?scenario=empty", notContain: "edge.example.test"},
		{name: "ConfTail warning", path: "/fgt-conftail/?scenario=warning", contains: "Synthetic delayed poll"},
		{name: "ConfTail error", path: "/fgt-conftail/?scenario=error", contains: "Synthetic Graylog failure"},
		{name: "ConfTail loading", path: "/fgt-conftail/?scenario=loading", contains: `data-poll-running="true"`},
		{name: "fixed clock", path: "/fgt-conftail/?scenario=full", contains: "2026-09-02T10:30:00Z"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := client.Get(fixture.URL() + test.path)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", test.path, response.StatusCode, http.StatusOK)
			}
			page := string(body)
			if test.contains != "" && !strings.Contains(page, test.contains) {
				t.Fatalf("GET %s did not contain %q", test.path, test.contains)
			}
			if test.notContain != "" && strings.Contains(page, test.notContain) {
				t.Fatalf("GET %s unexpectedly contained %q", test.path, test.notContain)
			}
		})
	}
}

type uxFixtureRoute struct {
	name        string
	method      string
	path        string
	wantStatus  int
	contentType string
}

func TestUXFixtureCoreRouteInventory(t *testing.T) {
	routes := []uxFixtureRoute{
		{name: "login page", method: http.MethodGet, path: "/login", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "login submit", method: http.MethodPost, path: "/login", wantStatus: http.StatusSeeOther},
		{name: "logout", method: http.MethodPost, path: "/logout", wantStatus: http.StatusSeeOther},
		{name: "firewalls", method: http.MethodGet, path: "/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "dashboard", method: http.MethodGet, path: "/dashboard", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "dashboard stats", method: http.MethodGet, path: "/dashboard/stats", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "search page", method: http.MethodGet, path: "/search", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "search submit", method: http.MethodPost, path: "/search", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "audit page", method: http.MethodGet, path: "/audit", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "audit results", method: http.MethodGet, path: "/audit/results/7", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "licenses page", method: http.MethodGet, path: "/licenses", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "license status", method: http.MethodGet, path: "/licenses/status", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "IPAM page", method: http.MethodGet, path: "/ipam", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "IPAM data", method: http.MethodGet, path: "/ipam/data", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "topology page", method: http.MethodGet, path: "/topology", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "topology data", method: http.MethodGet, path: "/topology/data/7", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "topology shares", method: http.MethodGet, path: "/topology/shares?fw_id=7", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "topology devices", method: http.MethodGet, path: "/graylog-devices/data/7", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "shared topology", method: http.MethodGet, path: "/topology/shared/fixture-token", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "shared topology data", method: http.MethodGet, path: "/topology/shared/fixture-token/data", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "shared topology devices", method: http.MethodGet, path: "/topology/shared/fixture-token/devices", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "activity log", method: http.MethodGet, path: "/activity_log", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "backup errors", method: http.MethodGet, path: "/errors", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "backups", method: http.MethodGet, path: "/backups/7", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "change password", method: http.MethodGet, path: "/change_password", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "SSE", method: http.MethodGet, path: "/events", wantStatus: http.StatusOK, contentType: "text/event-stream"},
		{name: "download", method: http.MethodGet, path: "/download/fixture.conf", wantStatus: http.StatusOK, contentType: "text/plain"},
	}
	testUXFixtureRoutes(t, routes)
}

func TestUXFixtureExtensionRouteInventory(t *testing.T) {
	routes := []uxFixtureRoute{
		{name: "ADM VPN", method: http.MethodGet, path: "/fgt-adm-vpn-conf/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ADM VPN status", method: http.MethodGet, path: "/fgt-adm-vpn-conf/graylog_dsv", wantStatus: http.StatusOK, contentType: "text/plain"},
		{name: "ConfGen", method: http.MethodGet, path: "/fgt-confgen/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ConfGen firewalls", method: http.MethodGet, path: "/fgt-confgen/list_firewalls", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen templates", method: http.MethodGet, path: "/fgt-confgen/load_templates", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen frontend log", method: http.MethodPost, path: "/fgt-confgen/log", wantStatus: http.StatusNoContent},
		{name: "Policy Split", method: http.MethodGet, path: "/fgt-polsplit/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "Policy Split firewalls", method: http.MethodGet, path: "/fgt-polsplit/list_firewalls", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Policy Split progress", method: http.MethodGet, path: "/fgt-polsplit/progress?id=fixture", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Config Converter", method: http.MethodGet, path: "/fgt-confconv/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "Config Converter firewalls", method: http.MethodGet, path: "/fgt-confconv/list_firewalls", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Config Converter summary", method: http.MethodGet, path: "/fgt-confconv/config_summary?fw_id=7", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfTail", method: http.MethodGet, path: "/fgt-conftail/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ConfTail status", method: http.MethodGet, path: "/fgt-conftail/status", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfTail chain", method: http.MethodGet, path: "/fgt-conftail/chain/fixture-chain", wantStatus: http.StatusOK, contentType: "text/html"},
	}
	testUXFixtureRoutes(t, routes)
}

func testUXFixtureRoutes(t *testing.T, routes []uxFixtureRoute) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture, err := startUXFixture(ctx, uxFixtureOptions{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			request, err := http.NewRequest(route.method, fixture.URL()+route.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("%s %s: %v", route.method, route.path, err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != route.wantStatus {
				t.Fatalf("%s %s status = %d, want %d", route.method, route.path, response.StatusCode, route.wantStatus)
			}
			if route.contentType != "" && !strings.HasPrefix(response.Header.Get("Content-Type"), route.contentType) {
				t.Fatalf("%s %s Content-Type = %q, want prefix %q", route.method, route.path, response.Header.Get("Content-Type"), route.contentType)
			}
		})
	}
}
