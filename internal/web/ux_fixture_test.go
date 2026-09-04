package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	appsecurity "github.com/arumes31/fortigate-scp-backup/internal/security"
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

const uxInteractionPage = `{{define "content"}}
<div class="page ui-primitives">
    <header class="page-header">
        <div><p class="eyebrow">Shared UI contract</p><h1>Interaction primitives</h1></div>
    </header>

    <section aria-labelledby="dialog-demo-heading">
        <h2 id="dialog-demo-heading">Confirmation dialog</h2>
        <p class="muted">Destructive actions require the exact resource name.</p>
        <button type="button" class="btn btn-danger" data-dialog-open="remove-firewall-dialog">Remove synthetic firewall</button>
        <dialog class="ui-dialog" id="remove-firewall-dialog" data-ui-dialog data-confirm-text="edge.example.test" aria-labelledby="remove-firewall-title">
            <div class="ui-dialog__body">
                <h2 id="remove-firewall-title">Confirm removal</h2>
                <p>This permanently removes <strong>edge.example.test</strong> from the synthetic fixture.</p>
                <label for="remove-firewall-confirmation">Type edge.example.test to confirm
                    <input id="remove-firewall-confirmation" type="text" autocomplete="off" data-confirm-input data-dialog-initial>
                </label>
                <div class="ui-dialog__actions">
                    <button type="button" class="btn btn-danger" data-confirm-action disabled>Remove firewall</button>
                    <button type="button" class="btn" data-dialog-close>Cancel</button>
                </div>
            </div>
        </dialog>
    </section>

    <section aria-labelledby="disclosure-demo-heading">
        <h2 id="disclosure-demo-heading">Progressive disclosure</h2>
        <details>
            <summary>Synthetic details</summary>
            <p>Secondary diagnostics remain available without competing with the primary task.</p>
        </details>
    </section>

    <section class="ui-tabs" aria-labelledby="tabs-demo-heading" data-tabs>
        <h2 id="tabs-demo-heading">Related views</h2>
        <div class="ui-tablist" role="tablist" aria-label="Synthetic record views">
            <button class="ui-tab" id="summary-tab" type="button" role="tab" aria-selected="true" aria-controls="summary-panel">Summary</button>
            <button class="ui-tab" id="raw-tab" type="button" role="tab" aria-selected="false" aria-controls="raw-panel" tabindex="-1">Raw data</button>
        </div>
        <div class="ui-tabpanel" id="summary-panel" role="tabpanel" aria-labelledby="summary-tab">Readable change summary.</div>
        <div class="ui-tabpanel" id="raw-panel" role="tabpanel" aria-labelledby="raw-tab" hidden>Raw synthetic configuration.</div>
    </section>

    <section aria-labelledby="copy-demo-heading">
        <h2 id="copy-demo-heading">Copy and feedback</h2>
        <div class="ui-copy-row">
            <code id="synthetic-copy-value">edge.example.test</code>
            <button type="button" class="btn button-with-icon" data-copy-target="synthetic-copy-value" data-copy-feedback="copy-result" data-copy-success="Copied" data-copy-error="Copy failed">
                <svg class="icon" aria-hidden="true"><use href="/static/icons.svg#copy"></use></svg>
                <span>Copy synthetic value</span>
            </button>
        </div>
        <span id="copy-result" aria-label="Copy result" data-feedback></span>
        <div class="feedback-examples" aria-label="Feedback examples">
            <p aria-label="Loading state" data-feedback="loading">Loading synthetic record…</p>
            <p aria-label="Success state" data-feedback="success">Synthetic record loaded.</p>
            <p aria-label="Warning state" data-feedback="warning">Synthetic record may be stale.</p>
            <p aria-label="Error state" data-feedback="error">Synthetic record could not be loaded.</p>
        </div>
    </section>

    <section aria-labelledby="time-demo-heading">
        <h2 id="time-demo-heading">Timestamp</h2>
        <time datetime="{{fmtMachineTime .Timestamp}}">{{fmtTime .Timestamp}}</time>
    </section>
</div>
{{end}}`

type uxInteractionData struct {
	Base      BaseData
	Timestamp time.Time
}

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
	interactionRenderer, err := webui.ParsePage(
		fstest.MapFS{"page.html": {Data: []byte(uxInteractionPage)}},
		"page.html",
		template.FuncMap{"fmtTime": fmtTime, "fmtMachineTime": fmtMachineTime},
	)
	if err != nil {
		panic(err)
	}
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
		webServer.render(w, "dashboard.html", uxLocalizedFixtureData(uxDashboardFixture(scenario), uxLanguageFromRequest(r)))
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
	mux.HandleFunc("GET /__ux/primitives", func(w http.ResponseWriter, _ *http.Request) {
		data := uxInteractionData{Base: uxBase("Interaction primitives", "dashboard"), Timestamp: uxFixtureNow}
		if err := interactionRenderer.RenderHTTP(w, data); err != nil {
			http.Error(w, "render interaction primitives", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("GET /__ux/error/{code}", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(r.PathValue("code"))
		if err != nil || (code != http.StatusNotFound && code != http.StatusInternalServerError) {
			http.Error(w, "unknown error fixture", http.StatusBadRequest)
			return
		}
		lang := uxLanguageFromRequest(r)
		title, message := errorPageCopy(lang, code)
		data := errorData{
			Base: uxBaseLang(title, "", lang), Code: code, Title: title, Message: message,
			RequestID: fmt.Sprintf("ux-request-%d", code), BackURL: "/dashboard",
		}
		if code == http.StatusInternalServerError {
			data.RetryURL = "/__ux/error/500"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		if err := webServer.pages["error.html"].render(w, data); err != nil {
			panic(err)
		}
	})
	registerUXCoreRoutes(mux, webServer, defaultScenario)
	registerUXExtensionRoutes(mux, extensionTemplates, defaultScenario)
	return mux
}

type uxExtensionTemplates struct {
	root          string
	admVPN        *webui.Renderer
	admVPNEdit    *template.Template
	confGen       *webui.Renderer
	polSplit      *webui.Renderer
	confConv      *webui.Renderer
	confTailIndex *webui.Renderer
	confTailChain *webui.Renderer
}

func loadUXExtensionTemplates() (*uxExtensionTemplates, error) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("locate UX fixture source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	admVPN, err := webui.ParsePage(
		os.DirFS(root),
		"extensions/fgt_adm_vpn_conf/templates/fgt_adm_vpn_conf_index.html",
		nil,
	)
	if err != nil {
		return nil, err
	}
	admVPNEdit, err := template.New("fgt_adm_vpn_conf_edit_form.html").Funcs(template.FuncMap{"L": webui.Localize}).ParseFiles(filepath.Join(root, "extensions/fgt_adm_vpn_conf/templates/fgt_adm_vpn_conf_edit_form.html"))
	if err != nil {
		return nil, err
	}
	confGen, err := webui.ParsePage(
		os.DirFS(root),
		"extensions/fgt_confgen/templates/fgt_confgen_index.html",
		nil,
	)
	if err != nil {
		return nil, err
	}
	polSplit, err := webui.ParsePage(
		os.DirFS(root),
		"extensions/fgt_polsplit/templates/fgt_polsplit_index.html",
		nil,
	)
	if err != nil {
		return nil, err
	}
	confConv, err := webui.ParsePage(
		os.DirFS(root),
		"extensions/fgt_confconv/templates/fgt_confconv_index.html",
		nil,
	)
	if err != nil {
		return nil, err
	}
	confTailFuncs := template.FuncMap{
		"fmtTime":            uxFormatTemplateTime,
		"fmtMachineTime":     uxFormatTemplateMachineTime,
		"fmtDuration":        uxFormatTemplateDuration,
		"fmtSessionDuration": uxFormatTemplateSessionDuration,
	}
	confTailIndex, err := webui.ParsePage(
		os.DirFS(root),
		"extensions/fgt_conftail/templates/index.html",
		confTailFuncs,
	)
	if err != nil {
		return nil, err
	}
	confTailChain, err := webui.ParsePage(
		os.DirFS(root),
		"extensions/fgt_conftail/templates/chain.html",
		confTailFuncs,
	)
	if err != nil {
		return nil, err
	}
	return &uxExtensionTemplates{
		root: root, admVPN: admVPN, admVPNEdit: admVPNEdit, confGen: confGen, polSplit: polSplit,
		confConv: confConv, confTailIndex: confTailIndex, confTailChain: confTailChain,
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

func uxFormatTemplateSessionDuration(startValue, endValue any) string {
	start, startOK := startValue.(time.Time)
	end, endOK := endValue.(time.Time)
	if !startOK || !endOK || start.IsZero() || end.IsZero() || end.Before(start) {
		return "-"
	}
	return end.Sub(start).Round(time.Second).String()
}

func registerUXExtensionRoutes(mux *http.ServeMux, templates *uxExtensionTemplates, defaultScenario uxScenario) {
	renderShared := func(renderer *webui.Renderer, data func(uxScenario) any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			scenario, ok := uxScenarioFromRequest(r, defaultScenario)
			if !ok {
				http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
				return
			}
			if err := renderer.RenderHTTP(w, uxLocalizedFixtureData(data(scenario), uxLanguageFromRequest(r))); err != nil {
				http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
			}
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

	mux.HandleFunc("GET /fgt-adm-vpn-conf/{$}", renderShared(templates.admVPN, uxADMVPNFixture))
	mux.HandleFunc("GET /fgt-adm-vpn-conf/edit/{id}", func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{
			"Lang": uxLanguageFromRequest(r),
			"ID":   7, "Firewallname": "edge.example.test", "Kundenname": "Synthetic customer", "Standort": "Vienna",
			"Cid": "101", "RemoteipFull": "10.105.1.7", "WanInterface": "wan1", "LanInterface": "loopback",
			"IpsecPskRo": "SENTINEL-STORED-RO-PSK-5e19", "IpsecPskHci": "SENTINEL-STORED-HCI-PSK-83d1",
			"Radiusmgt": "YES", "GraylogEnabled": true,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.admVPNEdit.ExecuteTemplate(w, "fgt_adm_vpn_conf_edit_form.html", data); err != nil {
			http.Error(w, "render edit form", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("GET /fgt-adm-vpn-conf/removal_commands/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "config vpn ipsec phase1-interface\n    delete edge.example.test\nend\n")
	})
	redirectADMVPN := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fgt-adm-vpn-conf/", http.StatusSeeOther)
	}
	mux.HandleFunc("POST /fgt-adm-vpn-conf/add", redirectADMVPN)
	mux.HandleFunc("POST /fgt-adm-vpn-conf/import", redirectADMVPN)
	mux.HandleFunc("POST /fgt-adm-vpn-conf/edit/{id}", redirectADMVPN)
	mux.HandleFunc("POST /fgt-adm-vpn-conf/delete/{id}", redirectADMVPN)
	mux.HandleFunc("POST /fgt-adm-vpn-conf/bulk/{operation}", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(64 << 10); err != nil {
			http.Error(w, "invalid selection", http.StatusBadRequest)
			return
		}
		ids := r.MultipartForm.Value["id"]
		if len(ids) == 0 || len(ids) > 100 {
			http.Error(w, "selection outside fixture bounds", http.StatusBadRequest)
			return
		}
		operation := r.PathValue("operation")
		failedIDs := []string{}
		if operation == "generate" && slices.Contains(ids, "8") {
			failedIDs = append(failedIDs, "8")
		}
		succeeded := len(ids) - len(failedIDs)
		w.Header().Set("X-FortiSafe-Bulk-Succeeded", strconv.Itoa(succeeded))
		w.Header().Set("X-FortiSafe-Bulk-Failed", strconv.Itoa(len(failedIDs)))
		w.Header().Set("X-FortiSafe-Bulk-Failed-IDs", strings.Join(failedIDs, ","))
		if operation == "export" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vpn_configs_%d_selected.csv"`, len(ids)))
			_, _ = io.WriteString(w, "id\r\n"+strings.Join(ids, "\r\n")+"\r\n")
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fgt_adm_configs_%d_selected.zip"`, len(ids)))
		_, _ = io.WriteString(w, "PK synthetic bulk fixture")
	})
	mux.HandleFunc("GET /fgt-adm-vpn-conf/generate_single/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "# synthetic generated configuration\n")
	})
	mux.HandleFunc("GET /fgt-adm-vpn-conf/export", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		_, _ = io.WriteString(w, "firewallname,cid\nedge.example.test,101\n")
	})
	mux.HandleFunc("GET /fgt-adm-vpn-conf/export_bookmarks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>Synthetic bookmarks</title>")
	})
	mux.HandleFunc("GET /fgt-adm-vpn-conf/graylog_dsv", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "edge.example.test|203.0.113.7|synthetic-site\n")
	})
	mux.HandleFunc("GET /fgt-confgen/{$}", renderShared(templates.confGen, uxConfGenFixture))
	mux.HandleFunc("GET /fgt-confgen/list_firewalls", jsonResponse(`[{"id":7,"fqdn":"edge.example.test"}]`))
	mux.HandleFunc("GET /fgt-confgen/load_templates", jsonResponse(`{"templates":["Synthetic baseline"]}`))
	mux.HandleFunc("GET /fgt-confgen/get_template/{templateName}", jsonResponse(`{
		"status":"success",
		"is_global":false,
		"data":{"policies":[{
			"policy_id":"fixture-policy","policy_name":"Synthetic allow","policy_comment":"Browser fixture",
			"src_interfaces":[],"dst_interfaces":[],"src_addresses":[],"src_address_groups":[],
			"src_internet_services":[],"src_vips":[],"dst_addresses":[],"dst_address_groups":[],
			"dst_internet_services":[],"dst_vips":[],"services":[],"action":"accept",
			"inspection_mode":"flow","ssl_ssh_profile":"","webfilter_profile":"","webfilter_enabled":false,
			"application_list":"","application_list_enabled":false,"av_profile":"","av_enabled":false,
			"ips_sensor":"","ips_sensor_enabled":false,"logtraffic":"all","logtraffic_start":"enable",
			"auto_asic_offload":"enable","nat":"disable","ip_pool":"","users":[],"groups":[]
		}]},
		"config":{"interfaces":[],"addresses":[],"address_groups":[],"internet_services":[],"vips":[],
			"ip_pools":[],"services":[],"service_groups":{},"ssl_ssh_profiles":[],"webfilter_profiles":[],
			"application_lists":[],"av_profiles":[],"ips_sensors":[],"users":[],"groups":[]}
	}`))
	mux.HandleFunc("POST /fgt-confgen/parse_config", jsonResponse(`{"interfaces":[],"addresses":[],"address_groups":[],"internet_services":[],"vips":[],"ip_pools":[],"services":[],"service_groups":{},"ssl_ssh_profiles":[],"webfilter_profiles":[],"application_lists":[],"av_profiles":[],"ips_sensors":[],"users":[],"groups":[]}`))
	mux.HandleFunc("POST /fgt-confgen/validate_policy", jsonResponse(`{"valid":true,"errors":[],"warnings":[{"code":"synthetic_review_warning","message":"Synthetic warning for browser coverage.","policy_id":"fixture-policy","policy_index":0}]}`))
	mux.HandleFunc("POST /fgt-confgen/generate_policy", jsonResponse(`{"outputs":[{"policy_id":"fixture-policy","policy_name":"Synthetic allow","output1":"config firewall policy\n    edit 1\nend","output2":"config firewall policy\n    edit 2\nend","output3":"config firewall policy\n    edit 3\nend"}],"validation":{"valid":true,"errors":[],"warnings":[]}}`))
	mux.HandleFunc("POST /fgt-confgen/log", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /fgt-polsplit/{$}", renderShared(templates.polSplit, uxPolSplitFixture))
	mux.HandleFunc("GET /fgt-polsplit/list_firewalls", jsonResponse(`[{"id":7,"fqdn":"edge.example.test"}]`))
	mux.HandleFunc("GET /fgt-polsplit/policy_info", jsonResponse(`{
		"firewall":{"id":7,"fqdn":"edge.example.test"},
		"policy":{"id":42,"name":"Synthetic open policy","vdom":"root","srcintf":["lan"],"dstintf":["wan1"],"srcaddr":["all"],"dstaddr":["all"],"services":["ALL"],"action":"accept","schedule":"always","nat":"enable","comments":"Synthetic fixture"},
		"action_display":"accept","backup_time":"2026-09-02 10:30","used_policy_id_count":1,"wan_bound":true,"warnings":[]
	}`))
	mux.HandleFunc("POST /fgt-polsplit/analyze", jsonResponse(`{
		"result_id":"00000000-0000-4000-8000-000000000035","warnings":[],"warning_count":0,"unresolved_count":0,"artifact_count":1,
		"total_messages":24,"tuple_count":1,"src_count":1,"dst_count":1,"svc_count":1,
		"panels":[{"key":"traffic","label":"Observed traffic","kind":"traffic","count":1},{"key":"per_service","label":"Per service","kind":"strategy","count":1,"recommended":true}]
	}`))
	mux.HandleFunc("GET /fgt-polsplit/results/{resultID}/panels/traffic", jsonResponse(`{"key":"traffic","kind":"traffic","data":{"tuples":[{"srcip":"10.0.0.10","dstip":"203.0.113.10","proto":"tcp","port":443,"service":"HTTPS","hits":24,"last_seen":"2026-09-02T10:30:00Z","flow":""}],"stale_tuples":[],"dns_suggestions":[],"isdb_suggestions":[],"user_activity":[],"app_usage":[],"utm_blocked":[]}}`))
	mux.HandleFunc("GET /fgt-polsplit/results/{resultID}/panels/per_service", jsonResponse(`{"key":"per_service","kind":"strategy","data":{"key":"per_service","label":"Per service","recommended":true,"policies":[{"id":100,"name":"PS42_HTTPS","tags":[],"src":[{"value":"10.0.0.10/32","is_net":false,"hosts":1}],"dst":[{"value":"203.0.113.10/32","is_net":false,"hosts":1}],"services":[{"key":"tcp/443","log_name":"HTTPS"}],"hits":24}],"new_objects":[],"config":"config firewall policy\n    edit 100\n        set name PS42_HTTPS\n    next\nend"}}`))
	mux.HandleFunc("GET /fgt-polsplit/results/{resultID}/export/{exportType}", func(w http.ResponseWriter, r *http.Request) {
		kind := r.PathValue("exportType")
		filename, contentType := "polsplit-policy-42-summary.json", "application/json"
		if kind == "traffic" {
			filename, contentType = "polsplit-policy-42-traffic.csv", "text/csv; charset=utf-8"
		} else if kind == "config" {
			filename, contentType = "polsplit-policy-42-"+r.URL.Query().Get("strategy")+".conf", "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, "synthetic "+kind+" export")
	})
	mux.HandleFunc("GET /fgt-polsplit/progress", jsonResponse(`{"state":"complete","progress":100}`))
	mux.HandleFunc("GET /fgt-confconv/{$}", renderShared(templates.confConv, uxConfConvFixture))
	mux.HandleFunc("GET /fgt-confconv/list_firewalls", jsonResponse(`[{"id":7,"fqdn":"edge.example.test"}]`))
	mux.HandleFunc("GET /fgt-confconv/config_summary", jsonResponse(`{
		"version":"7.6.1","versionOK":true,
		"interfaces":[
			{"name":"wan1","type":"physical","parent":"","vlanId":0,"ip":"203.0.113.2 255.255.255.0","allowaccess":"ping","role":"wan","members":[],"fortilink":false},
			{"name":"port1","type":"physical","parent":"","vlanId":0,"ip":"","allowaccess":"","role":"lan","members":[],"fortilink":false},
			{"name":"port2","type":"physical","parent":"","vlanId":0,"ip":"","allowaccess":"","role":"lan","members":[],"fortilink":false},
			{"name":"lan1","type":"physical","parent":"","vlanId":0,"ip":"10.0.0.1 255.255.255.0","allowaccess":"ping","role":"lan","members":[],"fortilink":false}
		],
		"zones":[],"sdwanZones":[{"name":"virtual-wan-link"}],
		"sdwanMembers":[{"seq":1,"interface":"wan1","gateway":"203.0.113.1","zone":"virtual-wan-link"}],
		"staticRoutes":[{"seq":1,"dst":"","device":"wan1","gateway":"203.0.113.1","disabled":false}],
		"backupTime":"2026-09-02T10:30:00Z"
	}`))
	mux.HandleFunc("POST /fgt-confconv/convert", jsonResponse(`{
		"sections":[{"recipe":"sdwan-routes-to-rules","label":"SD-WAN rules","lines":["config system sdwan","    config service","        edit 1","        next","    end","end"]}],
		"warnings":[],"appliedOrder":["sdwan-routes-to-rules"],
		"changes":[{"kind":"SD-WAN rule","name":"1","action":"create","summary":"Created SD-WAN rule."}],
		"changeCount":1,"changesTruncated":false,
		"combined":"config system sdwan\n    config service\n        edit 1\n        next\n    end\nend"
	}`))
	mux.HandleFunc("GET /fgt-conftail/{$}", renderShared(templates.confTailIndex, uxConfTailFixture))
	mux.HandleFunc("POST /fgt-conftail/{$}", renderShared(templates.confTailIndex, uxConfTailFixture))
	mux.HandleFunc("GET /fgt-conftail/status", jsonResponse(`{"running":false,"signature":"fixture"}`))
	mux.HandleFunc("GET /fgt-conftail/chain/{chainID}", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		view := strings.TrimSpace(r.URL.Query().Get("view"))
		if view != "transaction" && view != "object" {
			view = "chronological"
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page != 2 {
			page = 1
		}
		if err := templates.confTailChain.RenderHTTP(w, uxLocalizedFixtureData(uxConfTailChainFixture(scenario, view, page), uxLanguageFromRequest(r))); err != nil {
			http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("GET /fgt-conftail/chain/{chainID}/export/{format}", func(w http.ResponseWriter, r *http.Request) {
		format := r.PathValue("format")
		if format != "json" && format != "csv" {
			http.Error(w, "invalid export format", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="fortisafe-conftail-fixture-chain.`+format+`"`)
		if format == "json" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, `{"schema_version":1,"session":{"id":"fixture-chain","exported_count":0},"events":[]}`)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		_, _ = io.WriteString(w, "sequence,event_id,event_at\r\n")
	})
	mux.HandleFunc("POST /fgt-conftail/ignore-rules", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fgt-conftail/?ignore=created#ct-global-ignores", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /fgt-conftail/ignore-rules/{ruleID}/toggle", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fgt-conftail/?ignore=updated#ct-global-ignores", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /fgt-conftail/ignore-rules/{ruleID}/delete", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fgt-conftail/?ignore=deleted#ct-global-ignores", http.StatusSeeOther)
	})

	serveStatic("/fgt-confgen/static/", "extensions/fgt_confgen/static")
	serveStatic("/fgt-adm-vpn-conf/static/", "extensions/fgt_adm_vpn_conf/static")
	serveStatic("/fgt-polsplit/static/", "extensions/fgt_polsplit/static")
	serveStatic("/fgt-confconv/static/", "extensions/fgt_confconv/static")
	serveStatic("/fgt-conftail/static/", "extensions/fgt_conftail/static")
}

func uxADMVPNFixture(scenario uxScenario) any {
	configs := []any{}
	if scenario != uxScenarioEmpty {
		first := map[string]any{
			"ID": 7, "Firewallname": "edge.example.test", "Cid": "101", "Kundenname": "Synthetic customer",
			"Standort": "Vienna", "RemoteipFull": "10.105.1.7", "RemoteipFull1st": "10.150.11.7",
			"Ike2Username": "vpn-adm-synthetic-vienna", "WanInterface": "wan1", "LanInterface": "loopback", "Radiusmgt": "YES",
			"GraylogEnabled": true, "LastGraylogStatus": "online", "NextCheckISO": uxFixtureNow.Add(time.Minute).Format(time.RFC3339),
			"ClusterHostnames": "edge-a, edge-b", "DnsNameFull": "edge.example.test", "LastDnsStatus": "ok",
			"LastDnsResolved": "10.105.1.7", "HealthState": "healthy", "HealthLabel": "Checks pass",
			"HealthSummary": "Graylog online · DNS verified", "GraylogEvidence": "Graylog online", "DnsEvidence": "DNS verified",
			"LastCheckDisplay": "2026-09-02 10:29 UTC", "LastCheckISO": uxFixtureNow.Add(-time.Minute).Format(time.RFC3339),
			"LastGraylogDisplay": "2026-09-02 10:29 UTC", "LastGraylogISO": uxFixtureNow.Add(-time.Minute).Format(time.RFC3339),
			"LastDnsDisplay": "2026-09-02 10:28 UTC", "LastDnsISO": uxFixtureNow.Add(-2 * time.Minute).Format(time.RFC3339),
		}
		if scenario == uxScenarioError {
			first["LastGraylogStatus"] = "offline"
			first["LastDnsStatus"] = "mismatch"
			first["LastDnsResolved"] = "10.105.1.99"
			first["HealthState"] = "failed"
			first["HealthLabel"] = "Attention"
			first["HealthSummary"] = "Graylog offline · DNS mismatch"
			first["GraylogEvidence"] = "Graylog offline"
			first["DnsEvidence"] = "DNS mismatch"
		}
		configs = append(configs, first, map[string]any{
			"ID": 8, "Firewallname": "branch-with-an-intentionally-long-hostname.europe.example.test", "Cid": "102",
			"Kundenname": "Long-name fixture", "Standort": "Salzburg", "RemoteipFull": "10.105.1.8", "RemoteipFull1st": "10.150.11.8",
			"Ike2Username": "vpn-adm-long-name-salzburg", "WanInterface": "wan1", "LanInterface": "loopback", "Radiusmgt": "YES",
			"GraylogEnabled": true, "LastGraylogStatus": "online", "NextCheckISO": uxFixtureNow.Add(2 * time.Minute).Format(time.RFC3339),
			"DnsNameFull": "branch-with-an-intentionally-long-hostname.europe.example.test", "LastDnsStatus": "mismatch",
			"LastDnsResolved": "10.105.1.88", "HealthState": "failed", "HealthLabel": "Attention",
			"HealthSummary": "Graylog online · DNS mismatch", "GraylogEvidence": "Graylog online", "DnsEvidence": "DNS mismatch",
			"LastCheckDisplay": "2026-09-02 10:28 UTC", "LastCheckISO": uxFixtureNow.Add(-2 * time.Minute).Format(time.RFC3339),
			"LastGraylogDisplay": "2026-09-02 10:28 UTC", "LastGraylogISO": uxFixtureNow.Add(-2 * time.Minute).Format(time.RFC3339),
			"LastDnsDisplay": "2026-09-02 10:27 UTC", "LastDnsISO": uxFixtureNow.Add(-3 * time.Minute).Format(time.RFC3339),
		})
		if scenario == uxScenarioLoading {
			for id := 9; id <= 107; id++ {
				configs = append(configs, map[string]any{
					"ID": id, "Firewallname": fmt.Sprintf("bulk-%03d.example.test", id), "Cid": strconv.Itoa(1000 + id),
					"Kundenname": "Bulk fixture", "Standort": "Vienna", "RemoteipFull": fmt.Sprintf("10.105.1.%d", (id%240)+10),
					"RemoteipFull1st": fmt.Sprintf("10.150.11.%d", (id%240)+10), "Ike2Username": fmt.Sprintf("vpn-adm-bulk-%03d", id),
					"WanInterface": "wan1", "LanInterface": "loopback", "Radiusmgt": "YES", "GraylogEnabled": true,
					"LastGraylogStatus": "online", "LastDnsStatus": "ok", "DnsNameFull": fmt.Sprintf("bulk-%03d.example.test", id),
					"LastDnsResolved": fmt.Sprintf("10.105.1.%d", (id%240)+10), "HealthState": "healthy", "HealthLabel": "Checks pass",
					"HealthSummary": "Graylog online · DNS verified", "GraylogEvidence": "Graylog online", "DnsEvidence": "DNS verified",
					"LastCheckDisplay": "2026-09-02 10:29 UTC", "LastCheckISO": uxFixtureNow.Add(-time.Minute).Format(time.RFC3339),
				})
			}
		}
	}
	return map[string]any{
		"Base": uxBase("FGT ADM VPN Config", "admvpn"), "Configs": configs,
		"AvailableIPsCount": 42, "AvailableIPsPercentage": "84.0",
	}
}

func uxConfGenFixture(scenario uxScenario) any {
	firewalls := []any{}
	if scenario != uxScenarioEmpty {
		firewalls = append(firewalls, map[string]any{"ID": 7, "FQDN": "edge.example.test"})
	}
	return map[string]any{
		"Base": uxBase("Policy Generator", "configgen"), "Firewalls": firewalls,
		"Templates": []string{"Synthetic baseline"}, "PreselectedTemplate": "",
	}
}

func uxPolSplitFixture(scenario uxScenario) any {
	firewalls := []any{}
	if scenario != uxScenarioEmpty {
		firewalls = append(firewalls, map[string]any{"ID": 7, "FQDN": "edge.example.test"})
	}
	return map[string]any{"Base": uxBase("Policy Split Advisor", "polsplit"), "Firewalls": firewalls}
}

func uxConfConvFixture(scenario uxScenario) any {
	firewalls := []any{}
	if scenario != uxScenarioEmpty {
		firewalls = append(firewalls, map[string]any{"ID": 7, "FQDN": "edge.example.test"})
	}
	return map[string]any{"Base": uxBase("Configuration Conversions", "confconv"), "Firewalls": firewalls}
}

func uxConfTailFixture(scenario uxScenario) any {
	health := map[string]any{
		"State": "healthy", "Label": "Healthy", "Detail": "Synthetic fixture data",
		"Evidence": "1 page / 6 fetched / 6 inserted", "CheckedAt": uxFixtureNow,
	}
	if scenario == uxScenarioWarning {
		health = map[string]any{
			"State": "warning", "Label": "Warning", "Detail": "Synthetic delayed poll",
			"Evidence": "1 page / 6 fetched / 6 inserted", "CheckedAt": uxFixtureNow,
			"Action": "Review collector",
		}
	}
	if scenario == uxScenarioError {
		health = map[string]any{
			"State": "failed", "Label": "Failed",
			"Detail":   "Synthetic Graylog failure: an intentionally long unbroken diagnostic-value-that-must-wrap-without-expanding-the-health-card-beyond-the-desktop-content-region",
			"Evidence": "0 pages / 0 fetched / 0 inserted", "CheckedAt": uxFixtureNow,
			"Action": "Retry poll",
		}
	}
	return map[string]any{
		"Base": uxBase("Configuration Change Tail", "conftail"), "Health": health, "SessionHealth": health, "DeliveryHealth": health,
		"Dashboard": map[string]any{
			"Poll":   map[string]any{"LastStartedAt": uxFixtureNow.Add(-time.Minute), "LastSuccessAt": uxFixtureNow.Add(-time.Minute), "LastDuration": 250 * time.Millisecond, "Watermark": uxFixtureNow, "LastPages": 1, "LastFetched": 6, "LastInserted": 6},
			"Counts": map[string]any{}, "Active": []any{}, "ActiveTotal": 0,
			"History": []any{}, "HistoryTotal": 0, "TotalPages": 1,
		},
		"Filters": map[string]any{"State": "all", "Page": 1}, "NextPollRun": uxFixtureNow.Add(time.Minute),
		"ActiveFilters": []any{map[string]any{
			"Label": "Source", "Value": "branch-source.example.test",
			"Fields": []any{
				map[string]any{"Name": "firewall", "Value": "7"},
				map[string]any{"Name": "user", "Value": "body-only-operator"},
			},
		}},
		"HasNext": true,
		"NextFields": []any{
			map[string]any{"Name": "firewall", "Value": "7"},
			map[string]any{"Name": "user", "Value": "body-only-operator"},
			map[string]any{"Name": "page", "Value": "2"},
		},
		"PollRunning": scenario == uxScenarioLoading, "PollSignature": "fixture", "CoverageEnabled": true,
		"Coverage": []any{}, "Firewalls": []any{}, "Warnings": []string{},
		"IgnoreRules": []any{map[string]any{
			"ID": 17, "Kind": "operation", "DisplayValue": "Edit system.central-management",
			"Enabled": true, "CreatedBy": "fixture-operator", "CreatedAt": uxFixtureNow.Add(-time.Hour),
		}},
	}
}

func uxConfTailChainFixture(scenario uxScenario, view string, page int) any {
	firstPage := []any{
		map[string]any{
			"ID": 41, "Sequence": 1, "EventAt": uxFixtureNow.Add(-4 * time.Minute), "Source": "FGT-SITE-A", "VDOM": "root",
			"UserAttribution": "exact", "Action": "Edit", "TransactionID": "82378752",
			"Path": "system.central-management", "Object": "-",
			"ConfigAttribute": `type[fortimanager->fortimanager]fmg["manager.example.test"->"manager.example.test"]serial-number["FMGVMTEST00000001"->"FMGVMTEST00000001"]`,
			"LogID":           "0100044546", "LogDescription": "Attribute configured",
		},
		map[string]any{
			"ID": 42, "Sequence": 2, "EventAt": uxFixtureNow.Add(-3 * time.Minute), "Source": "FGT-SITE-A", "VDOM": "root",
			"UserAttribution": "exact", "Action": "Edit", "TransactionID": "82378753",
			"Path": "firewall.policy", "Object": "17", "ConfigAttribute": "comments[before->after]",
			"LogID": "0100044547", "LogDescription": "Attribute configured",
		},
		map[string]any{
			"ID": 43, "Sequence": 3, "EventAt": uxFixtureNow.Add(-2 * time.Minute), "Source": "FGT-SITE-A", "VDOM": "root",
			"UserAttribution": "exact", "Action": "Edit", "TransactionID": "82378752",
			"Path": "system.central-management", "Object": "-", "ConfigAttribute": strings.Repeat("long-redacted-value-", 32),
			"LogID": "0100044546", "LogDescription": "Attribute configured",
		},
	}
	secondPage := []any{
		map[string]any{
			"ID": 141, "Sequence": 101, "EventAt": uxFixtureNow.Add(-time.Minute), "Source": "FGT-SITE-A", "VDOM": "root",
			"UserAttribution": "exact", "Action": "Edit", "TransactionID": "82378752",
			"Path": "system.central-management", "Object": "-", "ConfigAttribute": "type[normal->fortimanager]",
			"LogID": "0100044546", "LogDescription": "Attribute configured",
		},
		map[string]any{
			"ID": 142, "Sequence": 102, "EventAt": uxFixtureNow, "Source": "FGT-SITE-A", "VDOM": "root",
			"UserAttribution": "exact", "Action": "Delete", "Path": "router.static", "Object": "7",
			"LogID": "0100044545", "LogDescription": "Object deleted",
		},
	}
	events := firstPage
	if page == 2 {
		events = secondPage
	}
	groups := []any{}
	if view == "transaction" {
		if page == 1 {
			groups = []any{
				map[string]any{"Label": "Transaction 82378752", "Events": []any{firstPage[0], firstPage[2]}},
				map[string]any{"Label": "Transaction 82378753", "Events": []any{firstPage[1]}},
			}
		} else {
			groups = []any{
				map[string]any{"Label": "Transaction 82378752", "Events": []any{secondPage[0]}},
				map[string]any{"Label": "Without transaction ID", "Events": []any{secondPage[1]}},
			}
		}
	}
	if view == "object" {
		if page == 1 {
			groups = []any{
				map[string]any{"Label": "system.central-management", "Events": []any{firstPage[0], firstPage[2]}},
				map[string]any{"Label": "firewall.policy / 17", "Events": []any{firstPage[1]}},
			}
		} else {
			groups = []any{
				map[string]any{"Label": "system.central-management", "Events": []any{secondPage[0]}},
				map[string]any{"Label": "router.static / 7", "Events": []any{secondPage[1]}},
			}
		}
	}
	state := "sealed"
	deliveryState := "accepted"
	delivery := map[string]any{
		"State": "accepted", "Label": "Accepted by Hookwise", "Detail": "Hookwise accepted the immutable ticket payload.",
		"Attempts": 1, "AcceptedAt": uxFixtureNow, "RequestID": "https://tickets.example.test/ticket/123",
		"TicketURL": "https://tickets.example.test/ticket/123",
	}
	if scenario == uxScenarioWarning {
		deliveryState = "pending"
		delivery = map[string]any{"State": "pending", "Label": "Queued", "Detail": "The immutable ticket is waiting for delivery.", "Attempts": 0, "NextAt": uxFixtureNow.Add(time.Minute)}
	}
	if scenario == uxScenarioError {
		deliveryState = "failed"
		delivery = map[string]any{
			"State": "failed", "Label": "Delivery failed", "Detail": "Automatic delivery stopped after a non-retryable failure.",
			"Attempts": 3, "LastError": "Synthetic classified failure " + strings.Repeat("diagnostic-value-", 24),
			"Action": "Check Hookwise authentication, endpoint configuration, and application logs.",
		}
	}
	if scenario == uxScenarioLoading {
		state = "active"
		deliveryState = ""
		delivery = map[string]any{"State": "waiting", "Label": "Not queued", "Detail": "This session is still collecting changes.", "Attempts": 0}
	}
	if scenario == uxScenarioEmpty {
		deliveryState = ""
		delivery = map[string]any{
			"State": "waiting", "Label": "No delivery record", "Detail": "No Hookwise delivery record is available for this sealed session.",
			"Action": "Check the sealing worker and application logs.",
		}
	}
	chainID := "fixture-chain"
	viewURL := func(targetView string, targetPage int) string {
		values := url.Values{}
		if targetPage > 1 {
			values.Set("page", strconv.Itoa(targetPage))
		}
		if targetView != "chronological" {
			values.Set("view", targetView)
		}
		path := "/fgt-conftail/chain/" + chainID
		if len(values) > 0 {
			path += "?" + values.Encode()
		}
		return path
	}
	chain := map[string]any{
		"ID": chainID, "FirewallID": 7, "FirewallName": "edge.example.test",
		"User": "synthetic-admin", "State": state, "DeliveryState": deliveryState,
		"FirstEventAt": uxFixtureNow.Add(-4 * time.Minute), "LastEventAt": uxFixtureNow,
		"EventCount": 102, "VDOMs": []string{"root"}, "Events": events,
	}
	if scenario != uxScenarioLoading && scenario != uxScenarioEmpty {
		chain["TicketPreview"] = map[string]any{
			"Summary":     "[FortiSafe ID 7 · CT-fixture] edge.example.test / synthetic-admin / 102 changes",
			"Description": "FortiGate configuration change session\n\nFirewall: edge.example.test (FortiSafe ID 7)\nAdministrator: synthetic-admin\n\nAffected objects:\n* system.central-management\n* firewall.policy / 17\n\nChange excerpts (oldest first):\n- 2026-09-02T10:26:00Z | Edit | system.central-management\n",
		}
	}
	data := map[string]any{
		"Base": uxBase("Configuration Change Session", "conftail"), "Page": page, "TotalPages": 2,
		"Chain": chain, "Delivery": delivery, "EventGroups": groups, "View": view,
		"ChronologicalURL": viewURL("chronological", page), "TransactionURL": viewURL("transaction", page), "ObjectURL": viewURL("object", page),
	}
	if page == 1 {
		data["NextURL"] = viewURL(view, 2)
	} else {
		data["PrevURL"] = viewURL(view, 1)
	}
	return data
}

func ipamDataOutFixture(snapshot ipamSnapshot) map[string]any {
	return map[string]any{
		"running": false, "computed_at": uxFixtureNow.Format(time.RFC3339), "snapshot": snapshot,
	}
}

func uxIPAMSnapshotFixture() ipamSnapshot {
	entries := []ipamEntry{
		{Prefix: "10.10.0.0/16", FwID: 7, FQDN: "edge.example.test", VDOM: "root", Source: "interface", Name: `=HYPERLINK("https://example.invalid","open")`},
		{Prefix: "10.10.10.0/24", FwID: 12, FQDN: "branch.example.test", VDOM: "tenant-a", Source: "route", Name: "route 1 via port2"},
		{Prefix: "172.16.20.0/24", FwID: 12, FQDN: "branch.example.test", VDOM: "root", Source: "dhcp", Name: "lan (172.16.20.10-172.16.20.200)"},
	}
	for i := 0; i < 1202; i++ {
		entries = append(entries, ipamEntry{
			Prefix: fmt.Sprintf("192.0.%d.%d/32", i/256, i%256), FwID: 19,
			FQDN: "lab.example.test", VDOM: "lab", Source: "address", Name: fmt.Sprintf("fixture-host-%04d", i),
		})
	}
	overlaps := []ipamOverlap{{
		Kind: "containment", Prefix: "10.10.0.0/16", Inner: "10.10.10.0/24", Count: 2,
		Firewalls: []string{"edge.example.test (=HYPERLINK)", "branch.example.test (route 1 via port2)"},
	}}
	for i := 0; i < 501; i++ {
		overlaps = append(overlaps, ipamOverlap{
			Kind: "duplicate", Prefix: fmt.Sprintf("198.18.%d.%d/32", i/256, i%256), Count: 2,
			Firewalls: []string{"fixture-a.example.test", "fixture-b.example.test"},
		})
	}
	return ipamSnapshot{Firewalls: 3, Scanned: 3, Prefixes: len(entries), Entries: entries, Overlaps: overlaps}
}

func registerUXCoreRoutes(mux *http.ServeMux, webServer *Server, defaultScenario uxScenario) {
	render := func(name string, data func(uxScenario) any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			scenario, ok := uxScenarioFromRequest(r, defaultScenario)
			if !ok {
				http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
				return
			}
			webServer.render(w, name, uxLocalizedFixtureData(data(scenario), uxLanguageFromRequest(r)))
		}
	}
	jsonResponse := func(payload string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, payload)
		}
	}

	mux.HandleFunc("GET /login", render("login.html", func(uxScenario) any {
		return loginData{Lang: "en", TOTPEnabled: true, RadiusEnabled: true}
	}))
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /{$}", render("index.html", uxFirewallFixture))
	mux.HandleFunc("GET /search", render("search.html", uxSearchFixture))
	mux.HandleFunc("POST /search", func(w http.ResponseWriter, r *http.Request) {
		data := uxSearchFixture(uxScenarioFull).(searchData)
		if query := r.FormValue("query"); query != "" {
			data.Query = query
			line := query + ` "<sentinel-config>"`
			data.Results = []searchResult{{
				FQDN: "edge.example.test", Filename: "edge.conf", Line: line,
				Segments: []searchSegment{{Text: query, Match: true}, {Text: ` "<sentinel-config>"`}},
			}}
		}
		webServer.render(w, "search.html", uxLocalizedFixtureData(data, uxLanguageFromRequest(r)))
	})
	mux.HandleFunc("GET /audit", render("audit.html", uxAuditFixture))
	mux.HandleFunc("GET /audit/results/{fwID}", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		if scenario == uxScenarioError && r.PathValue("fwID") == "12" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, `{`)
			return
		}
		payload := map[string]any{
			"has_config": true, "model": "FortiGate 100F", "version": "7.4.5",
			"backup_filename": "fixture.conf", "computed_at": uxFixtureNow.Format(time.RFC3339),
			"pci_score": 92, "cis_score": 88, "hipaa_score": 90,
			"findings": []map[string]any{}, "exempted": []map[string]any{}, "upgrade_path": []string{"7.4.6"},
			"ticket_id": "", "ticket_detail": "",
		}
		if r.PathValue("fwID") == "7" {
			payload["pci_score"], payload["cis_score"], payload["hipaa_score"] = 48, 42, 51
			payload["findings"] = []map[string]any{{
				"key": "fixture-high", "severity": "high", "text": "Synthetic administrative account has no MFA",
				"remediation": "Enable two-factor authentication.", "context": "config system admin", "context_start": 1, "line": 1,
			}}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(payload)
	})
	mux.HandleFunc("GET /licenses", render("licenses.html", func(scenario uxScenario) any {
		data := licensesData{Base: uxBase("Licenses", "licenses")}
		if scenario != uxScenarioEmpty {
			fetched := uxFixtureNow.Add(-30 * time.Minute)
			data.Rows = []licenseRow{
				{FwID: 7, FQDN: "edge.example.test", Hostname: "EDGE-FGT", Serial: "FGT-EDGE-001", Model: "FortiGate 100F", Version: "7.4.5", FetchedAt: fetched, Expiry: "2026-09-18", DaysLeft: 16, Level: "warn", Entitlements: []licenseEntitlement{{Service: "FortiGuard IPS", Expiry: "2026-09-18", Result: "Updates Installed"}}},
				{FwID: 12, FQDN: "branch.example.test", Hostname: "BRANCH-FGT", Serial: "FGT-BRANCH-012", Model: "FortiGate 80F", Version: "7.2.9", FetchedAt: fetched.Add(-time.Hour), Expiry: "2026-08-20", DaysLeft: -13, Level: "expired", Devices: []licenseDevice{{Kind: "switch", Name: "BRANCH-SW01", Serial: "CHILD-EXPIRED-001", Model: "FortiSwitch 108F", Version: "7.4.4", Status: "online"}}, Switches: 1},
				{FwID: 19, FQDN: "lab.example.test", Hostname: "LAB-FGT", Model: "FortiGate VM", Level: "unknown", FetchError: "Synthetic collection failure"},
			}
			data.Expiring, data.Expired, data.Unknown, data.LastFetchedAt = 1, 1, 1, fetched
		}
		return data
	}))
	mux.HandleFunc("GET /licenses/status", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch scenario {
		case uxScenarioLoading:
			_, _ = io.WriteString(w, `{"running":true,"done":1,"total":3,"current":"branch.example.test"}`)
		case uxScenarioError:
			_, _ = io.WriteString(w, `{`)
		default:
			_, _ = io.WriteString(w, `{"running":false}`)
		}
	})
	mux.HandleFunc("GET /ipam", render("ipam.html", func(uxScenario) any {
		return ipamData{Base: uxBase("IPAM", "ipam")}
	}))
	mux.HandleFunc("GET /ipam/data", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch scenario {
		case uxScenarioLoading:
			_, _ = io.WriteString(w, `{"running":true,"done":1,"total":3,"current":"branch.example.test"}`)
		case uxScenarioError:
			_, _ = io.WriteString(w, `{`)
		case uxScenarioEmpty:
			_ = json.NewEncoder(w).Encode(ipamDataOutFixture(ipamSnapshot{}))
		default:
			_ = json.NewEncoder(w).Encode(ipamDataOutFixture(uxIPAMSnapshotFixture()))
		}
	})
	mux.HandleFunc("POST /ipam/refresh", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	mux.HandleFunc("GET /topology", render("topology.html", uxTopologyFixture))
	mux.HandleFunc("GET /topology/data/{fwID}", jsonResponse(`{"fw_id":7,"fqdn":"edge.example.test","has_config":true,"model":"FortiGate-VM","interfaces":[]}`))
	mux.HandleFunc("GET /topology/shares", jsonResponse(`[]`))
	mux.HandleFunc("GET /graylog-devices/data/{fwID}", jsonResponse(`{"devices":[]}`))
	mux.HandleFunc("GET /topology/shared/{token}", func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if token == "expired-token" || token == "revoked-token" || token == "invalid-token" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		data := topologySharedPage{Token: token, Lang: uxLanguageFromRequest(r)}
		if token == "fixture-token" {
			data.IncludeDevices = true
			data.ExpiresAt = uxFixtureNow.Add(7 * 24 * time.Hour)
		} else {
			data.NeverExpires = true
		}
		webServer.render(w, "topology_shared.html", data)
	})
	mux.HandleFunc("GET /topology/shared/{token}/data", jsonResponse(`{"fw_id":7,"fqdn":"edge.example.test","has_config":true,"interfaces":[]}`))
	mux.HandleFunc("GET /topology/shared/{token}/devices", jsonResponse(`{"devices":[]}`))
	mux.HandleFunc("GET /activity_log", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		data := uxActivityFixture(scenario)
		data.Filters = activityLogFilterView{
			Query: r.URL.Query().Get("q"), User: r.URL.Query().Get("user"), Action: r.URL.Query().Get("action"),
			From: r.URL.Query().Get("from"), To: r.URL.Query().Get("to"),
		}
		data.HasFilters = data.Filters.hasFilters()
		if data.Filters.Query == "deep-synthetic-match" {
			data.Logs = []models.ActivityLog{{
				Username: "automation", Action: "Configuration Change",
				Details: "Synthetic match originally beyond the first 100 rows", Timestamp: uxFixtureNow,
			}}
			data.Total, data.TotalPages = 101, 2
		} else if data.Filters.Query == "no-match" {
			data.Logs, data.Total, data.TotalPages = nil, 0, 1
		}
		if page, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && page > 0 {
			data.Page = min(page, data.TotalPages)
		}
		if data.Page > 1 {
			data.PrevURL = activityLogPageURL(data.Filters, data.Page-1)
		}
		if data.Page < data.TotalPages {
			data.NextURL = activityLogPageURL(data.Filters, data.Page+1)
		}
		webServer.render(w, "activity_log.html", uxLocalizedFixtureData(data, uxLanguageFromRequest(r)))
	})
	mux.HandleFunc("GET /errors", func(w http.ResponseWriter, r *http.Request) {
		scenario, ok := uxScenarioFromRequest(r, defaultScenario)
		if !ok {
			http.Error(w, "unknown fixture scenario", http.StatusBadRequest)
			return
		}
		data := uxErrorsFixture(scenario)
		data.RetryQueued = r.URL.Query().Get("retry") == "queued"
		webServer.render(w, "errors.html", uxLocalizedFixtureData(data, uxLanguageFromRequest(r)))
	})
	mux.HandleFunc("POST /backup_now/{fwID}", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("return_to") != "/errors" {
			http.Error(w, "invalid return target", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/errors?retry=queued", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /backups/{fwID}", render("backups.html", uxBackupsFixture))
	mux.HandleFunc("GET /backups/{fwID}/compare", render("backup_compare.html", func(scenario uxScenario) any {
		return backupCompareData{
			Base: uxBase("Compare backups", "firewalls"), Firewall: models.Firewall{ID: 7, FQDN: "edge.example.test"},
			Left: models.Backup{ID: 1}, Right: models.Backup{ID: 2},
			Rows: []configDiffRow{
				{Kind: "unchanged", LeftLine: 1, RightLine: 1, Left: "config system test", Right: "config system test"},
				{Kind: "removed", LeftLine: 2, Left: "set value old"},
				{Kind: "added", RightLine: 2, Right: "set value new"},
			},
			Truncated: scenario == uxScenarioWarning,
		}
	}))
	mux.HandleFunc("/change_password", func(w http.ResponseWriter, r *http.Request) {
		data := changePasswordData{Base: uxBase("Change password", "password")}
		switch r.Method {
		case http.MethodPost:
			oldPassword := r.FormValue("old_password")
			newPassword := r.FormValue("new_password")
			confirmation := r.FormValue("confirm_password")
			if err := appsecurity.ValidateNewPassword(oldPassword, newPassword, confirmation); err != nil {
				data.Error = err.Error()
				webServer.render(w, "change_password.html", uxLocalizedFixtureData(data, uxLanguageFromRequest(r)))
				return
			}
			if oldPassword == "incorrect-current-password" {
				data.Error = "Current password is incorrect."
				webServer.render(w, "change_password.html", uxLocalizedFixtureData(data, uxLanguageFromRequest(r)))
				return
			}
			http.Redirect(w, r, "/change_password?updated=1", http.StatusSeeOther)
			return
		case http.MethodGet:
			data.Success = r.URL.Query().Get("updated") == "1"
			webServer.render(w, "change_password.html", uxLocalizedFixtureData(data, uxLanguageFromRequest(r)))
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
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
			"attention": []attentionItem{}, "attentionMore": 0, "attentionAll": 0, "loadError": false,
		}
		switch scenario {
		case uxScenarioEmpty:
			payload["total"] = 0
			payload["healthy"] = 0
			payload["backups24h"] = 0
		case uxScenarioWarning, uxScenarioError:
			payload["healthy"] = 2
			payload["failed"] = 1
			payload["loadError"] = scenario == uxScenarioError
			payload["attention"] = []attentionItem{{
				Source: "Backup", Severity: "Critical", Title: "branch.example.test",
				Detail: "synthetic connection timeout", Age: "8h", Action: "Retry or inspect", Href: "/backups/12",
			}}
			payload["attentionAll"] = 1
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

func uxLanguageFromRequest(r *http.Request) string {
	if strings.TrimSpace(r.URL.Query().Get("lang")) == "de" {
		return "de"
	}
	if r.Referer() != "" {
		if refererURL, err := url.Parse(r.Referer()); err == nil && refererURL.Query().Get("lang") == "de" {
			return "de"
		}
	}
	return "en"
}

func uxLocalizedFixtureData(data any, lang string) any {
	options := func(active string) webui.NavigationOptions {
		return webui.NavigationOptions{
			Lang: lang, Active: active, AdmVPN: true, ConfGen: true,
			PolSplit: true, ConfConv: true, ConfTail: true,
		}
	}
	localizeBase := func(value any) any {
		switch base := value.(type) {
		case BaseData:
			base.Lang = lang
			base.Shell = webui.ShellText(lang)
			base.Navigation = webui.Navigation(options(base.Active))
			return base
		case webui.BaseData:
			base.Lang = lang
			base.Shell = webui.ShellText(lang)
			base.Navigation = webui.Navigation(options(base.Active))
			return base
		default:
			return value
		}
	}
	if source, ok := data.(map[string]any); ok {
		copyMap := uxLocalizedFixtureMap(source, lang)
		if base, ok := copyMap["Base"]; ok {
			copyMap["Base"] = localizeBase(base)
		}
		if _, ok := copyMap["Lang"]; ok {
			copyMap["Lang"] = lang
		}
		return copyMap
	}
	value := reflect.ValueOf(data)
	if value.Kind() != reflect.Struct {
		return data
	}
	copyValue := reflect.New(value.Type()).Elem()
	copyValue.Set(value)
	if langField := copyValue.FieldByName("Lang"); langField.IsValid() && langField.CanSet() && langField.Kind() == reflect.String {
		langField.SetString(lang)
	}
	baseField := copyValue.FieldByName("Base")
	if !baseField.IsValid() || !baseField.CanSet() {
		return copyValue.Interface()
	}
	localized := localizeBase(baseField.Interface())
	if reflect.TypeOf(localized) == baseField.Type() {
		baseField.Set(reflect.ValueOf(localized))
	}
	return copyValue.Interface()
}

func uxLocalizedFixtureMap(source map[string]any, lang string) map[string]any {
	copyMap := make(map[string]any, len(source)+1)
	for key, value := range source {
		switch nested := value.(type) {
		case map[string]any:
			copyMap[key] = uxLocalizedFixtureMap(nested, lang)
		case []any:
			items := make([]any, len(nested))
			for index, item := range nested {
				if itemMap, ok := item.(map[string]any); ok {
					items[index] = uxLocalizedFixtureMap(itemMap, lang)
				} else {
					items[index] = item
				}
			}
			copyMap[key] = items
		default:
			copyMap[key] = value
		}
	}
	copyMap["Lang"] = lang
	return copyMap
}

func uxFirewalls() []models.Firewall {
	return []models.Firewall{
		{ID: 7, FQDN: "edge.example.test", Username: "backup", IntervalMin: 360, RetentionCount: 30, LastBackup: uxFixtureNow.Add(-20 * time.Minute), Status: "Success", SSHPort: 22},
		{ID: 12, FQDN: "branch.example.test", Username: "backup", IntervalMin: 60, RetentionCount: 14, LastBackup: uxFixtureNow.Add(-8 * time.Hour), Status: "Failed: synthetic connection timeout", SSHPort: 22},
		{ID: 23, FQDN: "fortigate-branch-north-industrial-campus-building-a.example.test", Username: "backup", IntervalMin: 180, RetentionCount: 21, LastBackup: uxFixtureNow.Add(-2 * time.Hour), Status: "In Progress", SSHPort: 9422},
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
	data := searchData{Base: uxBase("Search", "search"), Query: "admin-name"}
	if scenario == uxScenarioEmpty {
		data.Query = ""
	}
	if scenario != uxScenarioEmpty {
		data.Results = []searchResult{{
			FQDN: "edge.example.test", Filename: "edge.conf", Line: `set admin-name "<sentinel-config>"`,
			Segments: []searchSegment{{Text: "set "}, {Text: "admin-name", Match: true}, {Text: ` "<sentinel-config>"`}},
		}}
	}
	if scenario == uxScenarioWarning {
		row := data.Results[0]
		data.Results = make([]searchResult, maxSearchResults)
		for i := range data.Results {
			data.Results[i] = row
		}
		data.Truncated = true
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
		data.CustomRules = []customRule{{ID: 1, Name: "SSH policy", Pattern: "set admin-ssh-port", Severity: "warning", Remediation: "set admin-ssh-port 9422"}}
		data.Exemptions = []exemption{{ID: 1, FwID: 7, FindingKey: "fixture", FindingText: "Synthetic accepted risk", Reason: "Compensating control", Scope: "firewall"}}
		data.CVEStatus = cveRefreshStatus{Live: true, LastSuccessAt: uxFixtureNow.Add(-2 * time.Hour)}
	}
	if scenario == uxScenarioError {
		data.CVEStatus.LastError = "Synthetic CVE refresh failure"
		data.CVEStatus.LastAttemptAt = uxFixtureNow.Add(-time.Hour)
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

func uxActivityFixture(scenario uxScenario) activityLogData {
	data := activityLogData{Base: uxBase("Activity log", "activity"), Page: 1, TotalPages: 1}
	if scenario != uxScenarioEmpty {
		data.Logs = []models.ActivityLog{{Username: "reviewer", Action: "Backup completed", Details: "edge.example.test", Timestamp: uxFixtureNow}}
		data.Total = 1
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic activity-log failure."
	}
	return data
}

func uxErrorsFixture(scenario uxScenario) errorsData {
	data := errorsData{Base: uxBase("Backup errors", "firewalls")}
	if scenario != uxScenarioEmpty {
		data.Errors = []backupErrorView{{
			BackupError: models.BackupError{
				ID: 12, FQDN: "branch.example.test",
				Reason:      "synthetic connection timeout while reading configuration after the SSH handshake; the remote endpoint did not answer before the configured deadline",
				LastAttempt: uxFixtureNow.Add(-5 * time.Minute), LastSuccess: uxFixtureNow.Add(-8 * time.Hour),
			},
			NextRun: uxFixtureNow.Add(20 * time.Minute),
		}}
	}
	if scenario == uxScenarioError {
		data.Error = "Synthetic backup-error query failure."
	}
	return data
}

func uxBackupsFixture(scenario uxScenario) any {
	data := backupsData{Base: uxBase("Backups", "firewalls"), FwID: 7, FQDN: "edge.example.test"}
	if scenario != uxScenarioEmpty {
		data.Backups = []models.Backup{
			{ID: 1, FwID: 7, Timestamp: uxFixtureNow, Filename: "edge_20260902_103000.conf", SizeBytes: 214000, Checksum: strings.Repeat("a", 64)},
			{ID: 2, FwID: 7, Timestamp: uxFixtureNow.Add(-24 * time.Hour), Filename: "edge_20260901_103000.conf", SizeBytes: 212000, Checksum: strings.Repeat("b", 64)},
			{ID: 3, FwID: 7, Timestamp: uxFixtureNow.Add(-48 * time.Hour), Filename: "edge-with-a-very-long-synthetic-backup-filename_20260831_103000.conf", SizeBytes: 210000},
		}
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
	if scenario == uxScenarioError {
		data.LoadError = true
	}
	data.Attention, data.AttentionMore, data.AttentionAll = buildDashboardAttention(
		uxFixtureNow, data.Failures, data.Stale, data.BlockedPorts, data.GraylogIssues, data.DNSIssues, data.LicenseIssues,
	)
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
		{name: "shared primitive clock", path: "/__ux/primitives", contains: `datetime="2026-09-02T10:30:00Z"`},
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
		{name: "ADM VPN add", method: http.MethodPost, path: "/fgt-adm-vpn-conf/add", wantStatus: http.StatusSeeOther},
		{name: "ADM VPN import", method: http.MethodPost, path: "/fgt-adm-vpn-conf/import", wantStatus: http.StatusSeeOther},
		{name: "ADM VPN edit form", method: http.MethodGet, path: "/fgt-adm-vpn-conf/edit/7", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ADM VPN edit submit", method: http.MethodPost, path: "/fgt-adm-vpn-conf/edit/7", wantStatus: http.StatusSeeOther},
		{name: "ADM VPN removal commands", method: http.MethodGet, path: "/fgt-adm-vpn-conf/removal_commands/7", wantStatus: http.StatusOK, contentType: "text/plain"},
		{name: "ADM VPN delete", method: http.MethodPost, path: "/fgt-adm-vpn-conf/delete/7", wantStatus: http.StatusSeeOther},
		{name: "ADM VPN generate", method: http.MethodGet, path: "/fgt-adm-vpn-conf/generate_single/7", wantStatus: http.StatusOK, contentType: "text/plain"},
		{name: "ADM VPN CSV export", method: http.MethodGet, path: "/fgt-adm-vpn-conf/export", wantStatus: http.StatusOK, contentType: "text/csv"},
		{name: "ADM VPN bookmark export", method: http.MethodGet, path: "/fgt-adm-vpn-conf/export_bookmarks", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ADM VPN status", method: http.MethodGet, path: "/fgt-adm-vpn-conf/graylog_dsv", wantStatus: http.StatusOK, contentType: "text/plain"},
		{name: "ConfGen", method: http.MethodGet, path: "/fgt-confgen/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ConfGen firewalls", method: http.MethodGet, path: "/fgt-confgen/list_firewalls", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen templates", method: http.MethodGet, path: "/fgt-confgen/load_templates", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen template", method: http.MethodGet, path: "/fgt-confgen/get_template/Synthetic%20baseline", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen parse", method: http.MethodPost, path: "/fgt-confgen/parse_config", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen validate", method: http.MethodPost, path: "/fgt-confgen/validate_policy", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen generate", method: http.MethodPost, path: "/fgt-confgen/generate_policy", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfGen frontend log", method: http.MethodPost, path: "/fgt-confgen/log", wantStatus: http.StatusNoContent},
		{name: "Policy Split", method: http.MethodGet, path: "/fgt-polsplit/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "Policy Split firewalls", method: http.MethodGet, path: "/fgt-polsplit/list_firewalls", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Policy Split policy", method: http.MethodGet, path: "/fgt-polsplit/policy_info?fw_id=7&policy_id=42", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Policy Split result panel", method: http.MethodGet, path: "/fgt-polsplit/results/00000000-0000-4000-8000-000000000035/panels/traffic", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Policy Split summary export", method: http.MethodGet, path: "/fgt-polsplit/results/00000000-0000-4000-8000-000000000035/export/summary", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Policy Split traffic export", method: http.MethodGet, path: "/fgt-polsplit/results/00000000-0000-4000-8000-000000000035/export/traffic", wantStatus: http.StatusOK, contentType: "text/csv"},
		{name: "Policy Split config export", method: http.MethodGet, path: "/fgt-polsplit/results/00000000-0000-4000-8000-000000000035/export/config?strategy=per_service", wantStatus: http.StatusOK, contentType: "text/plain"},
		{name: "Policy Split analyze", method: http.MethodPost, path: "/fgt-polsplit/analyze", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Policy Split progress", method: http.MethodGet, path: "/fgt-polsplit/progress?id=fixture", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Config Converter", method: http.MethodGet, path: "/fgt-confconv/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "Config Converter firewalls", method: http.MethodGet, path: "/fgt-confconv/list_firewalls", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Config Converter summary", method: http.MethodGet, path: "/fgt-confconv/config_summary?fw_id=7", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "Config Converter convert", method: http.MethodPost, path: "/fgt-confconv/convert", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfTail", method: http.MethodGet, path: "/fgt-conftail/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ConfTail filtered", method: http.MethodPost, path: "/fgt-conftail/", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ConfTail status", method: http.MethodGet, path: "/fgt-conftail/status", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfTail chain", method: http.MethodGet, path: "/fgt-conftail/chain/fixture-chain", wantStatus: http.StatusOK, contentType: "text/html"},
		{name: "ConfTail JSON export", method: http.MethodGet, path: "/fgt-conftail/chain/fixture-chain/export/json", wantStatus: http.StatusOK, contentType: "application/json"},
		{name: "ConfTail CSV export", method: http.MethodGet, path: "/fgt-conftail/chain/fixture-chain/export/csv", wantStatus: http.StatusOK, contentType: "text/csv"},
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
