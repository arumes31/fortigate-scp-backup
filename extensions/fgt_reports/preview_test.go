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
	e.analyze, e.render = fortiosconfig.Analyze, renderpdf.Render
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
	for range 2 {
		e.generate(claim(t, e))
	}
	var ready int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM report_latest").Scan(&ready); err != nil || ready != 2 {
		t.Fatalf("synthetic report generation: count=%d error=%v", ready, err)
	}
	pending := source(83)
	pending.FirewallID, pending.Firewall, pending.Checksum = 9, "Pending Frankfurt", hash
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
	e.page, err = webui.ParsePage(assets, "templates/index.html", template.FuncMap{"R": reportText})
	if err != nil {
		t.Fatal(err)
	}
	e.detailPage, err = webui.ParsePage(assets, "templates/detail.html", template.FuncMap{"R": reportText})
	if err != nil {
		t.Fatal(err)
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
		r.Get("/{firewallID}", e.detail)
		r.Get("/{firewallID}/data", e.data)
		r.Get("/{firewallID}/{kind}.pdf", e.download)
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
