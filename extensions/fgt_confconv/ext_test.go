package fgt_confconv

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
	"github.com/go-chi/chi/v5"
)

func TestMountRequiresSharedPageContext(t *testing.T) {
	e := New(&config.Config{}, slog.New(slog.DiscardHandler))
	if err := e.Mount(chi.NewRouter(), extension.Deps{}); err == nil || !strings.Contains(err.Error(), "page context") {
		t.Fatalf("Mount error = %v, want missing shared page context", err)
	}
}

func TestMountRejectsNilSharedCipher(t *testing.T) {
	e := New(&config.Config{}, slog.New(slog.DiscardHandler))
	deps := extension.Deps{PageBase: func(*http.Request, string, string) webui.BaseData { return webui.BaseData{} }}
	if err := e.Mount(chi.NewRouter(), deps); err == nil || !strings.Contains(err.Error(), "cipher") {
		t.Fatalf("Mount error = %v, want missing shared cipher", err)
	}
}

func TestTemplatesParseAndRender(t *testing.T) {
	e := &Extension{}
	if err := e.parseTemplates(); err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}

	data := indexData{
		Base: webui.BaseData{
			Title: "Configuration Conversions", Username: "tester", Lang: "de", Active: "confconv", ReturnTo: "/fgt-confconv/",
			Shell:      webui.ShellText("de"),
			Navigation: webui.Navigation(webui.NavigationOptions{Lang: "de", Active: "confconv", ConfConv: true}),
		},
		Firewalls: []FirewallRef{{ID: 1, FQDN: "fw1.example.com"}},
	}

	var buf bytes.Buffer
	if err := e.page.Render(&buf, data); err != nil {
		t.Fatalf("template failed to render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`<html lang="de">`, `class="app-rail"`, `aria-current="page"`,
		`class="page confconv-page"`, "fw1.example.com", `class="cc-alpha"`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	for _, asset := range []string{"/static/searchable.js", "/fgt-confconv/static/styles.css", "/fgt-confconv/static/confconv.js"} {
		if count := strings.Count(out, asset); count != 1 {
			t.Errorf("asset %q rendered %d times, want exactly once", asset, count)
		}
	}
	for _, unwanted := range []string{`class="topbar"`, `class="sysfooter"`, "FORTISAFE_SYS"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("standalone Config Converter shell remains: %q", unwanted)
		}
	}
}
