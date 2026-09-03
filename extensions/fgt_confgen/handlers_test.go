package fgt_confgen

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

func TestIndexTemplateUsesSharedShell(t *testing.T) {
	e := &Extension{}
	if err := e.parseTemplates(); err != nil {
		t.Fatalf("parse shared page: %v", err)
	}
	data := indexContext{
		Base: webui.BaseData{
			Title: "Policy Generator", Username: "reviewer", Lang: "de", Active: "configgen", ReturnTo: "/fgt-confgen/",
			Shell:      webui.ShellText("de"),
			Navigation: webui.Navigation(webui.NavigationOptions{Lang: "de", Active: "configgen", ConfGen: true}),
		},
		Templates:           []string{"Synthetic baseline"},
		PreselectedTemplate: "Synthetic baseline",
	}
	var output bytes.Buffer
	if err := e.page.Render(&output, data); err != nil {
		t.Fatalf("render shared page: %v", err)
	}
	html := output.String()
	for _, want := range []string{
		`<html lang="de">`, `class="app-rail"`, `aria-current="page"`,
		`class="page confgen-page"`, `data-preselected-template="Synthetic baseline"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("shared ConfGen page missing %q", want)
		}
	}
	for _, asset := range []string{`/fgt-confgen/static/styles.css`, `/fgt-confgen/static/searchable.js`, `/fgt-confgen/static/scripts.js`} {
		if count := strings.Count(html, asset); count != 1 {
			t.Errorf("asset %q rendered %d times, want exactly once", asset, count)
		}
	}
	for _, unwanted := range []string{`class="topbar"`, `class="sysfooter"`, `window.preselectedTemplate =`} {
		if strings.Contains(html, unwanted) {
			t.Errorf("standalone ConfGen shell/bootstrap remains: %q", unwanted)
		}
	}
}

func TestMountRequiresSharedPageContext(t *testing.T) {
	e := New(&config.Config{}, slog.New(slog.DiscardHandler))
	if err := e.Mount(chi.NewRouter(), extension.Deps{}); err == nil || !strings.Contains(err.Error(), "page context") {
		t.Fatalf("Mount error = %v, want missing shared page context", err)
	}
}

// TestIsValidTemplateName: the validator must keep accepting legacy names
// (anything without URL delimiters, header-breaking quotes or control
// characters — including spaces and non-ASCII), and reject only the
// characters that would break the URL path, short-URL matching or the
// Content-Disposition header.
func TestIsValidTemplateName(t *testing.T) {
	valid := []string{
		"basic",
		"with.dots-and_underscores",
		"branch office",    // legacy: spaces were always accepted
		"Zweigstelle Büro", // legacy: non-ASCII letters
		"テンプレート",           // non-Latin scripts
		"a (v2) [prod]!",
		strings.Repeat("x", 128), // exactly at the length cap
	}
	for _, name := range valid {
		if !isValidTemplateName(name) {
			t.Errorf("isValidTemplateName(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("x", 129), // over the length cap
		"a/b",                    // path delimiter
		"a?b",                    // query delimiter
		"a#b",                    // fragment delimiter
		"a%20b",                  // escape injection into stored URLs
		`a"b`,                    // breaks quoted Content-Disposition
		`a\b`,                    // escape in Content-Disposition
		"a\x00b",                 // control character
		"a\nb",                   // control character
		"a\x7fb",                 // DEL
	}
	for _, name := range invalid {
		if isValidTemplateName(name) {
			t.Errorf("isValidTemplateName(%q) = true, want false", name)
		}
	}
}
