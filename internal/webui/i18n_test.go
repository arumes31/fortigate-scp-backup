package webui

import (
	"bytes"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLocalizeUsesGermanCatalogAndEnglishFallback(t *testing.T) {
	t.Parallel()
	if got := Localize("de", "Firewalls"); got != "Firewalls" {
		t.Fatalf("technical shared term changed = %q", got)
	}
	if got := Localize("de", "Add Firewall"); got != "Firewall hinzufügen" {
		t.Fatalf("German translation = %q", got)
	}
	if got := Localize("fr", "Add Firewall"); got != "Add Firewall" {
		t.Fatalf("unknown-language fallback = %q", got)
	}
	if got := Localize("de", "Uncatalogued operator text"); got != "Uncatalogued operator text" {
		t.Fatalf("unknown-copy fallback = %q", got)
	}
}

func TestRendererProvidesLocalizedTextFunctionToEveryPage(t *testing.T) {
	t.Parallel()
	renderer, err := ParsePage(fstest.MapFS{
		"page.html": {Data: []byte(`{{define "content"}}<h1>{{L .Base.Lang "Add Firewall"}}</h1>{{end}}`)},
	}, "page.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := renderer.Render(&output, struct{ Base BaseData }{Base: BaseData{
		Title: "Add Firewall", Lang: "de", Shell: ShellText("de"),
	}}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !containsAll(got, `<html lang="de">`, `<title>Firewall hinzufügen · FortiSafe</title>`, `<h1>Firewall hinzufügen</h1>`) {
		t.Fatalf("localized render = %s", got)
	}
}

func containsAll(value string, values ...string) bool {
	for _, candidate := range values {
		if !strings.Contains(value, candidate) {
			return false
		}
	}
	return true
}
