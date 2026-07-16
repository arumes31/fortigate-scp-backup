package fgt_polsplit

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// TestTemplateRenders parses the embedded page template and executes it with
// representative data, so template syntax errors fail in CI instead of at
// first page view.
func TestTemplateRenders(t *testing.T) {
	tmpl, err := template.New("").ParseFS(extensionFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	data := struct {
		Base      baseData
		Firewalls []FirewallRef
	}{
		Base:      baseData{Title: "Policy Split Advisor", Username: "tester", ExtPolSplitEnabled: true},
		Firewalls: []FirewallRef{{ID: 1, FQDN: "fw-01.example.com"}},
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "fgt_polsplit_index.html", data); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Policy Split Advisor", "fw-01.example.com", "ps-analyze-btn", "Pol_Split"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}
