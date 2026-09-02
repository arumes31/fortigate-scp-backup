package fgt_confconv

import (
	"bytes"
	"html/template"
	"log/slog"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/go-chi/chi/v5"
)

func TestMountRejectsNilSharedCipher(t *testing.T) {
	e := New(&config.Config{}, slog.New(slog.DiscardHandler))
	if err := e.Mount(chi.NewRouter(), extension.Deps{}); err == nil {
		t.Fatal("Mount accepted a nil shared cipher")
	}
}

func TestTemplatesParseAndRender(t *testing.T) {
	tmpl, err := template.New("").ParseFS(extensionFS, "templates/*.html")
	if err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}

	data := struct {
		Base      baseData
		Firewalls []FirewallRef
	}{
		Base:      baseData{Title: "Configuration Conversions", Username: "tester", ExtConfConvEnabled: true},
		Firewalls: []FirewallRef{{ID: 1, FQDN: "fw1.example.com"}},
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "fgt_confconv_index.html", data); err != nil {
		t.Fatalf("template failed to render: %v", err)
	}
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("fw1.example.com")) {
		t.Errorf("rendered page missing the firewall option:\n%s", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Conf_Conv")) {
		t.Errorf("rendered page missing the nav link:\n%s", out)
	}
}
