package web

import (
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/sshhostkey"
)

// TestParseTemplates proves every embedded template parses with the real
// funcMap — a malformed action would otherwise only surface at server start.
func TestParseTemplates(t *testing.T) {
	s := &Server{}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	if len(s.pages) == 0 {
		t.Fatal("no templates parsed")
	}
	for _, name := range []string{"licenses.html", "ipam.html", "dashboard.html"} {
		if _, ok := s.pages[name]; !ok {
			t.Errorf("expected template %s missing", name)
		}
	}
}

func TestIndexRendersPendingSSHHostKeyAcceptance(t *testing.T) {
	s := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	s.render(recorder, "index.html", indexData{
		Base:      BaseData{Title: "Firewalls"},
		Firewalls: []models.Firewall{{ID: 7, FQDN: "fw.example.com", SSHPort: 22}},
		PendingHostKeys: map[int]sshhostkey.PendingKey{
			7: {Algorithm: "ssh-ed25519", Fingerprint: "SHA256:detected"},
		},
	})

	body := recorder.Body.String()
	for _, want := range []string{"Accept new SSH key", "SHA256:detected", `/ssh_host_key/accept/7`} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered firewall page missing %q", want)
		}
	}
}
