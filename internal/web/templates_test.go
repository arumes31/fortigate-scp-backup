package web

import (
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/sshhostkey"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
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

func TestCoreTimestampTemplatesUseMachineReadableTimeElements(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"activity_log.html", "audit.html", "backups.html", "dashboard.html",
		"errors.html", "index.html", "licenses.html",
	} {
		t.Run(name, func(t *testing.T) {
			blob, err := templatesFS.ReadFile("templates/" + name)
			if err != nil {
				t.Fatal(err)
			}
			for lineNumber, line := range strings.Split(string(blob), "\n") {
				if strings.Contains(line, "fmtTime") &&
					(!strings.Contains(line, "<time") || !strings.Contains(line, "datetime=\"{{fmtMachineTime")) {
					t.Errorf("line %d displays fmtTime outside a machine-readable <time>: %s", lineNumber+1, line)
				}
			}
		})
	}
}

func TestSharedIconSpriteKeepsButtonNamesInMarkup(t *testing.T) {
	t.Parallel()
	blob, err := staticFS.ReadFile("static/icons.svg")
	if err != nil {
		t.Fatal(err)
	}
	body := string(blob)
	for _, symbol := range []string{`id="copy"`, `id="close"`, `id="chevron"`} {
		if !strings.Contains(body, symbol) {
			t.Errorf("icon sprite missing %s", symbol)
		}
	}
	if strings.Contains(body, "<title") {
		t.Error("shared sprite contains a title; icon meaning belongs to its visible button label")
	}
}

func TestAuthenticatedCorePageUsesSharedDesktopShell(t *testing.T) {
	t.Parallel()
	s := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	s.render(recorder, "change_password.html", changePasswordData{Base: BaseData{
		Title: "Change password", Username: "fixture-reviewer", Lang: "de", Active: "password",
		ReturnTo: "/change_password", Shell: webui.ShellText("de"),
		Navigation: webui.Navigation(webui.NavigationOptions{Lang: "de", Active: "password", AdmVPN: true}),
	}})

	body := recorder.Body.String()
	for _, want := range []string{`<html lang="de">`, `class="skip-link"`, `class="app-rail"`, `aria-label="Primärnavigation"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Core shell missing %q", want)
		}
	}
	if strings.Count(body, `aria-current="page"`) != 1 {
		t.Errorf("aria-current count = %d, want 1", strings.Count(body, `aria-current="page"`))
	}
	for _, unwanted := range []string{"topbar", "SEC_PROTO", "onclick="} {
		if strings.Contains(body, unwanted) {
			t.Errorf("Core shell unexpectedly contains %q", unwanted)
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
		PendingHostKeys: map[int]*sshhostkey.PendingKey{
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

func TestIndexOmitsSSHHostKeyAcceptanceWithoutPendingKey(t *testing.T) {
	tests := []struct {
		name            string
		pendingHostKeys map[int]*sshhostkey.PendingKey
	}{
		{
			name: "nil map",
		},
		{
			name:            "empty map",
			pendingHostKeys: map[int]*sshhostkey.PendingKey{},
		},
		{
			name: "different firewall",
			pendingHostKeys: map[int]*sshhostkey.PendingKey{
				8: {Algorithm: "ssh-ed25519", Fingerprint: "SHA256:other"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &Server{logger: slog.New(slog.DiscardHandler)}
			if err := s.parseTemplates(); err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			s.render(recorder, "index.html", indexData{
				Base:            BaseData{Title: "Firewalls"},
				Firewalls:       []models.Firewall{{ID: 7, FQDN: "fw.example.com", SSHPort: 22}},
				PendingHostKeys: test.pendingHostKeys,
			})

			body := recorder.Body.String()
			for _, unwanted := range []string{"SSH host key changed", "Accept new SSH key", `/ssh_host_key/accept/7`} {
				if strings.Contains(body, unwanted) {
					t.Errorf("rendered firewall page unexpectedly contains %q", unwanted)
				}
			}
		})
	}
}

func TestProgressPollingRetriesTransientFailures(t *testing.T) {
	tests := []struct {
		name  string
		wants []string
	}{
		{
			name: "ipam.html",
			wants: []string{
				"var pollFailures = 0;",
				"Math.min(POLL_RETRY_MAX_MS",
				"pollTimer = setTimeout(poll, retryDelay);",
			},
		},
		{
			name: "licenses.html",
			wants: []string{
				"if (!r.ok) { throw new Error('http ' + r.status); }",
				"var IDLE_POLL_MS = 30000;",
				"setTimeout(poll, IDLE_POLL_MS);",
				"setTimeout(poll, wasRunning ? retryDelay : IDLE_POLL_MS);",
				"Math.min(POLL_RETRY_MAX_MS",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blob, err := templatesFS.ReadFile("templates/" + test.name)
			if err != nil {
				t.Fatal(err)
			}
			body := string(blob)
			for _, want := range test.wants {
				if !strings.Contains(body, want) {
					t.Errorf("template missing polling safeguard %q", want)
				}
			}
		})
	}
}

func TestTopologyNestsPinnedAPsUnderWiredPorts(t *testing.T) {
	blob, err := staticFS.ReadFile("static/topology.js")
	if err != nil {
		t.Fatal(err)
	}
	body := string(blob)
	for _, want := range []string{
		"function apMatchesDevice",
		"wiredPort: port || \"\"",
		"const pinnedAPs = apNodesForSwitch(swName(sw));",
		"children: [...devs.map",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("topology script missing pinned-AP behavior %q", want)
		}
	}
	if strings.Contains(body, "...apNodesForSwitch(swName(sw))") {
		t.Error("pinned APs are still switch-level siblings instead of port children")
	}
}
