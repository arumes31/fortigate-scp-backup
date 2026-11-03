package renderpdf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func fixture() (reportmodel.Source, reportmodel.Assessment) {
	source := reportmodel.Source{
		FirewallID: 42, Firewall: "Vienna edge - Standort Süd", BackupID: 81,
		BackupAt:    time.Date(2026, 11, 3, 19, 30, 0, 0, time.UTC),
		GeneratedAt: time.Date(2026, 11, 3, 19, 31, 0, 0, time.UTC),
		Checksum:    strings.Repeat("a1", 32),
	}
	a := reportmodel.Assessment{
		Firmware: "7.4.7", Hostname: "edge-vienna", VDOMs: []string{"root", "office"}, Complete: false,
		Warnings: []string{"Dynamic routing state is not available in this configuration snapshot."},
		Exposures: []reportmodel.Exposure{{
			VDOM: "root", Name: "Kundenportal-Übergabe", Type: "static-nat", External: "203.0.113.20:8443/TCP",
			ExternalInterface: "wan1; source-interface filter: wan1", Backends: []string{"10.10.20.15:443"},
			Groups: []string{"Customer portals"}, PolicyIDs: []string{"900", "20"}, Outcome: "Conditional",
			GeoStatus: "Applicable to the selected source objects", Evidence: "root / firewall vip / lines 50-61",
			Notes: []string{"The configured geographic restriction applies to TCP/443 after translation. No live reachability check was performed."},
			Trace: []reportmodel.PolicyTrace{
				{Sequence: 1, ID: "900", Name: "Country restriction", Action: "deny", Source: "Configured country selectors",
					SourceInterface: "wan1", DestinationInterface: "dmz", Destination: "all", Service: "HTTPS (TCP/443)",
					Schedule: "always", Status: "enable", VIPMatch: "enable (explicit)", Profiles: "none", Logging: "all",
					Effect: "Applies to the selected geography selectors for this forwarding", Evidence: "root / firewall policy / lines 70-85"},
				{Sequence: 2, ID: "20", Name: "Publish customer portal", Action: "accept", Source: "all",
					SourceInterface: "wan1", DestinationInterface: "dmz", Destination: "Kundenportal-Übergabe", Service: "HTTPS (TCP/443)",
					Schedule: "always", Status: "enable", VIPMatch: "VIP reference", Profiles: "ips-sensor=server-protection", Logging: "all",
					Effect: "Permits remaining supported source conditions", Evidence: "root / firewall policy / lines 86-103"},
			},
		}},
		Sections: []reportmodel.Section{
			{Title: "Interfaces and zones", TitleDE: "Schnittstellen und Zonen", Rows: []reportmodel.Row{
				{Label: "wan1", Value: "role=wan; mode=static; ip=203.0.113.10/24", Evidence: "system interface / lines 10-19"},
				{Label: "dmz", Value: "ip=10.10.20.1/24", Evidence: "system interface / lines 20-28"},
			}},
			{Title: "VPN configuration", TitleDE: "VPN-Konfiguration", Rows: []reportmodel.Row{
				{Label: "Branch connection", Value: "phase1-interface; proposal=aes256-sha256; psk=<excluded>", Evidence: "vpn ipsec phase1-interface / lines 110-125"},
			}},
		},
		Findings: []reportmodel.Finding{
			{ID: "broad-source:root:Kundenportal-Übergabe", Priority: "medium", Title: "Confirm intended publication scope", TitleDE: "Vorgesehenen Veröffentlichungsumfang bestätigen",
				Detail: "The publication permits remaining source addresses after the configured geographic deny.", DetailDE: "Die Veröffentlichung erlaubt die verbleibenden Quelladressen nach der konfigurierten geografischen Sperre.",
				Recommendation: "Confirm the service owner, required source access and documented exceptions.", RecommendationDE: "Dienstverantwortlichen, benötigte Quellzugriffe und dokumentierte Ausnahmen bestätigen.",
				Evidence: "root / firewall policy / lines 86-103"},
			{ID: "analysis-coverage:routing", Priority: "info", Title: "Routing state requires validation", TitleDE: "Routing-Zustand muss validiert werden",
				Detail: "A saved configuration does not provide the active routing table.", DetailDE: "Eine gespeicherte Konfiguration enthält nicht die aktive Routing-Tabelle.",
				Recommendation: "Validate routing when verifying operational reachability.", RecommendationDE: "Routing bei der Prüfung der betrieblichen Erreichbarkeit validieren."},
		},
	}
	return source, a
}

func TestRenderAllTypesAndLanguages(t *testing.T) {
	source, assessment := fixture()
	for _, kind := range []string{"forwarding", "technical", "customer"} {
		for _, lang := range []string{"en", "de"} {
			t.Run(kind+"-"+lang, func(t *testing.T) {
				pdf, err := Render(context.Background(), source, assessment, kind, lang)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf[len(pdf)-64:], []byte("%%EOF")) {
					t.Fatal("renderer did not produce a complete PDF")
				}
				if !bytes.Contains(pdf, []byte("/ToUnicode")) || !bytes.Contains(pdf, []byte("/FontFile2")) {
					t.Fatal("PDF must contain embedded fonts and a searchable Unicode map")
				}
			})
		}
	}
}

func TestRenderRejectsInvalidInputsAndCancellation(t *testing.T) {
	source, assessment := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Render(ctx, source, assessment, "technical", "en"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	for _, args := range [][2]string{{"unknown", "en"}, {"technical", "unknown"}} {
		if _, err := Render(context.Background(), source, assessment, args[0], args[1]); err == nil {
			t.Fatal("invalid report type/language accepted")
		}
	}
	if _, err := Render(nil, source, assessment, "technical", "en"); err == nil { //nolint:staticcheck // Verify explicit rejection of an invalid caller context.
		t.Fatal("nil context accepted")
	}
}

func TestProjectionBudgetRejectsLargeValuesAndEmptyRows(t *testing.T) {
	source, a := fixture()
	a.Warnings = []string{strings.Repeat("x", maxText)}
	if _, err := Render(context.Background(), source, a, "forwarding", "en"); !errors.Is(err, errProjectionLimit) {
		t.Fatalf("large value must be rejected before projection: %v", err)
	}
	a = reportmodel.Assessment{Sections: []reportmodel.Section{{Rows: make([]reportmodel.Row, maxText/(3*128))}}}
	if err := validateProjection(context.Background(), source, a, "technical"); !errors.Is(err, errProjectionLimit) {
		t.Fatalf("empty row allocations must be bounded: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateProjection(ctx, source, a, "technical"); !errors.Is(err, context.Canceled) {
		t.Fatalf("preprojection walk must respect cancellation: %v", err)
	}
}

func TestCustomerProjectionCannotCarryTechnicalPayload(t *testing.T) {
	source, a := fixture()
	sentinel := "PRIVATE-PAYLOAD-NEVER-IN-CUSTOMER"
	source.Firewall = "10.99.1.2 " + sentinel
	source.Checksum = sentinel // provenance accepts only an actual SHA-256 encoding
	a.Firmware, a.Hostname = sentinel, sentinel
	a.VDOMs = []string{sentinel}
	a.Warnings = []string{sentinel}
	a.Exposures = []reportmodel.Exposure{{VDOM: sentinel, Name: sentinel, External: "10.99.1.3", Backends: []string{sentinel}, Outcome: sentinel, GeoStatus: sentinel, Evidence: sentinel, Notes: []string{sentinel}}}
	a.Sections = []reportmodel.Section{{Title: sentinel, Rows: []reportmodel.Row{{Value: sentinel}}}}
	a.Findings = []reportmodel.Finding{{ID: "management:" + sentinel, Priority: sentinel, Title: sentinel, TitleDE: sentinel, Detail: sentinel, DetailDE: sentinel, Recommendation: sentinel, RecommendationDE: sentinel, Evidence: sentinel}, {ID: sentinel, Priority: "high", Detail: sentinel}}
	for _, lang := range []string{"en", "de"} {
		projected, err := json.Marshal(project(source, a, "customer", lang))
		if err != nil {
			t.Fatal(err)
		}
		for _, disallowed := range []string{sentinel, "10.99.1.2", "10.99.1.3"} {
			if bytes.Contains(projected, []byte(disallowed)) {
				t.Fatalf("customer projection retained technical payload %q", disallowed)
			}
		}
		if !bytes.Contains(projected, []byte(choose(lang, "Administrative access", "Administrativer Zugriff"))) {
			t.Fatal("known findings must map to an actionable customer topic")
		}
	}
}

func TestForwardingProjectionPreservesEveryTraceField(t *testing.T) {
	source, a := fixture()
	trace := a.Exposures[0].Trace[1]
	trace.SourceInterface, trace.DestinationInterface = "SOURCE-INTERFACE-EVIDENCE", "DESTINATION-INTERFACE-EVIDENCE"
	trace.Profiles, trace.Logging = "PROFILE-EVIDENCE", "LOGGING-EVIDENCE"
	a.Exposures[0].Trace[1] = trace
	projected, err := json.Marshal(project(source, a, "forwarding", "en"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{trace.SourceInterface, trace.DestinationInterface, trace.Profiles, trace.Logging, "203.0.113.20:8443/TCP", "10.10.20.15:443", "Sequence 1 | policy 900", "Sequence 2 | policy 20"} {
		if !bytes.Contains(projected, []byte(want)) {
			t.Errorf("forwarding projection lost %q", want)
		}
	}
}

// These tests additionally exercise an independent PDF reader when Poppler is
// available. The projection/privacy tests above run on every Go-only CI host.
func TestPDFTextRoundTripAndCustomerRedaction(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext is not installed")
	}
	source, a := fixture()
	for _, kind := range []string{"forwarding", "technical", "customer"} {
		data, err := Render(context.Background(), source, a, kind, "de")
		if err != nil {
			t.Fatal(err)
		}
		text := extractText(t, data)
		if !strings.Contains(text, "FortiSafe") || !strings.Contains(text, "Seite") || !strings.Contains(text, "2026-11-03T19:30:00Z") {
			t.Fatalf("%s: missing provenance/footer after independent PDF extraction", kind)
		}
		if kind == "customer" {
			for _, forbidden := range []string{"10.10.20.15", "203.0.113.20", "Kundenportal", "edge-vienna", "Country restriction", "server-protection", "root / firewall"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("customer PDF leaked %q", forbidden)
				}
			}
			if !strings.Contains(text, "Kundenübersicht") || !strings.Contains(text, "Veröffentlichte Dienste") {
				t.Error("German customer text did not survive Unicode extraction")
			}
		} else if !strings.Contains(text, "Kundenportal-Übergabe") {
			t.Errorf("%s: German object name was lost", kind)
		}
	}
}

func TestPDFOversizedRowContinuesWithoutLosingText(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext is not installed")
	}
	source, a := fixture()
	var longValue strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&longValue, "ROW%04d configuration detail and evidence.\n", i)
	}
	longValue.WriteString("END-OF-LONG-ROW")
	a.Sections = []reportmodel.Section{{Title: "Pagination exercise", Rows: []reportmodel.Row{{
		Label: strings.Repeat("LongUnbrokenObjectName", 90),
		Value: longValue.String(),
	}}}}
	data, err := Render(context.Background(), source, a, "technical", "en")
	if err != nil {
		t.Fatal(err)
	}
	text := extractText(t, data)
	if !strings.Contains(text, "END-OF-LONG-ROW") || strings.Count(text, "Field") < 3 {
		t.Fatal("oversized row was clipped or continuation headings were missing")
	}
	for i := 0; i < 300; i++ {
		marker := fmt.Sprintf("ROW%04d", i)
		if strings.Count(text, marker) != 1 {
			t.Fatalf("long row lost or duplicated %s during pagination", marker)
		}
	}
}

func extractText(t *testing.T, data []byte) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := exec.Command("pdftotext", "-layout", file, "-").CombinedOutput()
	if err != nil {
		t.Fatalf("independent PDF text extraction failed: %v: %s", err, result)
	}
	return string(result)
}

// TestWritePreviewFixtures is opt-in and writes six synthetic PDFs for visual
// QA. Run with FORTISAFE_REPORT_PREVIEW_DIR=/tmp/fortisafe-report-previews.
func TestWritePreviewFixtures(t *testing.T) {
	dir := os.Getenv("FORTISAFE_REPORT_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set FORTISAFE_REPORT_PREVIEW_DIR to write synthetic PDF previews")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source, a := fixture()
	for _, kind := range []string{"forwarding", "technical", "customer"} {
		for _, lang := range []string{"en", "de"} {
			data, err := Render(context.Background(), source, a, kind, lang)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, kind+"-"+lang+".pdf"), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
