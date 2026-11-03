package renderpdf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func profileFixture() (reportmodel.Source, reportmodel.Assessment, reportmodel.Profile) {
	source, a := fixture()
	a.Exposures[0].Kind = "static_nat"
	a.Findings[0].Priority = "Medium"
	a.Findings[0].Category = "broad-source"
	a.Findings[0].VDOM = "root"
	a.Findings[0].Exposure = a.Exposures[0].Name
	a.Findings[1].Priority = "Informational"
	a.Findings[1].Category = "analysis-coverage"
	a.Exposures = append(a.Exposures, reportmodel.Exposure{VDOM: "office", Name: "Office service", Kind: "virtual_server", Type: "server-load-balance", External: "203.0.113.21:443", Outcome: "Indeterminate", GeoStatus: "Indeterminate"})
	a.Sections[0].Rows[0].VDOM = "root"
	a.Sections[0].Rows[1].VDOM = "office"
	byteCount := int64(123456)
	a.Telemetry = &reportmodel.Telemetry{Status: "partial", DeviceIdentity: "edge-vienna", Sources: []string{"edge-vienna"}, WindowStart: source.BackupAt.Add(-24 * time.Hour), WindowEnd: source.BackupAt, RetrievedAt: source.GeneratedAt,
		Datasets: []reportmodel.TelemetryDataset{
			{ID: "traffic_actions", Title: "Recorded traffic actions", TitleDE: "Protokollierte Verkehrsaktionen", Status: "available", Total: 125, Returned: 2, Limit: 20, Rows: []reportmodel.TelemetryRow{{Label: "accept", Count: 100}, {Label: "deny", Count: 25}}},
			{ID: "applications", Title: "Application observations", TitleDE: "Anwendungsbeobachtungen", Status: "partial", Total: 125, Returned: 2, Limit: 20, Truncated: true, Rows: []reportmodel.TelemetryRow{{Label: "HTTPS", Count: 70}, {Label: "Other / not returned", Count: 55}}},
			{ID: "reported_bytes", Title: "Reported traffic counters", TitleDE: "Gemeldete Verkehrszähler", Status: "partial", Total: 25, Returned: 1, Limit: 20, MissingFields: []string{"rcvdbyte"}, Rows: []reportmodel.TelemetryRow{{Label: "Covered terminal records", Count: 20, SentBytes: &byteCount}, {Label: "Missing required fields", Count: 5}}},
			{ID: "vpn_events", Title: "VPN observations", TitleDE: "VPN-Beobachtungen", Status: "missing_fields", MissingFields: []string{"subtype"}},
		}}
	p := reportmodel.DefaultProfile("en")
	p.Organization = "Example Consulting"
	p.Customer = "Customer reference ACME"
	p.Subtitle = "Review of {{publication_count}} publication definitions"
	p.Intro = "Snapshot {{backup_id}}: {{publication_count}} publications. Owner: {{customer}}."
	p.Footer = "Prepared by {{organization}}"
	p.Filters.VDOMs = []string{"root"}
	return source, a, p
}

func TestExportsUseSelectedSnapshotAcrossFormats(t *testing.T) {
	source, a, p := profileFixture()
	for _, lang := range []string{"en", "de"} {
		p.Language = lang
		for _, kind := range []string{"forwarding", "technical", "customer", "traffic"} {
			for _, format := range []string{"html", "csv", "json", "xml"} {
				t.Run(lang+"-"+kind+"-"+format, func(t *testing.T) {
					data, err := Export(context.Background(), source, a, kind, format, p)
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{source.Checksum, source.BackupAt.Format(time.RFC3339), reportmodel.ProfileHash(p), "Snapshot 81: 1 publications."} {
						if !bytes.Contains(data, []byte(want)) {
							t.Errorf("missing shared provenance/count %q", want)
						}
					}
					switch format {
					case "json":
						var doc exportDocument
						if err := json.Unmarshal(data, &doc); err != nil {
							t.Fatal(err)
						}
						if doc.Schema != reportmodel.Version || doc.Source.BackupID != 81 || doc.Kind != kind {
							t.Fatalf("invalid export envelope: %+v", doc)
						}
						if kind != "traffic" {
							for _, b := range doc.Report.Blocks {
								if b.Chart != nil && b.Chart.ID == "type" {
									var total int64
									for _, point := range b.Chart.Points {
										total += point.Value
									}
									if total != 1 {
										t.Fatalf("chart counted %d unfiltered publications", total)
									}
								}
							}
						}
					case "xml":
						decoder := xml.NewDecoder(bytes.NewReader(data))
						for {
							_, err := decoder.Token()
							if errors.Is(err, io.EOF) {
								break
							}
							if err != nil {
								t.Fatal(err)
							}
						}
						if !bytes.Contains(data, []byte("<rows><row><cell>")) {
							t.Fatal("XML lost table row boundaries")
						}
					case "csv":
						rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
						if err != nil {
							t.Fatal(err)
						}
						for _, row := range rows {
							if len(row) != 4 {
								t.Fatal("unstable CSV shape")
							}
						}
					case "html":
						if !bytes.HasPrefix(data, []byte("<!doctype html>")) || bytes.Contains(data, []byte("ZgotmplZ")) {
							t.Fatal("invalid escaped HTML")
						}
						if bytes.Contains(data, []byte("<script")) || bytes.Contains(data, []byte(`src="http`)) {
							t.Fatal("HTML must be standalone and script-free")
						}
					}
					if kind == "forwarding" && !bytes.Contains(data, []byte(choose(lang, "policy 900", "Richtlinie 900"))) {
						t.Fatal("filter removed earlier deny trace")
					}
				})
			}
		}
	}
}

func TestEveryCustomerFormatOmitsTechnicalAndTelemetryIdentifiers(t *testing.T) {
	source, a, p := profileFixture()
	secret := "PRIVATE-IDENTIFIER-DO-NOT-EXPORT"
	source.Firewall = "10.99.7.3-" + secret
	a.Hostname, a.Firmware = secret, secret
	a.Warnings = []string{secret}
	a.VDOMs = []string{secret}
	a.Exposures[0].VDOM = secret
	a.Exposures[0].Name = secret
	a.Exposures[0].External = "10.99.7.4"
	a.Exposures[0].Backends = []string{secret}
	a.Exposures[0].Evidence = secret
	a.Exposures[0].Notes = []string{secret}
	a.Findings[0] = reportmodel.Finding{ID: "management:" + secret, Category: "management", VDOM: secret, Priority: "Medium", Title: secret, TitleDE: secret, Detail: secret, DetailDE: secret, Recommendation: secret, RecommendationDE: secret, Evidence: secret}
	a.Telemetry.DeviceIdentity = secret
	a.Telemetry.Reason = secret
	a.Telemetry.Sources = []string{secret}
	for i := range a.Telemetry.Datasets {
		a.Telemetry.Datasets[i].Title = secret
		a.Telemetry.Datasets[i].TitleDE = secret
		a.Telemetry.Datasets[i].Reason = secret
		a.Telemetry.Datasets[i].MissingFields = []string{secret}
		for j := range a.Telemetry.Datasets[i].Rows {
			a.Telemetry.Datasets[i].Rows[j].Label = secret
			a.Telemetry.Datasets[i].Rows[j].Secondary = secret
		}
	}
	p.Filters.VDOMs = []string{secret}
	p.Name = secret
	p.Intro = "Reference: {{firewall}} / {{firewall_id}}. {{finding_count}} observations."
	for _, format := range []string{"html", "csv", "json", "xml", "pdf"} {
		t.Run(format, func(t *testing.T) {
			var data []byte
			var err error
			if format == "pdf" {
				if _, err := exec.LookPath("pdftotext"); err != nil {
					t.Skip("pdftotext unavailable")
				}
				data, err = RenderWithProfile(context.Background(), source, a, "customer", p)
				if err == nil {
					data = []byte(extractText(t, data))
				}
			} else {
				data, err = Export(context.Background(), source, a, "customer", format, p)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{secret, "10.99.7.3", "10.99.7.4", "10.10.20.15", "edge-vienna"} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Errorf("customer %s leaked %q", format, forbidden)
				}
			}
			if !bytes.Contains(data, []byte(p.Customer)) || !bytes.Contains(data, []byte("125")) {
				t.Fatal("customer alias or actual aggregate was lost")
			}
		})
	}
}

func TestCSVProtectsFormulasInEveryColumn(t *testing.T) {
	source, a, p := profileFixture()
	p.Organization = "-Organization"
	source.Firewall = "=SOURCE()"
	a.Sections = []reportmodel.Section{{ID: "interfaces", Title: "=TITLE()", Rows: []reportmodel.Row{{Label: "@Label", Value: " \t=SUM(1,2)", Evidence: "+Evidence"}}}}
	data, err := Export(context.Background(), source, a, "technical", "csv", p)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, row := range rows {
		for _, cell := range row {
			first := strings.TrimSpace(cell)
			if first != "" && strings.ContainsRune("=+-@", rune(first[0])) {
				t.Fatalf("unprotected formula cell: %q", cell)
			}
			for _, want := range []string{"'=TITLE()", "'@Label", "'=SOURCE()", "'-Organization"} {
				if cell == want {
					found[want] = true
				}
			}
		}
	}
	if len(found) != 4 {
		t.Fatalf("formula examples were dropped instead of quoted: %+v", found)
	}
}

func TestCSVProtectsInvisibleFormulaPrefixes(t *testing.T) {
	prefixes := []string{"", "\ufeff", "\u200b", "\u202e", "\u2066\u2069", "\ufeff \u200b"}
	values := []string{"=SUM(1,2)", "+123", "-1", "@name", "\ttext", "\rtext", "\ntext"}
	source, a, p := profileFixture()
	a.Sections = []reportmodel.Section{{ID: "interfaces", Title: "Invisible prefixes"}}
	a.Telemetry.Datasets = []reportmodel.TelemetryDataset{{ID: "applications", Status: "available", Total: int64(len(prefixes) * len(values))}}
	for _, prefix := range prefixes {
		for _, value := range values {
			input := prefix + value
			if got := csvSafe(input); got != "'"+input {
				t.Fatalf("unprotected CSV boundary value %q: %q", input, got)
			}
			a.Sections[0].Rows = append(a.Sections[0].Rows, reportmodel.Row{Label: input, Value: input})
			a.Telemetry.Datasets[0].Rows = append(a.Telemetry.Datasets[0].Rows, reportmodel.TelemetryRow{Label: input, Count: 1})
		}
	}
	for _, kind := range []string{"technical", "traffic"} {
		data, err := Export(context.Background(), source, a, kind, "csv", p)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		quoted := 0
		for _, row := range rows {
			for _, cell := range row {
				if strings.ContainsFunc(cell, func(r rune) bool { return unicode.In(r, unicode.Cf) }) {
					t.Fatalf("invisible format mark survived %s projection: %q", kind, cell)
				}
				if strings.HasPrefix(cell, "'") {
					quoted++
					continue
				}
				trimmed := strings.TrimLeftFunc(cell, unicode.IsSpace)
				if strings.ContainsAny(cell[:len(cell)-len(trimmed)], "\t\r\n") || (trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
					t.Fatalf("unprotected exported %s cell: %q", kind, cell)
				}
			}
		}
		if quoted < len(prefixes)*4 {
			t.Fatalf("%s formula examples were dropped instead of quoted: %d", kind, quoted)
		}
	}
}

func TestStructuredJSONNormalizesInvalidUTF8(t *testing.T) {
	source, a, p := profileFixture()
	invalid := "before" + string([]byte{0xff}) + "after"
	source.Firewall = invalid
	a.Sections = []reportmodel.Section{{ID: "interfaces", Title: invalid, Rows: []reportmodel.Row{{Label: invalid, Value: invalid}}}}
	a.Telemetry.Datasets[0].Rows[0].Label = invalid
	for _, kind := range []string{"technical", "traffic"} {
		data, err := Export(context.Background(), source, a, kind, "json", p)
		if err != nil {
			t.Fatal(err)
		}
		if !utf8.Valid(data) || !json.Valid(data) || len(data) > maxText {
			t.Fatalf("invalid or unbounded %s JSON", kind)
		}
		if !bytes.Contains(data, []byte("before\ufffdafter")) {
			t.Fatalf("%s JSON lost the safely normalized label", kind)
		}
	}
}

func TestProfileVisibilityAndLogAvailability(t *testing.T) {
	source, a, p := profileFixture()
	p.ShowFindings, p.ShowInventory, p.ShowTraces = false, false, false
	p.Charts = []string{}
	for _, kind := range []string{"technical", "forwarding"} {
		data, err := Export(context.Background(), source, a, kind, "json", p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("Sequence 1 | policy 900")) {
			t.Fatal("hidden trace retained")
		}
		if kind == "technical" && bytes.Contains(data, []byte("Interfaces and zones")) {
			t.Fatal("hidden inventory retained")
		}
		if !bytes.Contains(data, []byte("Hidden by profile")) || !bytes.Contains(data, []byte(source.Checksum)) {
			t.Fatal("visibility or provenance was lost")
		}
	}
	data, err := Export(context.Background(), source, a, "traffic", "json", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Required log fields are missing", "Not available", "123456", "reported log counters", "separate timestamps"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("traffic report omitted evidence/limits %q", want)
		}
	}
	a.Telemetry.Reason = "A captured source has partial observations."
	a.Telemetry.Datasets[0].Reason = "Only received records in the requested window are counted."
	for _, kind := range []string{"technical", "traffic"} {
		data, err = Export(context.Background(), source, a, kind, "json", p)
		if err != nil {
			t.Fatal(err)
		}
		for _, reason := range []string{a.Telemetry.Reason, a.Telemetry.Datasets[0].Reason} {
			if !bytes.Contains(data, []byte(reason)) {
				t.Errorf("%s omitted captured coverage reason %q", kind, reason)
			}
		}
	}
	p.Traffic = false
	data, err = Export(context.Background(), source, a, "traffic", "json", p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("123456")) || !bytes.Contains(data, []byte("disabled by profile")) {
		t.Fatal("disabled traffic profile disclosed old observations")
	}
}

func TestTelemetryChartsKeepTimelineAndAccountForRemainders(t *testing.T) {
	source, a, p := profileFixture()
	a.Telemetry.WindowStart = a.Telemetry.WindowStart.Add(123 * time.Millisecond)
	a.Telemetry.WindowEnd = a.Telemetry.WindowEnd.Add(123 * time.Millisecond)
	a.Telemetry.RetrievedAt = a.Telemetry.RetrievedAt.Add(123456789 * time.Nanosecond)
	trend := reportmodel.TelemetryDataset{ID: "traffic_trend", Status: "available", Returned: 12, Limit: 12}
	for i := 0; i < 12; i++ {
		start := a.Telemetry.WindowStart.Add(time.Duration(i) * 2 * time.Hour)
		count := int64(i + 1)
		trend.Total += count
		trend.Rows = append(trend.Rows, reportmodel.TelemetryRow{Label: start.Format(time.RFC3339Nano), Secondary: start.Add(2 * time.Hour).Format(time.RFC3339Nano), Timestamp: start, Count: count})
	}
	groups := reportmodel.TelemetryDataset{ID: "applications", Status: "partial", Returned: 20, Limit: 20, Truncated: true, MissingFields: []string{"app"}}
	for i := 0; i < 20; i++ {
		count := int64(20 - i)
		groups.Total += count
		groups.Rows = append(groups.Rows, reportmodel.TelemetryRow{Label: fmt.Sprintf("Application %02d", i+1), Count: count})
	}
	groups.Total += 22
	groups.Rows = append(groups.Rows, reportmodel.TelemetryRow{Label: "Other / not returned", Count: 17}, reportmodel.TelemetryRow{Label: "Missing required fields", Count: 5})
	a.Telemetry.Datasets = []reportmodel.TelemetryDataset{trend, groups}
	for _, lang := range []string{"en", "de"} {
		p.Language = lang
		data, err := Export(context.Background(), source, a, "traffic", "json", p)
		if err != nil {
			t.Fatal(err)
		}
		var doc exportDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		for _, stamp := range []time.Time{a.Telemetry.WindowStart, a.Telemetry.WindowEnd, a.Telemetry.RetrievedAt} {
			if !bytes.Contains(data, []byte(stamp.Format(time.RFC3339Nano))) {
				t.Fatalf("%s telemetry provenance rounded timestamp %s", lang, stamp)
			}
		}
		checked := 0
		for _, b := range doc.Report.Blocks {
			if b.Chart == nil {
				continue
			}
			switch b.Chart.ID {
			case "telemetry-traffic_trend":
				if len(b.Chart.Points) != 12 || len(b.Rows) != 12 {
					t.Fatalf("%s timeline lost an interval: %d points, %d rows", lang, len(b.Chart.Points), len(b.Rows))
				}
				for i, point := range b.Chart.Points {
					if point.Label != trend.Rows[i].Label || point.Value != trend.Rows[i].Count {
						t.Fatalf("%s timeline bucket %d changed: %+v", lang, i, point)
					}
					if b.Rows[i][2] != trend.Rows[i].Secondary || b.Rows[i][3] != trend.Rows[i].Timestamp.Format(time.RFC3339Nano) {
						t.Fatalf("%s timeline table rounded interval %d", lang, i)
					}
				}
				checked++
			case "telemetry-applications":
				if len(b.Chart.Points) != 11 || len(b.Rows) != 22 {
					t.Fatalf("%s grouped view lost bounded detail or remainders", lang)
				}
				remainder := b.Chart.Points[10]
				if remainder.Label != choose(lang, "Remaining table rows", "Übrige Tabellenzeilen") || remainder.Value != 77 {
					t.Fatalf("%s chart mislabels or miscounts mixed remainder: %+v", lang, remainder)
				}
				var sum int64
				for _, point := range b.Chart.Points {
					sum += point.Value
				}
				if sum != groups.Total || !strings.Contains(b.Text, choose(lang, "explicit remainder", "eigenen Rest")) {
					t.Fatalf("%s grouped chart does not account for all table rows", lang)
				}
				checked++
			}
		}
		if checked != 2 {
			t.Fatalf("%s telemetry charts missing: checked %d", lang, checked)
		}
	}
}

func TestMissingFieldsRetainKnownRecordCountWithoutClaimingUsableData(t *testing.T) {
	source, a, p := profileFixture()
	a.Telemetry.Datasets = []reportmodel.TelemetryDataset{{ID: "reported_bytes", Status: "missing_fields", Total: 137,
		Rows: []reportmodel.TelemetryRow{{Label: "PRIVATE_SOURCE", Secondary: "PRIVATE_SOURCE", Count: 137}}, MissingFields: []string{"sentbyte", "rcvdbyte"}},
		{ID: "applications", Status: "error", Total: 999}, {ID: "vpn_events", Status: "missing_fields"}}
	for _, lang := range []string{"en", "de"} {
		p.Language = lang
		for _, kind := range []string{"customer", "traffic"} {
			data, err := Export(context.Background(), source, a, kind, "json", p)
			if err != nil {
				t.Fatal(err)
			}
			var doc exportDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte(`"137"`)) || bytes.Contains(data, []byte(`"999"`)) || bytes.Contains(data, []byte("PRIVATE_SOURCE")) {
				t.Fatalf("%s %s did not isolate known missing-field counts", lang, kind)
			}
			overviewChecked, coverageChecked := false, false
			for _, b := range doc.Report.Blocks {
				if b.Heading == choose(lang, "Observation overview", "Beobachtungsübersicht") {
					if b.Rows[0][2] != "137" || b.Rows[1][2] != choose(lang, "Not available", "Nicht verfügbar") || b.Rows[2][2] != choose(lang, "Not available", "Nicht verfügbar") {
						t.Fatalf("%s %s confused unavailable data and known counts", lang, kind)
					}
					overviewChecked = true
				}
				if kind == "traffic" && b.Heading == telemetryDatasetTitle("reported_bytes", lang) {
					if b.Chart != nil || len(b.Rows) != 1 || b.Rows[0][0] != choose(lang, "Missing required fields", "Fehlende Pflichtfelder") || b.Rows[0][1] != "137" {
						t.Fatalf("%s missing-field remainder implied a usable grouping: %+v", lang, b)
					}
					if !strings.Contains(b.Text, telemetryStatus("missing_fields", lang)) || !strings.Contains(b.Text, choose(lang, "usable grouping and byte counters are unavailable", "nutzbare Gruppierungen und Bytezähler sind nicht verfügbar")) {
						t.Fatalf("%s missing-field status was lost", lang)
					}
					coverageChecked = true
				}
			}
			if !overviewChecked || (kind == "traffic" && !coverageChecked) {
				t.Fatalf("%s %s omitted the known-count overview or coverage row", lang, kind)
			}
		}
	}
}

func TestExportBoundsCancellationAndUnknownMacros(t *testing.T) {
	source, a, p := profileFixture()
	p.Intro = "{{password}}"
	if _, err := Export(context.Background(), source, a, "customer", "json", p); err == nil {
		t.Fatal("unknown macro accepted")
	}
	p = reportmodel.DefaultProfile("en")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Export(ctx, source, a, "technical", "html", p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
	a.Warnings = []string{strings.Repeat("&", maxText)}
	for _, format := range []string{"json", "xml"} {
		if _, err := Export(context.Background(), source, a, "technical", format, p); !errors.Is(err, errProjectionLimit) {
			t.Fatalf("oversized %s projection accepted: %v", format, err)
		}
	}
	buffer := &boundedBuffer{ctx: context.Background()}
	if _, err := buffer.WriteString(strings.Repeat("x", maxText+1)); !errors.Is(err, errOutputLimit) || buffer.Len() != 0 {
		t.Fatal("oversized output was retained")
	}
}

func TestPDFProfileContentsPagesAndOrientation(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext unavailable")
	}
	source, a, p := profileFixture()
	for _, orientation := range []string{"portrait", "landscape"} {
		for _, lang := range []string{"en", "de"} {
			t.Run(orientation+"-"+lang, func(t *testing.T) {
				p.Orientation, p.Language = orientation, lang
				data, err := RenderWithProfile(context.Background(), source, a, "technical", p)
				if err != nil {
					t.Fatal(err)
				}
				text := extractText(t, data)
				pages := strings.Split(text, "\f")
				if len(pages) < 4 {
					t.Fatal("cover/contents/body pagination missing")
				}
				heading := choose(lang, "Report profile and filters", "Berichtsprofil und Filter")
				pattern := regexp.MustCompile(regexp.QuoteMeta(heading) + `\s+(\d+)`)
				match := pattern.FindStringSubmatch(pages[1])
				if len(match) != 2 {
					t.Fatalf("contents entry missing: %s", pages[1])
				}
				page, _ := strconv.Atoi(match[1])
				if page < 3 || page > len(pages) || !strings.Contains(pages[page-1], heading) {
					t.Fatalf("contents points to wrong page %d", page)
				}
				if !strings.Contains(text, p.Organization) || !strings.Contains(text, "Prepared by") {
					t.Fatal("branding/footer missing")
				}
				geometry := "/MediaBox [ 0 0 595.28 841.89 ]"
				if orientation == "landscape" {
					geometry = "/MediaBox [ 0 0 841.89 595.28 ]"
				}
				if !bytes.Contains(data, []byte(geometry)) {
					t.Fatalf("page orientation missing %q", geometry)
				}
			})
		}
	}
}

func TestWriteProfilePreviewFixtures(t *testing.T) {
	dir := os.Getenv("FORTISAFE_REPORT_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set FORTISAFE_REPORT_PREVIEW_DIR for visual review")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source, a, p := profileFixture()
	for _, kind := range []string{"forwarding", "technical", "customer", "traffic"} {
		for _, lang := range []string{"en", "de"} {
			p.Language = lang
			p.Orientation = "portrait"
			if kind == "traffic" {
				p.Orientation = "landscape"
			}
			data, err := RenderWithProfile(context.Background(), source, a, kind, p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("profile-%s-%s.pdf", kind, lang)), data, 0o600); err != nil {
				t.Fatal(err)
			}
			data, err = Export(context.Background(), source, a, kind, "html", p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("profile-%s-%s.html", kind, lang)), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestBrandLogoAndLiteralHTMLAreSafeAcrossPresentationModes(t *testing.T) {
	source, a, p := profileFixture()
	logo := image.NewRGBA(image.Rect(0, 0, 32, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 32; x++ {
			logo.Set(x, y, color.RGBA{R: 15, G: 118, B: 110, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, logo); err != nil {
		t.Fatal(err)
	}
	p.LogoBase64 = base64.StdEncoding.EncodeToString(encoded.Bytes())
	p.Intro = `<script>alert("fixture")</script> <img src="https://example.invalid/image" onerror="alert(1)">`
	p.Organization = "Example <Organization>"
	for _, cover := range []bool{false, true} {
		p.Cover = cover
		data, err := Export(context.Background(), source, a, "customer", "html", p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("<script>")) || bytes.Contains(data, []byte(`<img src="https://`)) || !bytes.Contains(data, []byte("&lt;script&gt;")) {
			t.Fatal("HTML interpreted a plain-text profile field")
		}
		if !bytes.Contains(data, []byte("data:image/png;base64,")) || bytes.Contains(data, []byte("ZgotmplZ")) {
			t.Fatal("validated local logo missing from HTML")
		}
		pdf, err := RenderWithProfile(context.Background(), source, a, "customer", p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(pdf, []byte("/Subtype /Image")) {
			t.Fatalf("logo missing from PDF with cover=%v", cover)
		}
	}
}
