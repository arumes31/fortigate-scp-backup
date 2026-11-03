package renderpdf

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func TestForwardingExportUsesWebsiteSectionsAndOrderedPolicies(t *testing.T) {
	source, a := fixture()
	p := reportmodel.DefaultProfile("en")
	p.Charts = nil
	a.Exposures[0].Trace = append(a.Exposures[0].Trace, reportmodel.PolicyTrace{Sequence: 3, ID: "3", Action: "ipsec", Effect: "Unknown actions remain neutral"})
	view, _, _, err := prepare(context.Background(), source, a, "forwarding", p)
	if err != nil {
		t.Fatal(err)
	}
	var publication, policies, finding *block
	for i := range view.Blocks {
		b := &view.Blocks[i]
		switch b.Layout {
		case "publication":
			publication = b
		case "policies":
			policies = b
		case "finding":
			if finding == nil {
				finding = b
			}
		}
	}
	if publication == nil || policies == nil || finding == nil || len(policies.Columns) != 5 || len(policies.Rows) != 3 {
		t.Fatalf("publication details, ordered five-column policy table, or review findings missing")
	}
	if publication.Badge != a.Exposures[0].Outcome || finding.Badge != a.Findings[0].Priority {
		t.Fatal("outcome or finding priority lost")
	}
	for i, trace := range a.Exposures[0].Trace {
		row := strings.Join(policies.Rows[i], "\n")
		for _, required := range []string{fmt.Sprintf("%d / ID %s", trace.Sequence, trace.ID), trace.Name, trace.Status, trace.VIPMatch,
			trace.Source, trace.Destination, trace.SourceInterface, trace.DestinationInterface, trace.Service, trace.Schedule,
			trace.Profiles, trace.Logging, trace.Effect, trace.Evidence} {
			if !strings.Contains(row, required) {
				t.Errorf("policy %s lost %q", trace.ID, required)
			}
		}
		if policies.Actions[i] != trace.Action {
			t.Fatalf("policy %s action no longer matches its original trace row", trace.ID)
		}
	}
	html, err := Export(context.Background(), source, a, "forwarding", "html", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`<dl class="details">`, `class="action action-deny">Deny</span>`, `class="action action-allow">Allow (accept)</span>`, `class="action ">ipsec</span>`, `<details open><summary>Interfaces and zones`} {
		if !bytes.Contains(html, []byte(expected)) {
			t.Errorf("HTML is missing website layout or action semantics %q", expected)
		}
	}
}

func TestFindingBadgesAndPolicyActionsSurviveStructuredExports(t *testing.T) {
	source, a := fixture()
	p := reportmodel.DefaultProfile("en")
	a.Findings[0].Priority = "UNIQUE-PRIORITY"
	for _, format := range []string{"json", "xml", "csv"} {
		data, err := Export(context.Background(), source, a, "forwarding", format, p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("UNIQUE-PRIORITY")) || !bytes.Contains(data, []byte("Allow (accept)")) {
			t.Errorf("%s dropped finding priority or actual policy action", format)
		}
		switch format {
		case "json":
			var doc exportDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
		case "xml":
			if !bytes.Contains(data, []byte("<badge>UNIQUE-PRIORITY</badge>")) || !bytes.Contains(data, []byte("<actions><action>deny</action><action>accept</action></actions>")) {
				t.Fatal("XML lost explicit badge/action metadata")
			}
		case "csv":
			rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				found = found || row[2] == "badge" && row[3] == "UNIQUE-PRIORITY"
			}
			if !found {
				t.Fatal("CSV lost badge value/role")
			}
		}
	}
}

func TestRemovedCustomerReportIsRejectedInEveryFormat(t *testing.T) {
	source, a := fixture()
	p := reportmodel.DefaultProfile("en")
	if _, err := RenderWithProfile(context.Background(), source, a, "customer", p); err == nil {
		t.Fatal("removed customer PDF is still renderable")
	}
	for _, format := range []string{"html", "csv", "json", "xml"} {
		if _, err := Export(context.Background(), source, a, "customer", format, p); err == nil {
			t.Fatalf("removed customer %s is still exportable", format)
		}
	}
}

func TestPublicationGridAndPolicyContinuationPreserveEveryValue(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext unavailable")
	}
	source, a := fixture()
	p := reportmodel.DefaultProfile("en")
	p.Cover, p.Contents, p.ShowInventory, p.ShowFindings = false, false, false, false
	p.Charts = nil
	var effects []string
	for i := 0; i < 160; i++ {
		a.Exposures[0].Backends = append(a.Exposures[0].Backends, fmt.Sprintf("BACKEND%04d", i))
		effects = append(effects, fmt.Sprintf("TRACE%04d", i))
	}
	a.Exposures[0].Trace[0].Effect = strings.Join(effects, "\n")
	data, err := RenderWithProfile(context.Background(), source, a, "forwarding", p)
	if err != nil {
		t.Fatal(err)
	}
	text := extractText(t, data)
	for i := 0; i < 160; i++ {
		for _, prefix := range []string{"BACKEND", "TRACE"} {
			marker := fmt.Sprintf("%s%04d", prefix, i)
			if strings.Count(text, marker) != 1 {
				t.Fatalf("pagination lost or duplicated %s", marker)
			}
		}
	}
	if strings.Count(text, "# / Policy") < 2 || !strings.Contains(text, "Deny") || !strings.Contains(text, "accept") {
		t.Fatal("policy continuation lost repeated headings or action text")
	}
}

func TestBoldGermanActionKeepsTableHeaderWithFirstRow(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext unavailable")
	}
	d := wrapTestDocument(t, context.Background())
	d.width, d.height, d.bottom, d.lang = pageWidth, pageHeight, contentEnd, "de"
	d.newPage()
	label := "Erlauben (accept)"
	d.font(8.5, false)
	regular, err := d.pdf.MeasureTextWidth(label)
	if err != nil {
		t.Fatal(err)
	}
	d.font(8.5, true)
	bold, err := d.pdf.MeasureTextWidth(label)
	if err != nil {
		t.Fatal(err)
	}
	// One action line fits in regular type but requires two lines in bold.
	actionWidth := (regular+bold)/2 + 2*cellPad
	widths := []float64{pageWidth - 2*margin - actionWidth, actionWidth}
	columns := []string{"Richtlinie", "Aktion"}
	rows := [][]string{{"ROW-MARKER", label + "\nenable"}}
	regularOpening := 12.0 + 2*cellPad + 24 + 2*cellPad
	d.y = d.bottom - regularOpening
	d.table("", columns, widths, rows, []string{"accept"})
	if d.err != nil {
		t.Fatal(d.err)
	}
	var data bytes.Buffer
	if _, err := d.pdf.WriteTo(&data); err != nil {
		t.Fatal(err)
	}
	pages := strings.Split(extractText(t, data.Bytes()), "\f")
	if len(pages) < 3 || strings.Contains(pages[0], "Aktion") || !strings.Contains(pages[1], "Aktion") || !strings.Contains(pages[1], "ROW-MARKER") {
		t.Fatal("bold action wrapping left a table header without its first row")
	}
}

func TestCapturedGraylogQueryAndHostnameOriginSurviveExports(t *testing.T) {
	source, a, p := profileFixture()
	a.Telemetry.SourceOrigin, a.Telemetry.SourceMatch = "adm_vpn_cluster_hostnames", "dns_name_full"
	a.Telemetry.Query = `(source:"EDGE-A" OR source:"edge-a") AND (vd:"root")`
	a.Telemetry.VDOMs = []string{"root"}
	for _, format := range []string{"json", "xml", "csv", "html"} {
		data, err := Export(context.Background(), source, a, "traffic", format, p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("ADM VPN Config / cluster hostnames")) || !bytes.Contains(data, []byte("Full DNS name")) {
			t.Fatalf("%s lost captured hostname provenance", format)
		}
		// Decode the format's escaping before checking the exact reusable query.
		switch format {
		case "json":
			var doc exportDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, b := range doc.Report.Blocks {
				for _, row := range b.Rows {
					found = found || len(row) > 1 && row[0] == "Graylog base query" && row[1] == a.Telemetry.Query
				}
			}
			if !found {
				t.Fatal("query is not reproducible from the captured export")
			}
		case "xml":
			var parsed any
			if err := xml.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
		}
	}
}
