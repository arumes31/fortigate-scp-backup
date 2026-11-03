package fgt_reports

import (
	"html/template"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

func TestProfileViewPreservesSavedFiltersAndLocalizesChoices(t *testing.T) {
	p := reportmodel.DefaultProfile("de")
	p.Filters.VDOMs = []string{"no-longer-in-current-report"}
	p.Filters.Types = []string{"static_nat"}
	view := buildProfileView(webui.BaseData{Lang: "de"}, reportmodel.Source{FirewallID: 7}, p,
		reportmodel.Assessment{VDOMs: []string{"root", "root"}}, []reportmodel.Source{{FirewallID: 7}, {FirewallID: 8, Firewall: "Branch"}}, "")
	if view.Revision == "" || len(view.VDOMs) != 2 || len(view.CopySources) != 1 || view.CopySources[0].ID != 8 {
		t.Fatalf("saved choices or copy sources were lost: %+v", view)
	}
	if view.VDOMs[0].ID != "no-longer-in-current-report" || !view.VDOMs[0].Selected {
		t.Fatal("a saved VDOM absent from the report must remain editable")
	}
	if !view.Types[0].Selected || view.Types[0].ID != "static_nat" || view.Types[0].Label != "Statische IPv4-Zuordnung" {
		t.Fatalf("localized labels must preserve submitted IDs: %+v", view.Types[0])
	}
}

func TestProfileEditorPreservesSectionAndChartOrder(t *testing.T) {
	p := reportmodel.DefaultProfile("en")
	p.Sections = []string{"vpn", "interfaces", "policies"}
	p.Charts = []string{"geo", "priority", "type"}
	view := buildProfileView(webui.BaseData{Lang: "en"}, reportmodel.Source{FirewallID: 7}, p, reportmodel.Assessment{}, nil, "")
	output := renderReportTemplate(t, "profile", view)
	for name, want := range map[string][]string{"sections": p.Sections, "charts": p.Charts} {
		pattern := regexp.MustCompile(`<input type="checkbox" name="` + name + `" value="([^"]+)" checked>`)
		var got []string
		for _, match := range pattern.FindAllStringSubmatch(output, -1) {
			got = append(got, match[1])
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s checked control order = %v, want saved order %v", name, got, want)
		}
	}
}

func TestReportDetailShowsCapturedScopeAndDoesNotZeroFailedTelemetry(t *testing.T) {
	p := reportmodel.DefaultProfile("en")
	p.Name, p.Filters.VDOMs = "Captured customer scope", []string{"tenant-a"}
	a := reportmodel.Assessment{Firmware: "7.4.7", VDOMs: []string{"tenant-a", "tenant-b"}, Telemetry: &reportmodel.Telemetry{Status: "partial", Datasets: []reportmodel.TelemetryDataset{{ID: "traffic_actions", Title: "Traffic actions", Status: "error", Reason: "The grouping query could not be completed.", Limit: 20}}}}
	selected, selection := reportmodel.Select(a, p)
	output := renderReportTemplate(t, "detail", detailData{Base: webui.BaseData{Lang: "en"}, Report: reportData{Source: reportmodel.Source{FirewallID: 7}, Assessment: selected, Profile: p, Language: "en"}, Selection: selection})
	if !strings.Contains(output, p.Name) || !strings.Contains(output, selection.Description) || !strings.Contains(output, "tenant-a") {
		t.Fatal("detail lost captured profile or selection scope")
	}
	if strings.Contains(output, `class="report-metrics"`) {
		t.Fatal("failed telemetry must not display default zero metrics")
	}
}

func TestReportProfileFormsAreEscapedAndCarryRevision(t *testing.T) {
	base := webui.BaseData{Lang: "en", CSRFToken: "csrf-fixture"}
	p := reportmodel.DefaultProfile("en")
	p.Organization = `<img src=x onerror=alert(1)>`
	view := buildProfileView(base, reportmodel.Source{FirewallID: 7, Firewall: "Fixture"}, p,
		reportmodel.Assessment{VDOMs: []string{"root"}}, []reportmodel.Source{{FirewallID: 8, Firewall: "Branch"}}, "")
	output := renderReportTemplate(t, "profile", view)
	if strings.Contains(output, p.Organization) || !strings.Contains(output, "&lt;img") {
		t.Fatal("profile strings must be escaped in form values")
	}
	forms := regexp.MustCompile(`(?s)<form\b[^>]*action="/reports/[^>]*>.*?</form>`).FindAllString(output, -1)
	if len(forms) != 4 {
		t.Fatalf("got %d profile mutation forms, want edit/import/copy/reset", len(forms))
	}
	for _, form := range forms {
		csrf := strings.Contains(form, `name="csrf_token" value="csrf-fixture"`)
		revision := strings.Contains(form, `name="revision" value="`+view.Revision+`"`)
		if !csrf || !revision {
			t.Error("profile mutation form lacks CSRF or revision")
		}
	}
	assertReportControlsLabeled(t, output)
}

func TestReportCatalogAndSchedulePagesRenderBothLanguages(t *testing.T) {
	for _, lang := range []string{"en", "de"} {
		t.Run(lang, func(t *testing.T) {
			base := webui.BaseData{Lang: lang}
			catalog := renderReportTemplate(t, "catalog", buildCatalogView(base))
			if !strings.Contains(catalog, reportText(lang, "catalog")) || strings.Contains(catalog, "availability_") {
				t.Fatal("catalog is missing localized labels")
			}
			calendar := renderReportTemplate(t, "calendar", calendarPageData{Base: base, Rows: []reportScheduleRow{{FirewallID: 7, Firewall: "Branch", Profile: "Default", Frequency: "weekly", Timezone: "Europe/Berlin", NextDue: "2026-11-09 03:00 CET"}}})
			if !strings.Contains(calendar, "/reports/7/profile") || !strings.Contains(calendar, reportText(lang, "frequency_weekly")) {
				t.Fatal("schedule page lost its edit link or localized frequency")
			}
		})
	}
}

func renderReportTemplate(t *testing.T, name string, data any) string {
	t.Helper()
	page, err := webui.ParsePage(assets, "templates/"+name+".html", template.FuncMap{"R": reportText})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := page.RenderHTTP(recorder, data); err != nil {
		t.Fatal(err)
	}
	return recorder.Body.String()
}

func assertReportControlsLabeled(t *testing.T, output string) {
	t.Helper()
	labels := regexp.MustCompile(`(?s)<label\b[^>]*>.*?</label>`).FindAllString(output, -1)
	controls := regexp.MustCompile(`<(?:input|select|textarea)\b[^>]*>`).FindAllString(output, -1)
	ids := regexp.MustCompile(`\bid="([^"]+)"`)
	for _, control := range controls {
		if strings.Contains(control, `type="hidden"`) || strings.Contains(control, "aria-label=") || strings.Contains(control, "aria-labelledby=") {
			continue
		}
		id := ids.FindStringSubmatch(control)
		labeled := false
		for _, label := range labels {
			if strings.Contains(label, control) || len(id) == 2 && strings.Contains(label, `for="`+id[1]+`"`) {
				labeled = true
				break
			}
		}
		if !labeled {
			t.Errorf("control has no accessible label: %s", control)
		}
	}
}
