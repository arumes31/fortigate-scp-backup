package webui

import (
	"bytes"
	"errors"
	"html/template"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

type testPageData struct {
	Base    BaseData
	Message string
}

func TestParsePageIsolatesSameNamedTemplates(t *testing.T) {
	t.Parallel()
	pageA := fstest.MapFS{"page.html": {Data: []byte(`{{define "content"}}<h1>A: {{.Message}}</h1>{{end}}`)}}
	pageB := fstest.MapFS{"page.html": {Data: []byte(`{{define "content"}}<h1>B: {{.Message}}</h1>{{end}}`)}}

	rendererA, err := ParsePage(pageA, "page.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	rendererB, err := ParsePage(pageB, "page.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := testPageData{
		Base:    BaseData{Title: "Fixture", Lang: "en", Username: "reviewer"},
		Message: `<script>alert("unsafe")</script>`,
	}

	var outputA, outputB bytes.Buffer
	if err := rendererA.Render(&outputA, data); err != nil {
		t.Fatal(err)
	}
	if err := rendererB.Render(&outputB, data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(outputA.String(), "B:") || strings.Contains(outputB.String(), "A:") {
		t.Fatalf("same-named page templates leaked across renderers\nA: %s\nB: %s", outputA.String(), outputB.String())
	}
	if strings.Contains(outputA.String(), `<script>`) || !strings.Contains(outputA.String(), `&lt;script&gt;`) {
		t.Fatalf("page string was not HTML-escaped: %s", outputA.String())
	}
}

func TestRendererRejectsPreRenderedHTML(t *testing.T) {
	t.Parallel()
	pageFS := fstest.MapFS{"page.html": {Data: []byte(`{{define "content"}}{{.Unsafe}}{{end}}`)}}
	renderer, err := ParsePage(pageFS, "page.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := struct {
		Base   BaseData
		Unsafe struct{ Content template.HTML }
	}{Base: BaseData{Title: "Fixture"}}
	data.Unsafe.Content = template.HTML(`<img src=x onerror=alert(1)>`)

	var output bytes.Buffer
	err = renderer.Render(&output, data)
	if !errors.Is(err, ErrPreRenderedHTML) {
		t.Fatalf("Render error = %v, want ErrPreRenderedHTML", err)
	}
	if output.Len() != 0 {
		t.Fatalf("Render wrote %q before rejecting pre-rendered HTML", output.String())
	}
}

func TestRendererBuffersTemplateErrors(t *testing.T) {
	t.Parallel()
	pageFS := fstest.MapFS{"page.html": {Data: []byte(`{{define "content"}}before {{boom}}{{end}}`)}}
	renderer, err := ParsePage(pageFS, "page.html", template.FuncMap{
		"boom": func() (string, error) { return "", errors.New("synthetic render failure") },
	})
	if err != nil {
		t.Fatal(err)
	}

	output := bytes.NewBufferString("existing")
	if err := renderer.Render(output, testPageData{}); err == nil {
		t.Fatal("Render succeeded, want template execution error")
	}
	if got := output.String(); got != "existing" {
		t.Fatalf("Render partially wrote output: %q", got)
	}
}

func TestNavigationGroupsAreDataDriven(t *testing.T) {
	t.Parallel()
	groups := Navigation(NavigationOptions{
		Lang: "en", Active: "conftail", AdmVPN: true, ConfGen: true, ConfTail: true,
	})
	if got := groupLabels(groups); !reflect.DeepEqual(got, []string{"Overview", "Network data", "Tools"}) {
		t.Fatalf("group labels = %v", got)
	}
	items := flattenItems(groups)
	assertNavItem(t, items, "search", "/search", false)
	assertNavItem(t, items, "audit", "/audit", false)
	assertNavItem(t, items, "topology", "/topology", false)
	assertNavItem(t, items, "conftail", "/fgt-conftail/", true)
	assertNavItem(t, items, "admvpn", "/fgt-adm-vpn-conf/", false)
	if _, ok := items["polsplit"]; ok {
		t.Fatal("disabled Policy Split navigation item is present")
	}
	if _, ok := items["confconv"]; ok {
		t.Fatal("disabled Config Converter navigation item is present")
	}
}

func TestNavigationLocalizesGermanLabels(t *testing.T) {
	t.Parallel()
	groups := Navigation(NavigationOptions{Lang: "de", AdmVPN: true})
	if got := groupLabels(groups); !reflect.DeepEqual(got, []string{"Übersicht", "Netzwerkdaten", "Werkzeuge"}) {
		t.Fatalf("German group labels = %v", got)
	}
	items := flattenItems(groups)
	if items["search"].Label != "Suche" || items["licenses"].Label != "Lizenzen" {
		t.Fatalf("German navigation labels = search:%q licenses:%q", items["search"].Label, items["licenses"].Label)
	}
}

func TestSharedShellRendersNamedDesktopUtilities(t *testing.T) {
	t.Parallel()
	pageFS := fstest.MapFS{"page.html": {Data: []byte(`{{define "content"}}<h1>Fixture page</h1>{{end}}`)}}
	renderer, err := ParsePage(pageFS, "page.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := testPageData{Base: BaseData{
		Title: "Fixture", Username: "fixture-reviewer", Lang: "de", Active: "password",
		ReturnTo: "/change_password", Shell: ShellText("de"),
		Navigation: Navigation(NavigationOptions{Lang: "de", Active: "password", AdmVPN: true}),
	}}

	var output bytes.Buffer
	if err := renderer.Render(&output, data); err != nil {
		t.Fatal(err)
	}
	body := output.String()
	for _, want := range []string{
		`<html lang="de">`, `class="skip-link"`, `class="app-rail"`,
		`aria-label="Primärnavigation"`, `aria-label="Hilfsfunktionen"`,
		`Betriebskonsole`, `data-time-controls`, `data-time-mode="utc"`, `data-time-mode="local"`,
		`name="lang" value="en"`, `name="lang" value="de"`,
		`fixture-reviewer`, `href="/change_password" aria-current="page"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("shared shell missing %q\n%s", want, body)
		}
	}
	if strings.Count(body, `aria-current="page"`) != 1 {
		t.Errorf("aria-current count = %d, want 1", strings.Count(body, `aria-current="page"`))
	}
	for _, unwanted := range []string{"topbar", "hamburger", "SEC_PROTO", "onclick="} {
		if strings.Contains(body, unwanted) {
			t.Errorf("shared shell unexpectedly contains %q", unwanted)
		}
	}
}

func groupLabels(groups []NavGroup) []string {
	labels := make([]string, 0, len(groups))
	for _, group := range groups {
		labels = append(labels, group.Label)
	}
	return labels
}

func flattenItems(groups []NavGroup) map[string]NavItem {
	items := make(map[string]NavItem)
	for _, group := range groups {
		for _, item := range group.Items {
			items[item.Key] = item
		}
	}
	return items
}

func assertNavItem(t *testing.T, items map[string]NavItem, key, href string, current bool) {
	t.Helper()
	item, ok := items[key]
	if !ok {
		t.Fatalf("navigation item %q is missing", key)
	}
	if item.Href != href || item.Current != current {
		t.Fatalf("navigation item %q = %+v, want href %q current %t", key, item, href, current)
	}
}
