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
	pageA := fstest.MapFS{"page.html": {Data: []byte(`{{define "webui.content"}}<h1>A: {{.Message}}</h1>{{end}}`)}}
	pageB := fstest.MapFS{"page.html": {Data: []byte(`{{define "webui.content"}}<h1>B: {{.Message}}</h1>{{end}}`)}}

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
	pageFS := fstest.MapFS{"page.html": {Data: []byte(`{{define "webui.content"}}{{.Unsafe}}{{end}}`)}}
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
	pageFS := fstest.MapFS{"page.html": {Data: []byte(`{{define "webui.content"}}before {{boom}}{{end}}`)}}
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
		Active: "conftail", AdmVPN: true, ConfGen: true, ConfTail: true,
	})
	if got := groupLabels(groups); !reflect.DeepEqual(got, []string{"Overview", "Network data", "Tools", "Utilities"}) {
		t.Fatalf("group labels = %v", got)
	}
	items := flattenItems(groups)
	assertNavItem(t, items, "conftail", "/fgt-conftail/", true)
	assertNavItem(t, items, "admvpn", "/fgt-adm-vpn-conf/", false)
	if _, ok := items["polsplit"]; ok {
		t.Fatal("disabled Policy Split navigation item is present")
	}
	if _, ok := items["confconv"]; ok {
		t.Fatal("disabled Config Converter navigation item is present")
	}
}

func TestNavigationOmitsPasswordForRadiusUsers(t *testing.T) {
	t.Parallel()
	items := flattenItems(Navigation(NavigationOptions{IsRadius: true}))
	if _, ok := items["password"]; ok {
		t.Fatal("password navigation item is present for a RADIUS user")
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
