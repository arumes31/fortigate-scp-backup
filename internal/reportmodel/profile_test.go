package reportmodel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"reflect"
	"strings"
	"testing"
)

func TestProfileCanonicalHashAndExplicitSuppression(t *testing.T) {
	p := DefaultProfile("de")
	p.Sections, p.Charts = []string{}, []string{}
	p.Cover, p.Contents, p.ShowFindings, p.ShowInventory, p.ShowTraces, p.Traffic = false, false, false, false, false, false
	p.Filters.VDOMs = []string{"b", "a", "a"}
	p.Filters.Priorities = []string{"Medium", "High", "Medium"}
	p.Accent = "#ABCDEF"
	p.Schedule.MonthDay = 31
	normalized, err := NormalizeProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Sections)+len(normalized.Charts) != 0 || normalized.Cover || normalized.Contents || normalized.ShowFindings || normalized.ShowInventory || normalized.ShowTraces || normalized.Traffic {
		t.Fatalf("explicitly suppressed content was restored: %+v", normalized)
	}
	if normalized.Language != "de" || normalized.Accent != "#abcdef" || normalized.Schedule.MonthDay != 31 {
		t.Fatalf("unexpected normalization: %+v", normalized)
	}
	if !reflect.DeepEqual(normalized.Filters.VDOMs, []string{"a", "b"}) || !reflect.DeepEqual(normalized.Filters.Priorities, []string{"High", "Medium"}) {
		t.Fatalf("filter canonicalization: %+v", normalized.Filters)
	}
	if hash := ProfileHash(p); len(hash) != 64 || hash != ProfileHash(normalized) {
		t.Fatalf("hash is not stable: %q", hash)
	}
	changed := normalized
	changed.Intro = "Different requested narrative"
	if ProfileHash(changed) == ProfileHash(normalized) {
		t.Fatal("profile changes must invalidate the generation key")
	}
	if p.Filters.VDOMs[0] != "b" {
		t.Fatal("normalization mutated the caller's input")
	}
}

func TestProfileRejectsUntrustedOrUnboundedInput(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Profile)
	}{
		{"future schema", func(p *Profile) { p.Schema = SchemaVersion + 1 }},
		{"language", func(p *Profile) { p.Language = "unknown" }},
		{"orientation", func(p *Profile) { p.Orientation = "javascript:bad" }},
		{"time range", func(p *Profile) { p.TimeRange = "all_time" }},
		{"color", func(p *Profile) { p.Accent = "red;url(secret)" }},
		{"name length", func(p *Profile) { p.Name = strings.Repeat("a", 121) }},
		{"intro length", func(p *Profile) { p.Intro = strings.Repeat("a", 4001) }},
		{"control", func(p *Profile) { p.Customer = "A\x1bB" }},
		{"bidi", func(p *Profile) { p.Organization = "A\u202eB" }},
		{"single line", func(p *Profile) { p.Subtitle = "A\nB" }},
		{"unknown macro", func(p *Profile) { p.Intro = "{{config_password}}" }},
		{"unclosed macro", func(p *Profile) { p.Footer = "{{firewall" }},
		{"nested macro", func(p *Profile) { p.Intro = "{{{{firewall}}}}" }},
		{"unknown section", func(p *Profile) { p.Sections = []string{"private_keys"} }},
		{"unknown chart", func(p *Profile) { p.Charts = []string{"attacks_prevented"} }},
		{"unknown kind", func(p *Profile) { p.Filters.Types = []string{"script"} }},
		{"unknown outcome", func(p *Profile) { p.Filters.Outcomes = []string{"Safe"} }},
		{"unknown priority", func(p *Profile) { p.Filters.Priorities = []string{"Perfect"} }},
		{"VDOM bound", func(p *Profile) { p.Filters.VDOMs = make([]string, 257) }},
		{"VDOM control", func(p *Profile) { p.Filters.VDOMs = []string{"root\nother"} }},
		{"frequency", func(p *Profile) { p.Schedule.Frequency = "every_second" }},
		{"timezone", func(p *Profile) { p.Schedule.Timezone = "../token" }},
		{"local timezone", func(p *Profile) { p.Schedule.Timezone = "Local" }},
		{"hour", func(p *Profile) { p.Schedule.Hour = 24 }},
		{"minute", func(p *Profile) { p.Schedule.Minute = 60 }},
		{"weekday", func(p *Profile) { p.Schedule.Weekday = -1 }},
		{"month day", func(p *Profile) { p.Schedule.MonthDay = 32 }},
		{"logo URL", func(p *Profile) { p.LogoBase64 = "https://example.test/logo.png" }},
		{"logo bytes", func(p *Profile) { p.LogoBase64 = strings.Repeat("a", 350000) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultProfile("en")
			tc.edit(&p)
			if _, err := NormalizeProfile(p); err == nil {
				t.Fatal("unsafe or unsupported profile was accepted")
			}
			if ProfileHash(p) != "" {
				t.Fatal("invalid profile has a generation hash")
			}
		})
	}
}

func TestLogoCanonicalizationStripsMetadataAndRejectsTruncation(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	img.Set(3, 3, color.RGBA{R: 255, A: 255})
	for _, format := range []string{"png", "jpeg"} {
		t.Run(format, func(t *testing.T) {
			var raw bytes.Buffer
			var err error
			if format == "png" {
				err = png.Encode(&raw, img)
			} else {
				err = jpeg.Encode(&raw, img, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			data := append(append([]byte{}, raw.Bytes()...), []byte("TRAILING_PRIVATE_METADATA")...)
			p := DefaultProfile("en")
			p.LogoBase64 = base64.StdEncoding.EncodeToString(data)
			normalized, err := NormalizeProfile(p)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := base64.StdEncoding.DecodeString(normalized.LogoBase64)
			if err != nil || bytes.Contains(decoded, []byte("PRIVATE_METADATA")) || !bytes.HasPrefix(decoded, []byte("\x89PNG")) {
				t.Fatal("logo was not stripped and canonicalized")
			}
			if ProfileHash(normalized) != ProfileHash(p) {
				t.Fatal("normalizing a logo twice changes its hash")
			}
			p.LogoBase64 = base64.StdEncoding.EncodeToString(raw.Bytes()[:len(raw.Bytes())/2])
			if _, err := NormalizeProfile(p); err == nil {
				t.Fatal("truncated image was accepted")
			}
		})
	}
	var oversized bytes.Buffer
	if err := png.Encode(&oversized, image.NewRGBA(image.Rect(0, 0, 1025, 1))); err != nil {
		t.Fatal(err)
	}
	p := DefaultProfile("en")
	p.LogoBase64 = base64.StdEncoding.EncodeToString(oversized.Bytes())
	if _, err := NormalizeProfile(p); err == nil {
		t.Fatal("oversized image dimensions were accepted")
	}
}

func TestSelectionPreservesEvidenceAndNeverReanalyzesSubset(t *testing.T) {
	bytesCount := int64(42)
	a := Assessment{Complete: false, Firmware: "7.4.10", Hostname: "private-firewall", VDOMs: []string{"a", "b"}, Warnings: []string{"Global coverage limitation"},
		Exposures: []Exposure{
			{VDOM: "a", Name: "private-object", Kind: "static_nat", Outcome: "Conditional", Notes: []string{"earlier bypass"}, Trace: []PolicyTrace{{Sequence: 1, ID: "90", Action: "accept"}, {Sequence: 2, ID: "1", Action: "deny"}}},
			{VDOM: "b", Name: "other-object", Kind: "virtual_server", Outcome: "Indeterminate"},
		},
		Findings:  []Finding{{VDOM: "a", Category: "publications", Exposure: "private-object", Priority: "Medium"}, {VDOM: "b", Category: "publications", Exposure: "other-object", Priority: "Medium"}, {Category: "analysis", Priority: "Informational"}},
		Sections:  []Section{{ID: "interfaces", Rows: []Row{{VDOM: "a", Label: "Misleading VDOM b label"}, {VDOM: "b", Label: "Misleading VDOM a label"}}}, {ID: "ha", Rows: []Row{{VDOM: "", Label: "Appliance-wide HA"}}}},
		Telemetry: &Telemetry{Sources: []string{"private-source"}, Datasets: []TelemetryDataset{{Rows: []TelemetryRow{{Bytes: &bytesCount}}}}},
	}
	p := DefaultProfile("en")
	p.Filters.VDOMs = []string{"a"}
	p.Filters.Types = []string{"static_nat"}
	p.Filters.Outcomes = []string{"Conditional"}
	p.Sections = []string{"ha", "interfaces"}
	selected, stats := Select(a, p)
	if selected.Complete || len(selected.Warnings) != 1 || selected.Firmware != a.Firmware || selected.Hostname != a.Hostname {
		t.Fatal("global evidence or limitations were changed")
	}
	if len(selected.Exposures) != 1 || selected.Exposures[0].Outcome != "Conditional" || len(selected.Exposures[0].Trace) != 2 || selected.Exposures[0].Trace[0].ID != "90" {
		t.Fatalf("full rule trace/result must survive selection: %+v", selected.Exposures)
	}
	if len(selected.Findings) != 2 || len(selected.Sections) != 2 || selected.Sections[0].ID != "ha" || selected.Sections[1].Rows[0].VDOM != "a" {
		t.Fatalf("typed scope/order failed: %+v", selected)
	}
	if stats.Original.Exposures != 2 || stats.Selected.Exposures != 1 || stats.Selected.Traces != 2 || stats.Selected.Rows != 2 || !stats.Filtered {
		t.Fatalf("incorrect counts: %+v", stats)
	}
	selected.Exposures[0].Trace[0].ID = "mutated"
	selected.Exposures[0].Notes[0] = "mutated"
	selected.Sections[1].Rows[0].Label = "mutated"
	selected.Telemetry.Sources[0] = "mutated"
	*selected.Telemetry.Datasets[0].Rows[0].Bytes = 99
	if a.Exposures[0].Trace[0].ID != "90" || a.Exposures[0].Notes[0] != "earlier bypass" || a.Sections[0].Rows[0].Label == "mutated" || bytesCount != 42 || a.Telemetry.Sources[0] != "private-source" {
		t.Fatal("selection aliased mutable assessment data")
	}
}

func TestLegacyInventoryRetainedOnlyForUnscopedFullDefault(t *testing.T) {
	a := Assessment{Sections: []Section{{Title: "Legacy title", Rows: []Row{{Label: "VDOM never parse this"}}}}}
	p := DefaultProfile("en")
	selected, _ := Select(a, p)
	if len(selected.Sections) != 1 {
		t.Fatal("default profile lost the prior successful inventory")
	}
	p.Filters.VDOMs = []string{"root"}
	selected, _ = Select(a, p)
	if len(selected.Sections) != 0 || len(selected.Warnings) == 0 {
		t.Fatal("untyped legacy scope must be omitted explicitly")
	}
	p.Filters.VDOMs = nil
	p.Sections = []string{}
	selected, _ = Select(a, p)
	if len(selected.Sections) != 0 {
		t.Fatal("empty section selection restored legacy inventory")
	}
}

func TestChartsCountEveryFactWithoutLeakingDynamicLabels(t *testing.T) {
	a := Assessment{Findings: []Finding{{Priority: "Medium", Title: "SECRET_NAME"}, {Priority: "SECRET_PRIORITY"}}, Exposures: []Exposure{{Kind: "static_nat", Type: "SECRET_TYPE", Name: "SECRET_NAME", Outcome: "Configured permit", GeoStatus: "Applicable"}, {Kind: "SECRET_KIND", Outcome: "SECRET_OUTCOME", GeoStatus: "SECRET_GEO"}}}
	charts := ChartSeries(a, "all")
	if len(charts) != 4 {
		t.Fatalf("charts=%d", len(charts))
	}
	for _, chart := range charts {
		sum := 0
		for _, point := range chart.Points {
			sum += point.Value
		}
		if sum != 2 {
			t.Fatalf("%s count lost unknown input: %d", chart.ID, sum)
		}
	}
	data, err := json.Marshal(charts)
	if err != nil || bytes.Contains(data, []byte("SECRET")) {
		t.Fatal("chart labels disclosed source-derived values")
	}
	if len(ChartSeries(a, "unrecognized")) != 0 || len(ChartSeries(a, "priority")) != 1 {
		t.Fatal("chart allowlist failed")
	}
}
