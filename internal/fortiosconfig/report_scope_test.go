package fortiosconfig

import (
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func TestReportMetadataRetainsTypedVDOMAndGlobalOwnership(t *testing.T) {
	global := `config global
config system interface
    edit "a-wan"
        set vdom "a"
        set role wan
        set allowaccess https
    next
    edit "b-wan"
        set vdom "b"
        set role wan
        set allowaccess ssh
    next
end
config system ha
    set mode a-p
end
end
`
	policies := "config firewall policy\n" + testPolicy("900", "deny", "GeoCN", "all", "set match-vip enable") + testPolicy("1", "accept", "all", "Portal", "") + "end\n"
	config := testHeader + global + "config vdom\nedit a\n" + testObjects + policies + "next\nedit b\n" + testObjects + policies + "next\nend\n"
	a := assessment(t, config)
	allowed := map[string]bool{}
	for _, definition := range reportmodel.SectionDefinitions() {
		allowed[definition.ID] = true
	}
	for _, section := range a.Sections {
		if !allowed[section.ID] {
			t.Fatalf("section has no stable allowlisted ID: %+v", section)
		}
		if section.ID == "ha" && section.Rows[0].VDOM != "" {
			t.Fatal("global HA was assigned to an unrelated root VDOM")
		}
	}
	for _, finding := range a.Findings {
		if finding.Category == "" {
			t.Fatalf("finding has no typed category: %+v", finding)
		}
		if finding.Category == "publications" && (finding.Exposure != "Portal" || finding.VDOM != "a" && finding.VDOM != "b") {
			t.Fatalf("publication ownership is missing: %+v", finding)
		}
	}
	p := reportmodel.DefaultProfile("en")
	p.Filters.VDOMs = []string{"a"}
	p.Filters.Types = []string{"static_nat"}
	selected, _ := reportmodel.Select(a, p)
	if len(selected.Exposures) != 1 || selected.Exposures[0].Kind != "static_nat" || selected.Exposures[0].VDOM != "a" || len(selected.Exposures[0].Trace) != 2 {
		t.Fatalf("typed scope damaged publication analysis: %+v", selected.Exposures)
	}
	foundGlobal := false
	for _, section := range selected.Sections {
		for _, row := range section.Rows {
			if row.VDOM == "b" {
				t.Fatal("another VDOM leaked through the typed selection")
			}
			foundGlobal = foundGlobal || section.ID == "ha"
		}
	}
	if !foundGlobal {
		t.Fatal("appliance-wide context was dropped")
	}
	for _, finding := range selected.Findings {
		if finding.VDOM == "b" {
			t.Fatal("another VDOM's finding survived selection")
		}
	}
}
