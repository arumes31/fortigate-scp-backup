package reportmodel

import (
	"fmt"
	"sort"
)

type Counts struct {
	VDOMs     int `json:"vdoms"`
	Exposures int `json:"exposures"`
	Findings  int `json:"findings"`
	Sections  int `json:"sections"`
	Rows      int `json:"rows"`
	Traces    int `json:"traces"`
}

type Selection struct {
	Original      Counts  `json:"original"`
	Selected      Counts  `json:"selected"`
	Filters       Filters `json:"filters"`
	Filtered      bool    `json:"filtered"`
	Description   string  `json:"description"`
	DescriptionDE string  `json:"description_de"`
}

// Select filters the already completed analysis. It never recomputes policy
// outcomes from a subset of rules. Every selected exposure retains its complete
// trace. Blank VDOMs denote appliance-wide rows/findings, which remain visible.
// Visibility flags are renderer options and do not change the selected facts.
func Select(a Assessment, p Profile) (Assessment, Selection) {
	selected := a
	selected.VDOMs = []string{}
	selected.Warnings = append([]string{}, a.Warnings...)
	selected.Exposures = []Exposure{}
	selected.Findings = []Finding{}
	selected.Sections = []Section{}
	selected.Telemetry = cloneTelemetry(a.Telemetry)
	filters := cloneFilters(p.Filters)
	selection := Selection{Original: countAssessment(a), Filters: filters}
	vdoms := valueSet(filters.VDOMs)
	types := valueSet(filters.Types)
	outcomes := valueSet(filters.Outcomes)
	priorities := valueSet(filters.Priorities)
	sections := valueSet(p.Sections)
	allowLegacy := len(vdoms) == 0
	for _, section := range SectionDefinitions() {
		allowLegacy = allowLegacy && sections[section.ID]
	}
	legacyOmitted := false
	matchVDOM := func(vdom string) bool { return vdom == "" || len(vdoms) == 0 || vdoms[vdom] }
	for _, vdom := range a.VDOMs {
		if matchVDOM(vdom) {
			selected.VDOMs = append(selected.VDOMs, vdom)
		}
	}
	type exposureKey struct{ vdom, name string }
	exposures := map[exposureKey]bool{}
	for _, exposure := range a.Exposures {
		if !matchVDOM(exposure.VDOM) || len(types) != 0 && !types[exposure.Kind] || len(outcomes) != 0 && !outcomes[exposure.Outcome] {
			continue
		}
		exposures[exposureKey{exposure.VDOM, exposure.Name}] = true
		clone := exposure
		clone.Backends = append([]string{}, exposure.Backends...)
		clone.Groups = append([]string{}, exposure.Groups...)
		clone.PolicyIDs = append([]string{}, exposure.PolicyIDs...)
		clone.Notes = append([]string{}, exposure.Notes...)
		clone.Trace = append([]PolicyTrace{}, exposure.Trace...)
		selected.Exposures = append(selected.Exposures, clone)
	}
	for _, finding := range a.Findings {
		if finding.Category == "" && (len(vdoms)+len(types)+len(outcomes) > 0) {
			legacyOmitted = true
			continue
		}
		if !matchVDOM(finding.VDOM) || len(priorities) != 0 && !priorities[finding.Priority] {
			continue
		}
		if finding.Exposure != "" && !exposures[exposureKey{finding.VDOM, finding.Exposure}] {
			continue
		}
		selected.Findings = append(selected.Findings, finding)
	}
	for _, section := range a.Sections {
		if section.ID == "" && !allowLegacy {
			legacyOmitted = true
			continue
		}
		if section.ID != "" && !sections[section.ID] {
			continue
		}
		clone := section
		clone.Rows = []Row{}
		for _, row := range section.Rows {
			if matchVDOM(row.VDOM) {
				clone.Rows = append(clone.Rows, row)
			}
		}
		if len(clone.Rows) > 0 {
			selected.Sections = append(selected.Sections, clone)
		}
	}
	order := map[string]int{}
	for i, id := range p.Sections {
		order[id] = i
	}
	sort.SliceStable(selected.Sections, func(i, j int) bool {
		return order[selected.Sections[i].ID] < order[selected.Sections[j].ID]
	})
	selection.Selected = countAssessment(selected)
	if legacyOmitted {
		selected.Warnings = append(selected.Warnings, "Some legacy report facts lack typed section or scope metadata and were omitted from this selection. Regenerate from the saved configuration to apply these filters completely.")
	}
	selection.Filtered = len(vdoms)+len(types)+len(outcomes)+len(priorities) > 0 || selection.Original != selection.Selected
	selection.Description = fmt.Sprintf("Selected %d of %d publications, %d of %d findings, and %d of %d inventory rows. Appliance-wide context and assessment limitations are retained.", selection.Selected.Exposures, selection.Original.Exposures, selection.Selected.Findings, selection.Original.Findings, selection.Selected.Rows, selection.Original.Rows)
	selection.DescriptionDE = fmt.Sprintf("Ausgewählt: %d von %d Veröffentlichungen, %d von %d Feststellungen und %d von %d Inventareinträgen. Übergreifender Kontext und Analysegrenzen bleiben erhalten.", selection.Selected.Exposures, selection.Original.Exposures, selection.Selected.Findings, selection.Original.Findings, selection.Selected.Rows, selection.Original.Rows)
	return selected, selection
}

func cloneTelemetry(telemetry *Telemetry) *Telemetry {
	if telemetry == nil {
		return nil
	}
	clone := *telemetry
	clone.Sources = append([]string{}, telemetry.Sources...)
	clone.VDOMs = append([]string{}, telemetry.VDOMs...)
	clone.Datasets = append([]TelemetryDataset{}, telemetry.Datasets...)
	for i := range clone.Datasets {
		clone.Datasets[i].MissingFields = append([]string{}, telemetry.Datasets[i].MissingFields...)
		clone.Datasets[i].Rows = append([]TelemetryRow{}, telemetry.Datasets[i].Rows...)
		for j := range clone.Datasets[i].Rows {
			row := &clone.Datasets[i].Rows[j]
			for _, ptr := range []**int64{&row.Bytes, &row.SentBytes, &row.ReceivedBytes} {
				if *ptr != nil {
					value := **ptr
					*ptr = &value
				}
			}
		}
	}
	return &clone
}

func countAssessment(a Assessment) Counts {
	c := Counts{VDOMs: len(a.VDOMs), Exposures: len(a.Exposures), Findings: len(a.Findings), Sections: len(a.Sections)}
	for _, exposure := range a.Exposures {
		c.Traces += len(exposure.Trace)
	}
	for _, section := range a.Sections {
		c.Rows += len(section.Rows)
	}
	return c
}

func cloneFilters(f Filters) Filters {
	return Filters{
		VDOMs: append([]string{}, f.VDOMs...), Types: append([]string{}, f.Types...),
		Outcomes: append([]string{}, f.Outcomes...), Priorities: append([]string{}, f.Priorities...),
	}
}

func valueSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
