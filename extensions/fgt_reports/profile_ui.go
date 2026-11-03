package fgt_reports

import (
	"slices"
	"strconv"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

// Profile pages contain presentation data only. Authorization, persistence,
// uploads, revision checks and scheduling stay in the request handlers.
type reportChoice struct {
	ID       string
	Label    string
	Help     string
	Selected bool
}

type reportSourceChoice struct {
	ID    int
	Label string
}

type profilePageData struct {
	Base        webui.BaseData
	Source      reportmodel.Source
	Profile     reportmodel.Profile
	Revision    string
	HasReport   bool
	Sections    []reportChoice
	Charts      []reportChoice
	VDOMs       []reportChoice
	Types       []reportChoice
	Outcomes    []reportChoice
	Priorities  []reportChoice
	Macros      []reportChoice
	Weekdays    []reportChoice
	CopySources []reportSourceChoice
	NextDue     string
	Notice      string
	Error       string
}

type reportCatalogItem struct {
	ID           string
	Title        string
	Description  string
	Availability string
	Requirement  string
	Fields       string
	SourceURL    string
}

type catalogPageData struct {
	Base              webui.BaseData
	Families          []reportCatalogItem
	Datasets          []reportCatalogItem
	GraylogConfigured bool
}

type reportScheduleRow struct {
	FirewallID int
	Firewall   string
	Profile    string
	Frequency  string
	Timezone   string
	NextDue    string
}

type calendarPageData struct {
	Base webui.BaseData
	Rows []reportScheduleRow
}

func buildProfileView(base webui.BaseData, source reportmodel.Source, profile reportmodel.Profile, assessment reportmodel.Assessment, copySources []reportmodel.Source, nextDue string) profilePageData {
	view := profilePageData{Base: base, Source: source, Profile: profile, Revision: reportmodel.ProfileHash(profile), NextDue: nextDue}
	view.HasReport = assessment.Firmware != "" || assessment.Telemetry != nil
	view.Sections = orderedProfileOptions(base.Lang, reportmodel.SectionDefinitions(), profile.Sections)
	view.Charts = orderedProfileOptions(base.Lang, reportmodel.ChartDefinitions(), profile.Charts)
	view.Types = profileOptions(base.Lang, reportmodel.TypeDefinitions(), profile.Filters.Types)
	view.Outcomes = profileOptions(base.Lang, reportmodel.OutcomeDefinitions(), profile.Filters.Outcomes)
	view.Priorities = profileOptions(base.Lang, reportmodel.PriorityDefinitions(), profile.Filters.Priorities)
	view.Macros = profileOptions(base.Lang, reportmodel.MacroDefinitions(), nil)
	for index := range view.Macros {
		view.Macros[index].ID = "{{" + view.Macros[index].ID + "}}"
	}
	vdoms := slices.Clone(assessment.VDOMs)
	// Keep saved filters editable even if a VDOM is absent from the latest
	// already-filtered report, or the latest source has not been generated yet.
	for _, vdom := range profile.Filters.VDOMs {
		if !slices.Contains(vdoms, vdom) {
			vdoms = append(vdoms, vdom)
		}
	}
	slices.Sort(vdoms)
	for _, vdom := range slices.Compact(vdoms) {
		view.VDOMs = append(view.VDOMs, reportChoice{ID: vdom, Label: vdom, Selected: slices.Contains(profile.Filters.VDOMs, vdom)})
	}
	for day := range 7 {
		id := strconv.Itoa(day)
		view.Weekdays = append(view.Weekdays, reportChoice{ID: id, Label: reportText(base.Lang, "weekday_"+id), Selected: profile.Schedule.Weekday == day})
	}
	for _, other := range copySources {
		if other.FirewallID != source.FirewallID {
			view.CopySources = append(view.CopySources, reportSourceChoice{ID: other.FirewallID, Label: other.Firewall})
		}
	}
	slices.SortFunc(view.CopySources, func(a, b reportSourceChoice) int {
		if a.Label < b.Label {
			return -1
		}
		if a.Label > b.Label {
			return 1
		}
		return a.ID - b.ID
	})
	return view
}

func buildCatalogView(base webui.BaseData) catalogPageData {
	view := catalogPageData{Base: base}
	for _, capability := range reportmodel.Capabilities() {
		item := reportCatalogItem{ID: capability.ID, Title: capability.Name, Description: capability.Description, Availability: capability.Status, Requirement: strings.Join(capability.Requirements, ", "), SourceURL: capability.SourceURL}
		if base.Lang == "de" {
			if capability.NameDE != "" {
				item.Title = capability.NameDE
			}
			if capability.DescriptionDE != "" {
				item.Description = capability.DescriptionDE
			}
		}
		view.Families = append(view.Families, item)
	}
	for _, definition := range reportmodel.DatasetDefinitions() {
		item := reportCatalogItem{ID: definition.ID, Title: definition.Name, Description: definition.Description, Availability: definition.Status, Requirement: strings.Join(definition.RequiredData, ", ")}
		if base.Lang == "de" {
			if definition.NameDE != "" {
				item.Title = definition.NameDE
			}
			if definition.DescriptionDE != "" {
				item.Description = definition.DescriptionDE
			}
		}
		fields := make([]string, 0, len(definition.Columns))
		for _, column := range definition.Columns {
			label := column.Label
			if base.Lang == "de" && column.LabelDE != "" {
				label = column.LabelDE
			}
			fields = append(fields, label)
		}
		item.Fields = strings.Join(fields, ", ")
		view.Datasets = append(view.Datasets, item)
	}
	return view
}

func profileOptions(lang string, definitions []reportmodel.Option, selected []string) []reportChoice {
	choices := make([]reportChoice, 0, len(definitions))
	for _, definition := range definitions {
		label := definition.Label
		if lang == "de" && definition.LabelDE != "" {
			label = definition.LabelDE
		}
		choices = append(choices, reportChoice{ID: definition.ID, Label: label, Selected: slices.Contains(selected, definition.ID)})
	}
	return choices
}

// HTML submits checked controls in document order. Keep the stored sequence
// first so a later edit does not silently restore registry/default ordering.
func orderedProfileOptions(lang string, definitions []reportmodel.Option, selected []string) []reportChoice {
	canonical := profileOptions(lang, definitions, selected)
	byID := make(map[string]reportChoice, len(canonical))
	for _, choice := range canonical {
		byID[choice.ID] = choice
	}
	choices := make([]reportChoice, 0, len(canonical))
	for _, id := range selected {
		if choice, ok := byID[id]; ok {
			choices = append(choices, choice)
			delete(byID, id)
		}
	}
	for _, choice := range canonical {
		if _, ok := byID[choice.ID]; ok {
			choices = append(choices, choice)
		}
	}
	return choices
}
