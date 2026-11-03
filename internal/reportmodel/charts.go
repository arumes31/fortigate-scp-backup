package reportmodel

type ChartPoint struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	LabelDE string `json:"label_de"`
	Value   int    `json:"value"`
}

type Chart struct {
	ID      string       `json:"id"`
	Title   string       `json:"title"`
	TitleDE string       `json:"title_de"`
	Unit    string       `json:"unit"`
	Points  []ChartPoint `json:"points"`
}

// ChartSeries contains configuration counts only. Its labels are a fixed
// allowlist and cannot disclose object names, IPs, users, or arbitrary values.
// kind is priority, type, outcome, or geo; empty/all returns all four charts.
func ChartSeries(a Assessment, kind string) []Chart {
	charts := []Chart{}
	for _, definition := range ChartDefinitions() {
		if kind != "" && kind != "all" && kind != definition.ID {
			continue
		}
		var options []Option
		values := map[string]int{}
		switch definition.ID {
		case "priority":
			options = PriorityDefinitions()
			for _, finding := range a.Findings {
				values[finding.Priority]++
			}
		case "type":
			options = TypeDefinitions()
			for _, exposure := range a.Exposures {
				values[exposure.Kind]++
			}
		case "outcome":
			options = OutcomeDefinitions()
			for _, exposure := range a.Exposures {
				values[exposure.Outcome]++
			}
		case "geo":
			options = GeoDefinitions()
			for _, exposure := range a.Exposures {
				values[exposure.GeoStatus]++
			}
		}
		chart := Chart{ID: definition.ID, Title: definition.Label, TitleDE: definition.LabelDE, Unit: "count", Points: []ChartPoint{}}
		for _, option := range options {
			chart.Points = append(chart.Points, ChartPoint{ID: option.ID, Label: option.Label, LabelDE: option.LabelDE, Value: values[option.ID]})
			delete(values, option.ID)
		}
		unknown := 0
		for _, count := range values {
			unknown += count
		}
		if unknown > 0 {
			chart.Points = append(chart.Points, ChartPoint{ID: "unclassified", Label: "Unclassified", LabelDE: "Nicht zugeordnet", Value: unknown})
		}
		charts = append(charts, chart)
	}
	return charts
}
