package renderpdf

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// RenderWithProfile renders an audience-specific report from one immutable
// assessment and the profile captured for it. Selection follows complete
// policy analysis; retained publications keep their complete rule traces.
func RenderWithProfile(ctx context.Context, source reportmodel.Source, a reportmodel.Assessment, kind string, p reportmodel.Profile) ([]byte, error) {
	view, options, _, err := prepare(ctx, source, a, kind, p)
	if err != nil {
		return nil, err
	}
	return renderDocument(ctx, source, view, options)
}

func prepare(ctx context.Context, source reportmodel.Source, a reportmodel.Assessment, kind string, p reportmodel.Profile) (content, renderOptions, string, error) {
	var empty content
	var options renderOptions
	if ctx == nil {
		return empty, options, "", errors.New("reports: context is required")
	}
	if err := ctx.Err(); err != nil {
		return empty, options, "", err
	}
	if kind != "forwarding" && kind != "technical" && kind != "customer" && kind != "traffic" {
		return empty, options, "", errors.New("reports: unsupported report type")
	}
	p, err := reportmodel.NormalizeProfile(p)
	if err != nil {
		return empty, options, "", fmt.Errorf("reports: invalid profile: %w", err)
	}
	// Select copies slices for isolation, so bound the full input before it is
	// called, including technical fields that a customer projection will omit.
	for _, scope := range []string{"forwarding", "technical"} {
		if err := validateProjection(ctx, source, a, scope); err != nil {
			return empty, options, "", err
		}
	}
	if err := validateTelemetry(ctx, a.Telemetry); err != nil {
		return empty, options, "", err
	}
	selected, selection := reportmodel.Select(a, p)
	if err := ctx.Err(); err != nil {
		return empty, options, "", err
	}
	if !p.Traffic {
		selected.Telemetry = &reportmodel.Telemetry{Status: "disabled"}
	}
	var view content
	if kind == "traffic" {
		view = trafficContent(source, selected.Telemetry, p.Language)
	} else {
		view = projectVisible(source, selected, kind, p.Language, p.ShowInventory, p.ShowFindings, p.ShowTraces)
	}
	if kind == "customer" && p.Customer != "" {
		view.Identification = p.Customer
	}
	view.Company = p.Organization
	macros := map[string]string{
		"firewall": view.Identification, "firewall_id": strconv.Itoa(source.FirewallID), "backup_id": strconv.Itoa(source.BackupID),
		"backup_at": formatTime(source.BackupAt, p.Language), "generated_at": formatTime(source.GeneratedAt, p.Language),
		"publication_count": strconv.Itoa(selection.Selected.Exposures), "finding_count": strconv.Itoa(selection.Selected.Findings),
		"vdom_count": strconv.Itoa(selection.Selected.VDOMs), "organization": p.Organization, "customer": p.Customer, "report_title": view.Title,
	}
	for _, field := range []struct {
		input  string
		output *string
		limit  int
	}{
		{p.Subtitle, &view.Subtitle, 240}, {p.Intro, &view.Introduction, 4000},
	} {
		*field.output, err = expandMacros(field.input, macros, field.limit)
		if err != nil {
			return empty, options, "", err
		}
	}
	footer, err := expandMacros(p.Footer, macros, 300)
	if err != nil {
		return empty, options, "", err
	}
	if footer != "" {
		view.Footer += " | " + footer
	}
	hash := reportmodel.ProfileHash(p)
	if hash == "" {
		return empty, options, "", errors.New("reports: profile hash unavailable")
	}
	profile := profileBlock(p, selection, hash, kind)
	var extra []block
	extra = append(extra, profile)
	if kind != "traffic" {
		for _, id := range p.Charts {
			for _, series := range reportmodel.ChartSeries(selected, id) {
				extra = append(extra, chartBlock(series, p.Language))
			}
		}
	}
	view.Blocks = append(extra, view.Blocks...)
	if (kind == "technical" || kind == "customer") && selected.Telemetry != nil {
		view.Blocks = append(view.Blocks, telemetrySummary(selected.Telemetry, p.Language, kind == "customer")...)
	}
	if kind == "customer" {
		for i := range view.Blocks {
			view.Blocks[i].Contents = view.Blocks[i].Heading != ""
		}
	}
	options = renderOptions{language: p.Language, landscape: p.Orientation == "landscape", cover: p.Cover, contents: p.Contents}
	rgb, _ := hex.DecodeString(p.Accent[1:]) // NormalizeProfile admits only #RRGGBB.
	copy(options.accent[:], rgb)
	if p.LogoBase64 != "" {
		options.logo, err = base64.StdEncoding.Strict().DecodeString(p.LogoBase64)
		if err != nil {
			return empty, options, "", errors.New("reports: invalid logo")
		}
		options.logoMIME = "image/png" // NormalizeProfile canonicalizes logos to PNG.
	}
	if err := cleanContent(ctx, &view, len(p.LogoBase64)); err != nil {
		return empty, options, "", err
	}
	return view, options, hash, nil
}

func expandMacros(input string, values map[string]string, maxRunes int) (string, error) {
	var result strings.Builder
	for input != "" {
		start := strings.Index(input, "{{")
		if start < 0 {
			result.WriteString(input)
			break
		}
		result.WriteString(input[:start])
		end := strings.Index(input[start+2:], "}}")
		if end < 0 {
			return "", errors.New("reports: unclosed profile macro")
		}
		key := input[start+2 : start+2+end]
		value, ok := values[key]
		if !ok {
			return "", errors.New("reports: unknown profile macro")
		}
		if len(value) > maxRunes*4-result.Len() {
			return "", errors.New("reports: expanded profile text exceeds limit")
		}
		result.WriteString(value)
		input = input[start+2+end+2:]
		if result.Len() > maxRunes*4 {
			return "", errors.New("reports: expanded profile text exceeds limit")
		}
	}
	value := result.String()
	if utf8.RuneCountInString(value) > maxRunes {
		return "", errors.New("reports: expanded profile text exceeds limit")
	}
	return value, nil
}

func profileBlock(p reportmodel.Profile, selection reportmodel.Selection, hash, kind string) block {
	lang := p.Language
	rows := [][]string{
		{choose(lang, "Profile revision", "Profilrevision"), hash},
		{choose(lang, "Selected configuration view", "Gewählte Konfigurationsansicht"), localized(lang, selection.Description, selection.DescriptionDE)},
	}
	if kind != "customer" {
		rows = append(rows, []string{choose(lang, "Profile", "Profil"), p.Name})
	}
	vdoms := choose(lang, "All virtual domains", "Alle virtuellen Domänen")
	if len(p.Filters.VDOMs) > 0 {
		if kind == "customer" {
			vdoms = fmt.Sprintf(choose(lang, "%d selected virtual-domain filters", "%d ausgewählte Domänenfilter"), len(p.Filters.VDOMs))
		} else {
			vdoms = strings.Join(p.Filters.VDOMs, ", ")
		}
	}
	rows = append(rows, []string{"VDOM", vdoms})
	for _, filter := range []struct {
		title       string
		values      []string
		definitions []reportmodel.Option
	}{
		{choose(lang, "Publication types", "Veröffentlichungstypen"), p.Filters.Types, reportmodel.TypeDefinitions()},
		{choose(lang, "Publication outcomes", "Veröffentlichungsergebnisse"), p.Filters.Outcomes, reportmodel.OutcomeDefinitions()},
		{choose(lang, "Finding priorities", "Prioritäten der Feststellungen"), p.Filters.Priorities, reportmodel.PriorityDefinitions()},
	} {
		labels := []string{}
		for _, id := range filter.values {
			for _, definition := range filter.definitions {
				if id == definition.ID {
					labels = append(labels, localized(lang, definition.Label, definition.LabelDE))
					break
				}
			}
		}
		value := choose(lang, "All", "Alle")
		if len(labels) > 0 {
			value = strings.Join(labels, ", ")
		}
		rows = append(rows, []string{filter.title, value})
	}
	shown := func(value bool) string {
		if value {
			return choose(lang, "Shown", "Angezeigt")
		}
		return choose(lang, "Hidden by profile", "Im Profil ausgeblendet")
	}
	rows = append(rows, []string{choose(lang, "Detailed findings", "Detaillierte Feststellungen"), shown(p.ShowFindings)})
	if kind != "customer" {
		rows = append(rows, []string{choose(lang, "Technical inventory", "Technisches Inventar"), shown(p.ShowInventory)}, []string{choose(lang, "Policy traces", "Richtlinienpfade"), shown(p.ShowTraces)})
	}
	b := mainBlock(fields(choose(lang, "Report profile and filters", "Berichtsprofil und Filter"), lang, rows))
	b.Text = choose(lang, "Configuration filters apply after full policy analysis. VDOM filters also scope Graylog queries. Publication type, publication outcome and finding-priority filters apply only to configuration observations. Logs retain their separate device and time-window scope.", "Konfigurationsfilter werden nach der vollständigen Richtlinienanalyse angewandt. VDOM-Filter grenzen auch Graylog-Abfragen ein. Filter für Veröffentlichungstyp, Veröffentlichungsergebnis und Feststellungspriorität gelten nur für Konfigurationsbeobachtungen. Logs behalten ihren eigenen Geräte- und Zeitumfang.")
	return b
}

func chartBlock(series reportmodel.Chart, lang string) block {
	c := &chart{ID: series.ID, Unit: choose(lang, "Count", "Anzahl"), Points: []chartPoint{}}
	rows := [][]string{}
	for _, point := range series.Points {
		if point.Value == 0 {
			continue
		}
		label := localized(lang, point.Label, point.LabelDE)
		c.Points = append(c.Points, chartPoint{Label: label, Value: int64(point.Value)})
		rows = append(rows, []string{label, strconv.Itoa(point.Value)})
	}
	if len(c.Points) == 0 {
		label := choose(lang, "No selected observations", "Keine ausgewählten Beobachtungen")
		c.Points = append(c.Points, chartPoint{Label: label, Value: 0})
		rows = append(rows, []string{label, "0"})
	}
	return block{Contents: true, Heading: localized(lang, series.Title, series.TitleDE),
		Text:    choose(lang, "Counts describe selected configuration definitions or review observations. They are not live traffic, incidents, or unique firewall policies. Zero-count categories are omitted.", "Die Zahlen beschreiben ausgewählte Konfigurationsdefinitionen oder Prüfpunkte. Sie sind keine Angaben zu Live-Verkehr, Vorfällen oder eindeutigen Firewall-Regeln. Kategorien ohne Einträge werden ausgelassen."),
		Columns: []string{choose(lang, "Category", "Kategorie"), c.Unit}, Widths: []float64{3, 1}, Rows: rows, Chart: c}
}

// Bound the expanded output model before JSON/XML encoders or HTML escaping
// allocate their working buffers. Six bytes per input byte bounds escaping;
// row overhead also bounds large collections of empty values.
func cleanContent(ctx context.Context, c *content, logoBytes int) error {
	remaining := maxText - 65536 - logoBytes
	clean := func(value *string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if remaining < 128 || len(*value) > (remaining-128)/6 {
			return errProjectionLimit
		}
		remaining -= 128 + 6*len(*value)
		*value = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\t' {
				return r
			}
			if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
				return -1
			}
			return r
		}, *value)
		return nil
	}
	for _, value := range []*string{&c.Title, &c.Identification, &c.Company, &c.Subtitle, &c.Introduction, &c.Footer} {
		if err := clean(value); err != nil {
			return err
		}
	}
	for i := range c.Blocks {
		b := &c.Blocks[i]
		if err := clean(&b.Heading); err != nil {
			return err
		}
		if err := clean(&b.Text); err != nil {
			return err
		}
		for j := range b.Columns {
			if err := clean(&b.Columns[j]); err != nil {
				return err
			}
		}
		for j := range b.Rows {
			remaining -= 512
			if remaining < 0 {
				return errProjectionLimit
			}
			for k := range b.Rows[j] {
				if err := clean(&b.Rows[j][k]); err != nil {
					return err
				}
			}
		}
		if b.Chart != nil {
			for j := range b.Chart.Points {
				if b.Chart.Points[j].Value < 0 {
					return errors.New("reports: invalid chart count")
				}
				if err := clean(&b.Chart.Points[j].Label); err != nil {
					return err
				}
			}
		}
	}
	return ctx.Err()
}
