package renderpdf

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// Title returns the localized title for a supported report kind.
func Title(kind, lang string) string {
	switch kind {
	case "forwarding":
		return choose(lang, "Port Forwarding & Exposure", "Portweiterleitungen & Erreichbarkeit")
	case "technical":
		return choose(lang, "Technical Configuration Report", "Technischer Konfigurationsbericht")
	case "traffic":
		return choose(lang, "Traffic & Log Observations", "Verkehrs- und Logbeobachtungen")
	default:
		return "FortiSafe Reports"
	}
}

func project(source reportmodel.Source, a reportmodel.Assessment, kind, lang string) content {
	return projectVisible(source, a, kind, lang, true, true, true)
}

func projectVisible(source reportmodel.Source, a reportmodel.Assessment, kind, lang string, showInventory, showFindings, showTraces bool) content {
	c := baseContent(source, kind, lang)
	c.Blocks = append(c.Blocks, block{Text: choose(lang,
		"Assessment of the saved configuration. Operational status and external reachability have not been tested. Policy conclusions apply only to the supported conditions described in this report.",
		"Bewertung der gespeicherten Konfiguration. Betriebszustand und externe Erreichbarkeit wurden nicht getestet. Richtlinienaussagen gelten nur für die im Bericht beschriebenen unterstützten Bedingungen.")})
	c.Blocks = append(c.Blocks, mainBlock(provenance(source, a, lang)))
	c.Blocks = append(c.Blocks, coverage(a, lang)...)
	if kind == "forwarding" {
		c.Blocks = append(c.Blocks, forwardingContentVisible(a, lang, showTraces)...)
		if showInventory {
			c.Blocks = append(c.Blocks, technicalInventory(a, lang)...)
		}
		if showFindings {
			c.Blocks = append(c.Blocks, findingContent(a, lang)...)
		}
	} else {
		c.Blocks = append(c.Blocks, technicalContentVisible(a, lang, showInventory, showFindings)...)
		c.Blocks = append(c.Blocks, block{Text: choose(lang,
			"Configuration evidence is not operational verification or compliance certification. Source references identify the selected backup's blocks and lines; raw configuration is not embedded.",
			"Konfigurationsnachweise sind keine Betriebsverifikation oder Konformitätszertifizierung. Quellenverweise identifizieren Blöcke und Zeilen des ausgewählten Backups; die Rohkonfiguration ist nicht eingebettet.")})
		return c
	}
	c.Blocks = append(c.Blocks, block{Contents: true, Heading: choose(lang, "Reading this report", "Hinweise zum Bericht"), Text: choose(lang,
		"Policy IDs identify rules; sequence numbers describe their order. A configured mapping is not a live reachability test. Unknown conditions are not a security pass. Source references identify the selected backup's configuration blocks and lines; raw backup content is not embedded. Characters outside the embedded font are shown as Unicode code points.",
		"Richtlinien-IDs identifizieren Regeln; Sequenznummern beschreiben ihre Reihenfolge. Eine konfigurierte Zuordnung ist kein Erreichbarkeitstest. Unbekannte Bedingungen sind kein Sicherheitsnachweis. Quellenverweise beziehen sich auf Blöcke und Zeilen des ausgewählten Backups; die Rohkonfiguration ist nicht eingebettet. Zeichen außerhalb der eingebetteten Schrift werden als Unicode-Codepunkte dargestellt.")})
	return c
}

func baseContent(source reportmodel.Source, kind, lang string) content {
	identity := source.Firewall
	if identity == "" {
		identity = fmt.Sprintf("Firewall #%d", source.FirewallID)
	}
	return content{
		Title:          Title(kind, lang),
		Identification: identity,
		Footer: fmt.Sprintf("FortiSafe | FW #%d | Backup #%d | %s %s", source.FirewallID, source.BackupID,
			choose(lang, "Reports", "Berichte"), reportmodel.Version),
	}
}

func provenance(source reportmodel.Source, a reportmodel.Assessment, lang string) block {
	return fields(choose(lang, "Snapshot and scope", "Snapshot und Umfang"), lang, [][]string{
		{choose(lang, "Source backup", "Quellbackup"), fmt.Sprintf("#%d | %s", source.BackupID, formatTime(source.BackupAt, lang))},
		{choose(lang, "Report generated", "Bericht erstellt"), formatTime(source.GeneratedAt, lang)},
		{choose(lang, "Configuration SHA-256", "Konfiguration SHA-256"), checksum(source.Checksum, lang)},
		{choose(lang, "Firmware", "Firmware"), value(a.Firmware, lang)},
		{choose(lang, "Configured hostname", "Konfigurierter Hostname"), value(a.Hostname, lang)},
		{"VDOMs", strings.Join(a.VDOMs, ", ")},
		{choose(lang, "Assessment schema", "Bewertungsschema"), reportmodel.Version},
	})
}

func fields(title, lang string, rows [][]string) block {
	return block{Heading: title, Columns: []string{choose(lang, "Field", "Feld"), choose(lang, "Configuration / evidence", "Konfiguration / Nachweis")}, Widths: []float64{1, 3}, Rows: rows}
}

func coverage(a reportmodel.Assessment, lang string) []block {
	state := choose(lang, "Complete for the implemented checks and supported configuration conditions.", "Vollständig für die implementierten Prüfungen und unterstützten Konfigurationsbedingungen.")
	if !a.Complete {
		state = choose(lang, "Analysis has limitations. Review the conditions below before using policy conclusions.", "Die Analyse ist eingeschränkt. Beachten Sie die folgenden Bedingungen, bevor Sie Richtlinienaussagen verwenden.")
	}
	blocks := []block{{Contents: true, Heading: choose(lang, "Analysis coverage", "Analyseumfang"), Text: state}}
	for _, warning := range a.Warnings {
		blocks = append(blocks, block{Text: "- " + warning})
	}
	return blocks
}

func forwardingContentVisible(a reportmodel.Assessment, lang string, showTraces bool) []block {
	backends, traces := 0, 0
	for _, exposure := range a.Exposures {
		backends += len(exposure.Backends)
		traces += len(exposure.Trace)
	}
	blocks := []block{mainBlock(fields(choose(lang, "Inventory summary", "Inventarübersicht"), lang, [][]string{
		{choose(lang, "VIP / virtual-server definitions", "VIP- / Virtual-Server-Definitionen"), strconv.Itoa(len(a.Exposures))},
		{choose(lang, "Configured backend entries", "Konfigurierte Backend-Einträge"), strconv.Itoa(backends)},
		{choose(lang, "Recorded policy trace entries", "Erfasste Richtlinien-Schritte"), strconv.Itoa(traces)},
	}))}
	if len(a.Exposures) == 0 {
		return append(blocks, block{Text: choose(lang,
			"No VIP or virtual-server definitions were detected in the analyzed scope. This does not establish that the firewall has no externally accessible services.",
			"Im analysierten Umfang wurden keine VIP- oder Virtual-Server-Definitionen erkannt. Daraus folgt nicht, dass die Firewall keine extern erreichbaren Dienste hat.")})
	}
	blocks = append(blocks, inventory(a.Exposures, lang))
	for index, exposure := range a.Exposures {
		blocks = append(blocks, exposureDetail(index+1, exposure, lang, showTraces)...)
	}
	return blocks
}

func inventory(exposures []reportmodel.Exposure, lang string) block {
	b := block{
		Contents: true, Heading: choose(lang, "Forwarding inventory", "Weiterleitungsinventar"),
		Columns: []string{choose(lang, "VIP / virtual server", "VIP / Virtual Server"), choose(lang, "VDOM / type", "VDOM / Typ"), choose(lang, "External listener", "Externer Listener"), choose(lang, "Assessment", "Bewertung")},
		Widths:  []float64{1.45, 1, 1.4, 1.15},
	}
	for _, e := range exposures {
		b.Rows = append(b.Rows, []string{e.Name, e.VDOM + " / " + e.Type, e.External, e.Outcome})
	}
	return b
}

// The technical report has no per-publication detail cards, so its summary
// retains the backend mapping and geographic assessment alongside each VIP.
func technicalForwardingInventory(exposures []reportmodel.Exposure, lang string) block {
	b := block{
		Contents: true, Heading: choose(lang, "Forwarding inventory", "Weiterleitungsinventar"),
		Columns: []string{choose(lang, "VDOM / object / type", "VDOM / Objekt / Typ"), choose(lang, "External listener", "Externer Listener"), choose(lang, "Backend mapping", "Backend-Zuordnung"), choose(lang, "Assessment", "Bewertung")},
		Widths:  []float64{1.15, 1.15, 1.25, 1.15},
	}
	for _, e := range exposures {
		b.Rows = append(b.Rows, []string{e.VDOM + " / " + e.Name + "\n" + e.Type, e.External,
			strings.Join(e.Backends, "\n"), e.Outcome + "\nGeo: " + e.GeoStatus})
	}
	return b
}

func exposureDetail(number int, e reportmodel.Exposure, lang string, showTraces bool) []block {
	rows := [][]string{
		{choose(lang, "Source", "Quelle"), e.External + " · " + e.ExternalInterface},
		{choose(lang, "Configured backends", "Konfigurierte Backends"), strings.Join(e.Backends, "\n")},
		{choose(lang, "Geographic restrictions", "Geografische Einschränkungen"), e.GeoStatus},
		{choose(lang, "VIP groups", "VIP-Gruppen"), strings.Join(e.Groups, ", ")},
		{choose(lang, "Evidence", "Nachweis"), e.Evidence},
		{choose(lang, "Related policy IDs", "Zugehörige Richtlinien-IDs"), strings.Join(e.PolicyIDs, ", ")},
	}
	detail := fields(fmt.Sprintf("%d. %s", number, e.Name), lang, rows)
	detail.Layout, detail.Badge = "publication", e.Outcome
	detail.Text = e.VDOM + " · " + e.Type + " · " + e.External
	blocks := []block{detail}
	for _, note := range e.Notes {
		blocks = append(blocks, block{Text: "- " + note})
	}
	if !showTraces {
		return append(blocks, block{Text: choose(lang, "Policy trace details are hidden by the selected profile. The assessment was computed from the complete configuration.", "Richtliniendetails sind im gewählten Profil ausgeblendet. Die Bewertung wurde aus der vollständigen Konfiguration ermittelt.")})
	}
	if len(e.Trace) == 0 {
		return append(blocks, block{Text: choose(lang,
			"No supported policy trace was established. See the assessment and coverage notes; this does not prove that the object has no network effect.",
			"Es konnte kein unterstützter Richtlinienpfad ermittelt werden. Beachten Sie Bewertung und Analysehinweise; dies beweist nicht, dass das Objekt keine Netzwirkung hat.")})
	}
	trace := block{Layout: "policies", Heading: e.Name + " / " + choose(lang, "Policy sequence", "Richtlinienreihenfolge"),
		Columns: []string{choose(lang, "# / Policy", "# / Richtlinie"), choose(lang, "Action", "Aktion"), choose(lang, "Source → Destination", "Quelle → Ziel"), choose(lang, "Service / Schedule", "Dienst / Zeitplan"), choose(lang, "Assessment", "Bewertung")},
		Widths:  []float64{1.15, 1, 1.55, 1.2, 1.5},
	}
	for _, p := range e.Trace {
		trace.Rows = append(trace.Rows, []string{
			fmt.Sprintf("%d / ID %s\n%s\n%s", p.Sequence, p.ID, p.Name, p.Evidence),
			actionLabel(p.Action, lang) + "\n" + p.Status + "\nmatch-vip: " + p.VIPMatch,
			p.Source + " → " + p.Destination + "\n" + p.SourceInterface + " → " + p.DestinationInterface,
			p.Service + "\n" + p.Schedule + "\n" + choose(lang, "Security profiles: ", "Sicherheitsprofile: ") + p.Profiles + "\n" + choose(lang, "Logging: ", "Protokollierung: ") + p.Logging,
			p.Effect,
		})
		trace.Actions = append(trace.Actions, p.Action)
	}
	return append(blocks, trace)
}

func technicalContentVisible(a reportmodel.Assessment, lang string, showInventory, showFindings bool) []block {
	blocks := []block{{Contents: true, Heading: choose(lang, "Engineering summary", "Technische Zusammenfassung"), Text: fmt.Sprintf(choose(lang,
		"The selected configuration contains %d detected publication definitions across %d VDOMs. The assessment recorded %d review observations. Configured VPN, HA, routing and security-profile settings are configuration evidence; their operational state has not been verified.",
		"Die ausgewählte Konfiguration enthält %d erkannte Veröffentlichungsdefinitionen in %d VDOMs. Die Bewertung enthält %d Prüfpunkte. Konfigurierte VPN-, HA-, Routing- und Sicherheitsprofileinstellungen sind Konfigurationsnachweise; ihr Betriebszustand wurde nicht verifiziert."),
		len(a.Exposures), len(a.VDOMs), len(a.Findings))}}
	if showInventory {
		blocks = append(blocks, technicalInventory(a, lang)...)
		if len(a.Exposures) > 0 {
			blocks = append(blocks, technicalForwardingInventory(a.Exposures, lang), block{Text: choose(lang,
				"The Port Forwarding & Exposure report from this same backup contains the full per-object rule traces and geographic restriction explanations.",
				"Der Bericht zu Portweiterleitungen aus demselben Backup enthält die vollständigen Richtlinienpfade und Erklärungen zu geografischen Einschränkungen je Objekt.")})
		}
	}
	if !showFindings {
		return blocks
	}
	return append(blocks, findingContent(a, lang)...)
}

func technicalInventory(a reportmodel.Assessment, lang string) []block {
	blocks := []block{{Contents: true, Heading: choose(lang, "Technical inventory", "Technisches Inventar")}}
	for _, section := range a.Sections {
		rows := make([][]string, 0, len(section.Rows))
		for _, row := range section.Rows {
			detail := row.Value
			if row.Evidence != "" {
				detail += "\n" + choose(lang, "Source: ", "Quelle: ") + row.Evidence
			}
			rows = append(rows, []string{row.Label, detail})
		}
		b := fields(localized(lang, section.Title, section.TitleDE), lang, rows)
		b.Layout, b.Badge = "inventory", strconv.Itoa(len(rows))
		blocks = append(blocks, b)
	}
	return blocks
}

func findingContent(a reportmodel.Assessment, lang string) []block {
	blocks := []block{{Contents: true, Heading: choose(lang, "Review findings", "Prüfergebnisse")}}
	if len(a.Findings) == 0 {
		return append(blocks, block{Text: choose(lang,
			"The implemented checks recorded no findings. This is not a complete security assessment or compliance certification; review the analysis coverage.",
			"Die implementierten Prüfungen haben keine Feststellungen erfasst. Dies ist keine vollständige Sicherheitsbewertung oder Konformitätszertifizierung; beachten Sie den Analyseumfang.")})
	}
	for index, f := range a.Findings {
		b := fields(fmt.Sprintf("%d. %s", index+1, localized(lang, f.Title, f.TitleDE)), lang, [][]string{
			{choose(lang, "Recommended action", "Empfohlene Maßnahme"), localized(lang, f.Recommendation, f.RecommendationDE)},
			{choose(lang, "Source reference", "Quellenverweis"), f.Evidence},
			{choose(lang, "Reference", "Referenz"), f.ID},
		})
		b.Layout, b.Badge, b.Text = "finding", f.Priority, localized(lang, f.Detail, f.DetailDE)
		blocks = append(blocks, b)
	}
	return blocks
}

func localized(lang, en, de string) string {
	if lang == "de" && de != "" {
		return de
	}
	return en
}

func formatTime(t time.Time, lang string) string {
	if t.IsZero() {
		return choose(lang, "Not available", "Nicht verfügbar")
	}
	return t.Format(time.RFC3339)
}

func value(s, lang string) string {
	if s == "" {
		return choose(lang, "Not established from this backup", "Aus diesem Backup nicht ermittelt")
	}
	return s
}

func checksum(s, lang string) string {
	if len(s) != 64 {
		return choose(lang, "Not available", "Nicht verfügbar")
	}
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != 32 {
		return choose(lang, "Not available", "Nicht verfügbar")
	}
	return strings.ToLower(s)
}

func mainBlock(b block) block { b.Contents = true; return b }
