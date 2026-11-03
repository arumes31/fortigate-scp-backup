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
	case "customer":
		return choose(lang, "Customer Review & Improvement Roadmap", "Kundenübersicht & Verbesserungsplan")
	default:
		return "FortiSafe Reports"
	}
}

func project(source reportmodel.Source, a reportmodel.Assessment, kind, lang string) content {
	if kind == "customer" {
		return customerContent(source, a, lang)
	}
	c := baseContent(source, kind, lang, false)
	c.Blocks = append(c.Blocks, block{Text: choose(lang,
		"Assessment of the saved configuration. Operational status and external reachability have not been tested. Policy conclusions apply only to the supported conditions described in this report.",
		"Bewertung der gespeicherten Konfiguration. Betriebszustand und externe Erreichbarkeit wurden nicht getestet. Richtlinienaussagen gelten nur für die im Bericht beschriebenen unterstützten Bedingungen.")})
	c.Blocks = append(c.Blocks, provenance(source, a, lang))
	c.Blocks = append(c.Blocks, coverage(a, lang)...)
	if kind == "forwarding" {
		c.Blocks = append(c.Blocks, forwardingContent(a, lang)...)
	} else {
		c.Blocks = append(c.Blocks, technicalContent(a, lang)...)
		c.Blocks = append(c.Blocks, block{Text: choose(lang,
			"Configuration evidence is not operational verification or compliance certification. Source references identify the selected backup's blocks and lines; raw configuration is not embedded.",
			"Konfigurationsnachweise sind keine Betriebsverifikation oder Konformitätszertifizierung. Quellenverweise identifizieren Blöcke und Zeilen des ausgewählten Backups; die Rohkonfiguration ist nicht eingebettet.")})
		return c
	}
	c.Blocks = append(c.Blocks, block{Heading: choose(lang, "Reading this report", "Hinweise zum Bericht"), Text: choose(lang,
		"Policy IDs identify rules; sequence numbers describe their order. A configured mapping is not a live reachability test. Unknown conditions are not a security pass. Source references identify the selected backup's configuration blocks and lines; raw backup content is not embedded. Characters outside the embedded font are shown as Unicode code points.",
		"Richtlinien-IDs identifizieren Regeln; Sequenznummern beschreiben ihre Reihenfolge. Eine konfigurierte Zuordnung ist kein Erreichbarkeitstest. Unbekannte Bedingungen sind kein Sicherheitsnachweis. Quellenverweise beziehen sich auf Blöcke und Zeilen des ausgewählten Backups; die Rohkonfiguration ist nicht eingebettet. Zeichen außerhalb der eingebetteten Schrift werden als Unicode-Codepunkte dargestellt.")})
	return c
}

func baseContent(source reportmodel.Source, kind, lang string, customer bool) content {
	identity := source.Firewall
	if identity == "" || customer {
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
	blocks := []block{{Heading: choose(lang, "Analysis coverage", "Analyseumfang"), Text: state}}
	for _, warning := range a.Warnings {
		blocks = append(blocks, block{Text: "- " + warning})
	}
	return blocks
}

func forwardingContent(a reportmodel.Assessment, lang string) []block {
	backends, traces := 0, 0
	for _, exposure := range a.Exposures {
		backends += len(exposure.Backends)
		traces += len(exposure.Trace)
	}
	blocks := []block{fields(choose(lang, "Inventory summary", "Inventarübersicht"), lang, [][]string{
		{choose(lang, "VIP / virtual-server definitions", "VIP- / Virtual-Server-Definitionen"), strconv.Itoa(len(a.Exposures))},
		{choose(lang, "Configured backend entries", "Konfigurierte Backend-Einträge"), strconv.Itoa(backends)},
		{choose(lang, "Recorded policy trace entries", "Erfasste Richtlinien-Schritte"), strconv.Itoa(traces)},
	})}
	if len(a.Exposures) == 0 {
		return append(blocks, block{Text: choose(lang,
			"No VIP or virtual-server definitions were detected in the analyzed scope. This does not establish that the firewall has no externally accessible services.",
			"Im analysierten Umfang wurden keine VIP- oder Virtual-Server-Definitionen erkannt. Daraus folgt nicht, dass die Firewall keine extern erreichbaren Dienste hat.")})
	}
	blocks = append(blocks, inventory(a.Exposures, lang))
	for index, exposure := range a.Exposures {
		blocks = append(blocks, exposureDetail(index+1, exposure, lang)...)
	}
	return blocks
}

func inventory(exposures []reportmodel.Exposure, lang string) block {
	b := block{
		Heading: choose(lang, "Forwarding inventory", "Weiterleitungsinventar"),
		Columns: []string{choose(lang, "VDOM / object", "VDOM / Objekt"), choose(lang, "External listener", "Externer Listener"), choose(lang, "Backend mapping", "Backend-Zuordnung"), choose(lang, "Assessment", "Bewertung")},
		Widths:  []float64{1.15, 1.15, 1.25, 1.15},
	}
	for _, e := range exposures {
		b.Rows = append(b.Rows, []string{e.VDOM + " / " + e.Name, e.External,
			strings.Join(e.Backends, "\n"), e.Outcome + "\n" + choose(lang, "Geo: ", "Geo: ") + e.GeoStatus})
	}
	return b
}

func exposureDetail(number int, e reportmodel.Exposure, lang string) []block {
	rows := [][]string{
		{choose(lang, "Type / VDOM", "Typ / VDOM"), e.Type + " / " + e.VDOM},
		{choose(lang, "External listener", "Externer Listener"), e.External},
		{choose(lang, "External interface settings", "Externe Schnittstelle / Filter"), e.ExternalInterface},
		{choose(lang, "Backends", "Backends"), strings.Join(e.Backends, "\n")},
		{choose(lang, "VIP groups", "VIP-Gruppen"), strings.Join(e.Groups, ", ")},
		{choose(lang, "Related policy IDs", "Zugehörige Richtlinien-IDs"), strings.Join(e.PolicyIDs, ", ")},
		{choose(lang, "Policy conclusion", "Richtlinienaussage"), e.Outcome},
		{choose(lang, "Geographic restriction", "Geografische Einschränkung"), e.GeoStatus},
		{choose(lang, "Source reference", "Quellenverweis"), e.Evidence},
	}
	blocks := []block{fields(fmt.Sprintf("%d. %s", number, e.Name), lang, rows)}
	for _, note := range e.Notes {
		blocks = append(blocks, block{Text: "- " + note})
	}
	if len(e.Trace) == 0 {
		return append(blocks, block{Text: choose(lang,
			"No supported policy trace was established. See the assessment and coverage notes; this does not prove that the object has no network effect.",
			"Es konnte kein unterstützter Richtlinienpfad ermittelt werden. Beachten Sie Bewertung und Analysehinweise; dies beweist nicht, dass das Objekt keine Netzwirkung hat.")})
	}
	for _, trace := range e.Trace {
		title := fmt.Sprintf("%s %d | %s %s", choose(lang, "Sequence", "Sequenz"), trace.Sequence, choose(lang, "policy", "Richtlinie"), trace.ID)
		blocks = append(blocks, fields(title, lang, [][]string{
			{choose(lang, "Name / action / state", "Name / Aktion / Status"), trace.Name + " / " + trace.Action + " / " + trace.Status},
			{choose(lang, "Ingress / egress", "Eingang / Ausgang"), trace.SourceInterface + " / " + trace.DestinationInterface},
			{choose(lang, "Source selectors", "Quellauswahl"), trace.Source},
			{choose(lang, "Destination selectors", "Zielauswahl"), trace.Destination},
			{choose(lang, "Service", "Dienst"), trace.Service},
			{choose(lang, "Schedule", "Zeitplan"), trace.Schedule},
			{choose(lang, "VIP matching", "VIP-Zuordnung"), trace.VIPMatch},
			{choose(lang, "Security profiles", "Sicherheitsprofile"), trace.Profiles},
			{choose(lang, "Logging", "Protokollierung"), trace.Logging},
			{choose(lang, "Effect on this path", "Wirkung auf diesen Pfad"), trace.Effect},
			{choose(lang, "Source reference", "Quellenverweis"), trace.Evidence},
		}))
	}
	return blocks
}

func technicalContent(a reportmodel.Assessment, lang string) []block {
	blocks := []block{{Heading: choose(lang, "Engineering summary", "Technische Zusammenfassung"), Text: fmt.Sprintf(choose(lang,
		"The selected configuration contains %d detected publication definitions across %d VDOMs. The assessment recorded %d review observations. Configured VPN, HA, routing and security-profile settings are configuration evidence; their operational state has not been verified.",
		"Die ausgewählte Konfiguration enthält %d erkannte Veröffentlichungsdefinitionen in %d VDOMs. Die Bewertung enthält %d Prüfpunkte. Konfigurierte VPN-, HA-, Routing- und Sicherheitsprofileinstellungen sind Konfigurationsnachweise; ihr Betriebszustand wurde nicht verifiziert."),
		len(a.Exposures), len(a.VDOMs), len(a.Findings))}}
	for _, section := range a.Sections {
		rows := make([][]string, 0, len(section.Rows))
		for _, row := range section.Rows {
			detail := row.Value
			if row.Evidence != "" {
				detail += "\n" + choose(lang, "Source: ", "Quelle: ") + row.Evidence
			}
			rows = append(rows, []string{row.Label, detail})
		}
		blocks = append(blocks, fields(localized(lang, section.Title, section.TitleDE), lang, rows))
	}
	if len(a.Exposures) > 0 {
		blocks = append(blocks, inventory(a.Exposures, lang), block{Text: choose(lang,
			"The Port Forwarding & Exposure report from this same backup contains the full per-object rule traces and geographic restriction explanations.",
			"Der Bericht zu Portweiterleitungen aus demselben Backup enthält die vollständigen Richtlinienpfade und Erklärungen zu geografischen Einschränkungen je Objekt.")})
	}
	blocks = append(blocks, block{Heading: choose(lang, "Findings and recommended actions", "Feststellungen und empfohlene Maßnahmen")})
	if len(a.Findings) == 0 {
		return append(blocks, block{Text: choose(lang,
			"The implemented checks recorded no findings. This is not a complete security assessment or compliance certification; review the analysis coverage.",
			"Die implementierten Prüfungen haben keine Feststellungen erfasst. Dies ist keine vollständige Sicherheitsbewertung oder Konformitätszertifizierung; beachten Sie den Analyseumfang.")})
	}
	for index, f := range a.Findings {
		blocks = append(blocks, fields(fmt.Sprintf("%d. %s", index+1, localized(lang, f.Title, f.TitleDE)), lang, [][]string{
			{choose(lang, "Priority / reference", "Priorität / Referenz"), f.Priority + " / " + f.ID},
			{choose(lang, "Observation", "Feststellung"), localized(lang, f.Detail, f.DetailDE)},
			{choose(lang, "Recommended action", "Empfohlene Maßnahme"), localized(lang, f.Recommendation, f.RecommendationDE)},
			{choose(lang, "Source reference", "Quellenverweis"), f.Evidence},
		}))
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
