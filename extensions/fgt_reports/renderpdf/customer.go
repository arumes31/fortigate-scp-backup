package renderpdf

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

type customerTopic struct {
	key      string
	title    string
	meaning  string
	action   string
	question string
	count    int
	priority int
}

// customerContent deliberately never copies finding prose, object names,
// warnings, firmware, hostnames, VDOM names, IPs, backend lists, or traces. Only
// allowlisted finding-ID prefixes, normalized priorities and aggregate counts
// cross the audience boundary. An unknown finding becomes a generic review
// topic rather than a raw technical finding in a customer document.
func customerContentVisible(source reportmodel.Source, a reportmodel.Assessment, lang string, showFindings bool) content {
	c := baseContent(source, "customer", lang, true)
	c.Blocks = append(c.Blocks, block{Text: choose(lang,
		"A discussion guide based on a saved firewall configuration. It supports an agreed improvement plan; operational performance, external reachability and contract status have not been assessed.",
		"Ein Gesprächsleitfaden auf Grundlage einer gespeicherten Firewall-Konfiguration. Er unterstützt einen abgestimmten Verbesserungsplan; Betriebsleistung, externe Erreichbarkeit und Vertragsstatus wurden nicht bewertet.")})
	coverageState := choose(lang, "Supported checks completed", "Unterstützte Prüfungen abgeschlossen")
	if !a.Complete {
		coverageState = choose(lang, "Limited analysis - engineering clarification required", "Eingeschränkte Analyse - technische Klärung erforderlich")
	}
	c.Blocks = append(c.Blocks, fields(choose(lang, "Assessment overview", "Bewertungsübersicht"), lang, [][]string{
		{choose(lang, "Firewall reference", "Firewall-Referenz"), fmt.Sprintf("#%d", source.FirewallID)},
		{choose(lang, "Configuration snapshot", "Konfigurationsstand"), formatTime(source.BackupAt, lang)},
		{choose(lang, "Report generated", "Bericht erstellt"), formatTime(source.GeneratedAt, lang)},
		{choose(lang, "Analysis coverage", "Analyseumfang"), coverageState},
		{choose(lang, "Publication definitions", "Veröffentlichungen (Definitionen)"), strconv.Itoa(len(a.Exposures))},
		{choose(lang, "Virtual domains in scope", "Virtuelle Domänen im Umfang"), strconv.Itoa(len(a.VDOMs))},
		{choose(lang, "Review observations", "Prüfpunkte"), strconv.Itoa(len(a.Findings))},
	}))
	c.Blocks = append(c.Blocks, block{Text: choose(lang,
		"Counts describe configured objects, not active users or reachable services. Confirm business requirements and the technical evidence before approving changes.",
		"Die Zahlen beschreiben konfigurierte Objekte, keine aktiven Benutzer oder erreichbaren Dienste. Bestätigen Sie vor Änderungen die Geschäftsanforderungen und technischen Nachweise.")})
	if !a.Complete {
		c.Blocks = append(c.Blocks, block{Text: choose(lang,
			"An engineer should clarify the analysis limitations using the technical report.",
			"Die Analysegrenzen sollten anhand des technischen Berichts geklärt werden.")})
	}
	if showFindings {
		topics := customerTopics(a.Findings, lang)
		c.Blocks = append(c.Blocks, block{Heading: choose(lang, "Priority discussion topics", "Priorisierte Gesprächsthemen")})
		if len(topics) == 0 {
			c.Blocks = append(c.Blocks, block{Text: choose(lang,
				"No rule-generated review observations were recorded. Confirm business requirements, ownership of published services and the analysis scope in the next review. The absence of findings is not a security guarantee.",
				"Es wurden keine regelbasierten Prüfpunkte erfasst. Bestätigen Sie im nächsten Review die Geschäftsanforderungen, die Verantwortung für veröffentlichte Dienste und den Analyseumfang. Das Fehlen von Feststellungen ist keine Sicherheitsgarantie.")})
		}
		for _, topic := range topics {
			priority := choose(lang, "Planned review", "Geplante Prüfung")
			if topic.priority <= 1 {
				priority = choose(lang, "Priority review", "Priorisierte Prüfung")
			}
			c.Blocks = append(c.Blocks, fields(topic.title, lang, [][]string{
				{choose(lang, "Review level / observations", "Prüfstufe / Prüfpunkte"), fmt.Sprintf("%s / %d", priority, topic.count)},
				{choose(lang, "Customer relevance", "Bedeutung für den Kunden"), topic.meaning},
				{choose(lang, "Proposed action", "Vorgeschlagene Maßnahme"), topic.action},
				{choose(lang, "Information needed", "Benötigte Information"), topic.question},
			}))
		}
	}
	c.Blocks = append(c.Blocks, block{
		Heading: choose(lang, "Suggested improvement sequence", "Vorgeschlagene Reihenfolge"),
		Text:    choose(lang, "Planning horizons are proposals to agree with the customer, not commitments or automatic change requests.", "Die Planungshorizonte sind mit dem Kunden abzustimmende Vorschläge, keine Zusagen oder automatischen Änderungsaufträge."),
		Columns: []string{choose(lang, "Horizon", "Horizont"), choose(lang, "Action and intended outcome", "Maßnahme und Ziel")}, Widths: []float64{1, 3},
		Rows: [][]string{
			{choose(lang, "Next review", "Nächstes Review"), choose(lang, "Confirm analysis limitations, service owners and required access. Agree which observations need technical validation.", "Analysegrenzen, Dienstverantwortliche und benötigte Zugriffe bestätigen. Technisch zu validierende Prüfpunkte abstimmen.")},
			{choose(lang, "Next 30 days", "Nächste 30 Tage"), choose(lang, "Validate agreed priorities, document the intended configuration and plan approved changes with a rollback procedure.", "Abgestimmte Prioritäten validieren, Sollkonfiguration dokumentieren und freigegebene Änderungen mit Rückfallverfahren planen.")},
			{choose(lang, "Next quarter", "Nächstes Quartal"), choose(lang, "Check outcomes, review recovery and monitoring needs, and compare a new configuration assessment with the agreed baseline.", "Ergebnisse prüfen, Wiederherstellungs- und Überwachungsbedarf bewerten und eine neue Konfigurationsbewertung mit dem abgestimmten Ausgangsstand vergleichen.")},
		},
	})
	c.Blocks = append(c.Blocks, block{Heading: choose(lang, "Decisions for the review meeting", "Entscheidungen für das Review"), Text: choose(lang,
		"Which published services are business-critical, and who owns them? Who needs access? What interruption and recovery times are acceptable? Which maintenance windows are available? Who will approve and validate each agreed action? Budget and effort estimates require separately confirmed scope.",
		"Welche veröffentlichten Dienste sind geschäftskritisch und wer ist verantwortlich? Wer benötigt Zugriff? Welche Ausfall- und Wiederherstellungszeiten sind akzeptabel? Welche Wartungsfenster stehen zur Verfügung? Wer genehmigt und validiert die abgestimmten Maßnahmen? Budget- und Aufwandsschätzungen erfordern einen gesondert bestätigten Umfang.")})
	c.Blocks = append(c.Blocks, fields(choose(lang, "Evidence and limitations", "Nachweise und Grenzen"), lang, [][]string{
		{choose(lang, "Backup reference", "Backup-Referenz"), fmt.Sprintf("#%d", source.BackupID)},
		{choose(lang, "Configuration SHA-256", "Konfiguration SHA-256"), checksum(source.Checksum, lang)},
		{choose(lang, "Assessment schema", "Bewertungsschema"), reportmodel.Version},
		{choose(lang, "Separate evidence required", "Gesonderte Nachweise erforderlich"), choose(lang,
			"Reachability, backend health, HA failover, utilization, uptime, attack counts, license/support expiry and compliance certification are not established by this report.",
			"Erreichbarkeit, Backend-Zustand, HA-Failover, Auslastung, Verfügbarkeit, Angriffszahlen, Lizenz-/Supportablauf und Konformitätszertifizierung werden durch diesen Bericht nicht belegt.")},
	}))
	return c
}

func customerTopics(findings []reportmodel.Finding, lang string) []customerTopic {
	topics := make(map[string]*customerTopic)
	for _, finding := range findings {
		key, _, _ := strings.Cut(finding.ID, ":")
		topic := topicFor(key, lang)
		current, ok := topics[topic.key]
		if !ok {
			topic.priority = 4
			current = &topic
			topics[topic.key] = current
		}
		current.count++
		priority := 3
		switch strings.ToLower(finding.Priority) {
		case "critical", "high":
			priority = 1
		case "medium":
			priority = 2
		}
		current.priority = min(current.priority, priority)
	}
	out := make([]customerTopic, 0, len(topics))
	for _, topic := range topics {
		out = append(out, *topic)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].priority != out[j].priority {
			return out[i].priority < out[j].priority
		}
		return out[i].key < out[j].key
	})
	return out
}

func topicFor(key, lang string) customerTopic {
	var titleEN, titleDE, meaningEN, meaningDE, actionEN, actionDE, questionEN, questionDE string
	switch key {
	case "broad-source", "geo-coverage", "overlap", "unreferenced":
		key = "access"
		titleEN, titleDE = "Published services and access", "Veröffentlichte Dienste und Zugriff"
		meaningEN, meaningDE = "The assessment identified publication or access conditions that merit an engineering review.", "Die Bewertung hat Veröffentlichungs- oder Zugriffsbedingungen erkannt, die technisch geprüft werden sollten."
		actionEN, actionDE = "Validate the intended access scope, applicable restrictions and exceptions before agreeing changes.", "Vor der Abstimmung von Änderungen den vorgesehenen Zugriffsumfang, geltende Einschränkungen und Ausnahmen validieren."
		questionEN, questionDE = "Service purpose, required users and locations, business owner, and approved exceptions.", "Zweck des Dienstes, benötigte Benutzer und Standorte, Verantwortlicher und freigegebene Ausnahmen."
	case "logging":
		titleEN, titleDE = "Monitoring and investigation", "Überwachung und Untersuchung"
		meaningEN, meaningDE = "Logging-related configuration needs review against the customer's monitoring requirements.", "Protokollierungsbezogene Einstellungen sollten mit den Überwachungsanforderungen des Kunden abgeglichen werden."
		actionEN, actionDE = "Review relevant policy logging and validate delivery, alerting and retention with the receiving platform.", "Relevante Richtlinienprotokollierung prüfen und Zustellung, Alarmierung und Aufbewahrung auf der Zielplattform validieren."
		questionEN, questionDE = "Required events, retention period, monitoring owner and response process.", "Benötigte Ereignisse, Aufbewahrungsdauer, Monitoring-Verantwortlicher und Reaktionsprozess."
	case "management":
		titleEN, titleDE = "Administrative access", "Administrativer Zugriff"
		meaningEN, meaningDE = "Administrative access settings require a review against the agreed management model.", "Administrative Zugriffseinstellungen sollten mit dem abgestimmten Verwaltungsmodell abgeglichen werden."
		actionEN, actionDE = "Confirm approved management paths and review authentication and source restrictions.", "Freigegebene Verwaltungswege bestätigen sowie Authentifizierung und Quellbeschränkungen prüfen."
		questionEN, questionDE = "Authorized administrators, management locations and emergency-access procedure.", "Berechtigte Administratoren, Verwaltungsstandorte und Verfahren für Notfallzugriffe."
	case "resilience":
		titleEN, titleDE = "Resilience and recovery", "Ausfallsicherheit und Wiederherstellung"
		meaningEN, meaningDE = "The captured resilience configuration should be compared with the customer's recovery needs.", "Die erfasste Konfiguration zur Ausfallsicherheit sollte mit den Wiederherstellungsanforderungen des Kunden verglichen werden."
		actionEN, actionDE = "Review the design and agree a recovery or failover validation exercise and runbook.", "Das Design prüfen und eine Wiederherstellungs- oder Failover-Validierung mit Betriebsanleitung abstimmen."
		questionEN, questionDE = "Acceptable outage, recovery targets, available redundancy and maintenance window.", "Akzeptabler Ausfall, Wiederherstellungsziele, vorhandene Redundanz und Wartungsfenster."
	case "vpn-crypto":
		titleEN, titleDE = "Remote connectivity", "Standort- und Fernzugriff"
		meaningEN, meaningDE = "VPN configuration observations warrant a compatibility and security review.", "Feststellungen zur VPN-Konfiguration erfordern eine Prüfung von Kompatibilität und Sicherheit."
		actionEN, actionDE = "Review agreed cryptographic settings with the remote peer owner and plan validated changes.", "Abgestimmte Kryptografieeinstellungen mit dem Verantwortlichen der Gegenstelle prüfen und validierte Änderungen planen."
		questionEN, questionDE = "Remote peer ownership, compatibility requirements and permitted service interruption.", "Verantwortlicher der Gegenstelle, Kompatibilitätsanforderungen und zulässige Dienstunterbrechung."
	default:
		key = "analysis-coverage"
		titleEN, titleDE = "Engineering clarification", "Technische Klärung"
		meaningEN, meaningDE = "Some observations need technical interpretation before a customer decision can be made.", "Einige Prüfpunkte müssen technisch interpretiert werden, bevor eine Kundenentscheidung getroffen werden kann."
		actionEN, actionDE = "Review the technical evidence and any unsupported or unresolved configuration conditions.", "Technische Nachweise sowie nicht unterstützte oder ungeklärte Konfigurationsbedingungen prüfen."
		questionEN, questionDE = "An engineer's validation, the relevant business requirement and any missing evidence.", "Technische Validierung, relevante Geschäftsanforderung und fehlende Nachweise."
	}
	return customerTopic{key: key, title: choose(lang, titleEN, titleDE), meaning: choose(lang, meaningEN, meaningDE), action: choose(lang, actionEN, actionDE), question: choose(lang, questionEN, questionDE)}
}
