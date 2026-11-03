package renderpdf

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func validateTelemetry(ctx context.Context, t *reportmodel.Telemetry) error {
	if t == nil {
		return ctx.Err()
	}
	b := projectionBudget{ctx: ctx, remaining: maxText - 8192}
	if len(t.Datasets) > 64 || len(t.Sources) > 256 || len(t.VDOMs) > 256 {
		return errProjectionLimit
	}
	if !b.take(t.Status, t.Reason, t.DeviceIdentity, t.SourceOrigin, t.SourceMatch, t.Query) || !b.list(t.Sources) || !b.list(t.VDOMs) {
		return b.err
	}
	for _, dataset := range t.Datasets {
		if len(dataset.Rows) > 10000 || dataset.Total < 0 || dataset.Returned < 0 || dataset.Limit < 0 {
			return errors.New("reports: invalid telemetry bounds")
		}
		if !b.take(dataset.ID, dataset.Title, dataset.TitleDE, dataset.Status, dataset.Reason) || !b.list(dataset.MissingFields) {
			return b.err
		}
		for _, row := range dataset.Rows {
			if row.Count < 0 {
				return errors.New("reports: invalid telemetry count")
			}
			for _, value := range []*int64{row.Bytes, row.SentBytes, row.ReceivedBytes} {
				if value != nil && *value < 0 {
					return errors.New("reports: invalid telemetry counter")
				}
			}
			if !b.take(row.Label, row.Secondary) {
				return b.err
			}
		}
	}
	return ctx.Err()
}

func telemetryStatus(status, lang string) string {
	switch status {
	case "available":
		return choose(lang, "Available observations", "Beobachtungen verfügbar")
	case "partial":
		return choose(lang, "Partial observations - review coverage", "Teilweise Beobachtungen - Umfang prüfen")
	case "no_data":
		return choose(lang, "No matching received log records", "Keine passenden empfangenen Logeinträge")
	case "missing_fields":
		return choose(lang, "Required log fields are missing", "Erforderliche Logfelder fehlen")
	case "error":
		return choose(lang, "Log query was not successful", "Logabfrage war nicht erfolgreich")
	case "disabled":
		return choose(lang, "Log reporting disabled by profile", "Logberichte im Profil deaktiviert")
	case "not_configured":
		return choose(lang, "Log source is not configured", "Logquelle ist nicht konfiguriert")
	default:
		return choose(lang, "Observation availability is not established", "Verfügbarkeit der Beobachtungen nicht ermittelt")
	}
}

func observedTotal(dataset reportmodel.TelemetryDataset, lang string) string {
	switch dataset.Status {
	case "available", "partial", "no_data":
		return strconv.FormatInt(dataset.Total, 10)
	case "missing_fields":
		if dataset.Total > 0 {
			return strconv.FormatInt(dataset.Total, 10)
		}
	}
	return choose(lang, "Not available", "Nicht verfügbar")
}

func formatTelemetryTime(t time.Time, lang string) string {
	if t.IsZero() {
		return choose(lang, "Not available", "Nicht verfügbar")
	}
	return t.Format(time.RFC3339Nano)
}

func trafficContent(source reportmodel.Source, t *reportmodel.Telemetry, lang string) content {
	c := baseContent(source, "traffic", lang)
	c.Blocks = append(c.Blocks, block{Text: choose(lang,
		"Observed FortiGate log aggregates from Graylog. Counts refer to received log records, not unique sessions, attacks or complete network traffic. Configuration and log observations have separate timestamps and scope.",
		"Beobachtete FortiGate-Logaggregate aus Graylog. Die Zahlen beziehen sich auf empfangene Logeinträge, nicht auf eindeutige Sitzungen, Angriffe oder den vollständigen Netzwerkverkehr. Konfiguration und Logbeobachtungen haben getrennte Zeitangaben und Umfänge.")})
	c.Blocks = append(c.Blocks, mainBlock(fields(choose(lang, "Report provenance", "Berichtsherkunft"), lang, [][]string{
		{choose(lang, "Configuration backup reference", "Konfigurationsbackup-Referenz"), fmt.Sprintf("#%d | %s", source.BackupID, formatTime(source.BackupAt, lang))},
		{choose(lang, "Report generated", "Bericht erstellt"), formatTime(source.GeneratedAt, lang)},
		{choose(lang, "Configuration SHA-256", "Konfiguration SHA-256"), checksum(source.Checksum, lang)},
		{choose(lang, "Assessment schema", "Bewertungsschema"), reportmodel.Version},
	})))
	c.Blocks = append(c.Blocks, telemetrySummary(t, lang)...)
	if t == nil {
		return c
	}
	for _, dataset := range t.Datasets {
		b := mainBlock(block{Heading: localized(lang, dataset.Title, dataset.TitleDE)})
		if b.Heading == "" {
			b.Heading = telemetryDatasetTitle(dataset.ID, lang)
		}
		b.Text = telemetryStatus(dataset.Status, lang)
		if dataset.Reason != "" {
			b.Text += "\n" + dataset.Reason
		}
		if len(dataset.MissingFields) > 0 {
			b.Text += "\n" + choose(lang, "One or more required fields unavailable: ", "Mindestens eines der erforderlichen Felder nicht verfügbar: ") + strings.Join(dataset.MissingFields, ", ")
		}
		if dataset.Truncated {
			b.Text += "\n" + choose(lang, "Only a bounded set of groups is listed individually. The table includes an explicit remainder for records in unreturned groups; records missing required fields are listed separately.", "Nur eine begrenzte Auswahl der Gruppen wird einzeln aufgeführt. Die Tabelle weist Logeinträge aus nicht zurückgegebenen Gruppen als eigenen Rest aus; Einträge mit fehlenden Pflichtfeldern werden separat aufgeführt.")
		}
		if dataset.Status == "missing_fields" && dataset.Total > 0 {
			// The collector established the received-record denominator, but
			// none of those records has all required grouping/counter fields.
			// Project only that known count and a fixed coverage label.
			b.Text += "\n" + choose(lang, "The received-record count is known; usable grouping and byte counters are unavailable.", "Die Anzahl der empfangenen Logeinträge ist bekannt; nutzbare Gruppierungen und Bytezähler sind nicht verfügbar.")
			b.Columns = []string{choose(lang, "Coverage", "Abdeckung"), choose(lang, "Received log records", "Empfangene Logeinträge")}
			b.Rows = [][]string{{choose(lang, "Missing required fields", "Fehlende Pflichtfelder"), strconv.FormatInt(dataset.Total, 10)}}
			c.Blocks = append(c.Blocks, b)
			continue
		}
		if dataset.Status != "available" && dataset.Status != "partial" && dataset.Status != "no_data" {
			c.Blocks = append(c.Blocks, b)
			continue
		}
		if len(dataset.Rows) == 0 {
			b.Text += "\n" + choose(lang, "No grouped observations are available for this view. A lack of logs does not establish a lack of traffic or threats.", "Für diese Ansicht sind keine gruppierten Beobachtungen verfügbar. Fehlende Logs belegen nicht das Fehlen von Verkehr oder Bedrohungen.")
			c.Blocks = append(c.Blocks, b)
			continue
		}
		secondary, bytes, sent, received, timestamp := false, false, false, false, false
		for _, row := range dataset.Rows {
			secondary = secondary || row.Secondary != ""
			bytes = bytes || row.Bytes != nil
			sent = sent || row.SentBytes != nil
			received = received || row.ReceivedBytes != nil
			timestamp = timestamp || !row.Timestamp.IsZero()
		}
		b.Columns = []string{choose(lang, "Observed group", "Beobachtete Gruppe"), choose(lang, "Received log records", "Empfangene Logeinträge")}
		if secondary {
			b.Columns = append(b.Columns, choose(lang, "Additional dimension", "Weitere Dimension"))
		}
		if timestamp {
			b.Columns = append(b.Columns, choose(lang, "Time bucket", "Zeitintervall"))
		}
		if bytes {
			b.Columns = append(b.Columns, choose(lang, "Reported byte counter", "Gemeldeter Byte-Zähler"))
		}
		if sent {
			b.Columns = append(b.Columns, choose(lang, "Reported sent bytes", "Gemeldete gesendete Bytes"))
		}
		if received {
			b.Columns = append(b.Columns, choose(lang, "Reported received bytes", "Gemeldete empfangene Bytes"))
		}
		for _, row := range dataset.Rows {
			values := []string{row.Label, strconv.FormatInt(row.Count, 10)}
			if secondary {
				values = append(values, row.Secondary)
			}
			if timestamp {
				values = append(values, formatTelemetryTime(row.Timestamp, lang))
			}
			counter := func(value *int64) string {
				if value == nil {
					return choose(lang, "Not available", "Nicht verfügbar")
				}
				return strconv.FormatInt(*value, 10)
			}
			if bytes {
				values = append(values, counter(row.Bytes))
			}
			if sent {
				values = append(values, counter(row.SentBytes))
			}
			if received {
				values = append(values, counter(row.ReceivedBytes))
			}
			b.Rows = append(b.Rows, values)
		}
		if bytes || sent || received {
			b.Text += "\n" + choose(lang, "Byte values are reported log counters. They are not verified unique-transfer totals or bandwidth measurements; log semantics and duplicate/session updates can affect them.", "Byte-Werte sind gemeldete Logzähler. Sie sind keine verifizierten eindeutigen Übertragungssummen oder Bandbreitenmessungen; Logsemantik und doppelte bzw. aktualisierte Sitzungseinträge können sie beeinflussen.")
		}
		// A bounded graphic accompanies the complete returned value table.
		// The remainder is explicit and does not silently discard any rows.
		chart := &chart{ID: "telemetry-" + dataset.ID, Unit: choose(lang, "Received log records", "Empfangene Logeinträge")}
		pointLimit := 10
		if dataset.ID == "traffic_trend" {
			// The collector returns twelve adjacent chronological intervals,
			// not ranked groups. Keep the full timeline visible.
			pointLimit = 12
		}
		var others int64
		for i, row := range dataset.Rows {
			if i < pointLimit {
				chart.Points = append(chart.Points, chartPoint{Label: row.Label, Value: row.Count})
				continue
			}
			if row.Count > math.MaxInt64-others {
				others = -1
				break
			}
			others += row.Count
		}
		if others >= 0 {
			if len(dataset.Rows) > pointLimit {
				chart.Points = append(chart.Points, chartPoint{Label: choose(lang, "Remaining table rows", "Übrige Tabellenzeilen"), Value: others})
			}
			b.Chart = chart
		}
		c.Blocks = append(c.Blocks, b)
	}
	return c
}

// telemetrySummary records the captured scope and availability without raw log messages.
func telemetrySummary(t *reportmodel.Telemetry, lang string) []block {
	if t == nil {
		t = &reportmodel.Telemetry{Status: "not_configured"}
	}
	rows := [][]string{
		{choose(lang, "Log source", "Logquelle"), "Graylog / FortiGate"},
		{choose(lang, "Availability", "Verfügbarkeit"), telemetryStatus(t.Status, lang)},
		{choose(lang, "Window start", "Zeitraum von"), formatTelemetryTime(t.WindowStart, lang)},
		{choose(lang, "Window end", "Zeitraum bis"), formatTelemetryTime(t.WindowEnd, lang)},
		{choose(lang, "Observations retrieved", "Beobachtungen abgerufen"), formatTelemetryTime(t.RetrievedAt, lang)},
	}
	rows = append(rows, []string{choose(lang, "Device attribution", "Gerätezuordnung"), t.DeviceIdentity}, []string{choose(lang, "Source selectors", "Quellselektion"), strings.Join(t.Sources, ", ")})
	if t.SourceOrigin != "" {
		rows = append(rows, []string{choose(lang, "Hostname source", "Herkunft der Hostnamen"), telemetrySourceOrigin(t.SourceOrigin, lang)})
	}
	if t.SourceMatch != "" {
		rows = append(rows, []string{choose(lang, "ADM VPN Config match", "Zuordnung in ADM VPN Config"), telemetrySourceMatch(t.SourceMatch, lang)})
	}
	if t.Query != "" {
		vdoms := choose(lang, "All virtual domains for the selected firewall", "Alle virtuellen Domänen der ausgewählten Firewall")
		if len(t.VDOMs) > 0 {
			vdoms = strings.Join(t.VDOMs, ", ")
		}
		rows = append(rows, []string{choose(lang, "Queried VDOMs", "Abgefragte VDOMs"), vdoms}, []string{choose(lang, "Graylog base query", "Graylog-Basisabfrage"), t.Query})
	}
	if t.Reason != "" {
		rows = append(rows, []string{choose(lang, "Coverage detail", "Details zum Umfang"), t.Reason})
	}
	b := mainBlock(fields(choose(lang, "Observed log coverage", "Umfang der Logbeobachtungen"), lang, rows))
	b.Text = choose(lang, "Separate log queries can describe overlapping records. Counts must not be added across views or treated as unique sessions, users, attacks or device uptime. Missing or partial data is not a passing security check.", "Getrennte Logabfragen können sich überschneidende Einträge beschreiben. Zahlen dürfen nicht über Ansichten addiert oder als eindeutige Sitzungen, Benutzer, Angriffe oder Geräteverfügbarkeit verstanden werden. Fehlende oder teilweise Daten sind keine bestandene Sicherheitsprüfung.")
	result := []block{b}
	if len(t.Datasets) > 0 {
		summary := block{Contents: true, Heading: choose(lang, "Observation overview", "Beobachtungsübersicht"), Columns: []string{choose(lang, "View", "Ansicht"), choose(lang, "Availability", "Verfügbarkeit"), choose(lang, "Received log records", "Empfangene Logeinträge")}, Widths: []float64{1.4, 1.8, 1}}
		for _, dataset := range t.Datasets {
			title := telemetryDatasetTitle(dataset.ID, lang)
			if dataset.Title != "" {
				title = localized(lang, dataset.Title, dataset.TitleDE)
			}
			state := telemetryStatus(dataset.Status, lang)
			if dataset.Truncated {
				state += "; " + choose(lang, "bounded groups", "begrenzte Gruppen")
			}
			if dataset.Reason != "" {
				state += "\n" + dataset.Reason
			}
			summary.Rows = append(summary.Rows, []string{title, state, observedTotal(dataset, lang)})
		}
		result = append(result, summary)
	}
	return result
}

func telemetrySourceOrigin(origin, lang string) string {
	switch origin {
	case "adm_vpn_cluster_hostnames":
		return choose(lang, "ADM VPN Config / cluster hostnames", "ADM VPN Config / Cluster-Hostnamen")
	case "adm_vpn_firewallname":
		return choose(lang, "ADM VPN Config / firewall name", "ADM VPN Config / Firewallname")
	case "config_hostname":
		return choose(lang, "Saved configuration / hostname", "Gespeicherte Konfiguration / Hostname")
	case "registered_short_hostname":
		return choose(lang, "Registered firewall / short hostname", "Registrierte Firewall / kurzer Hostname")
	default:
		return choose(lang, "Not established", "Nicht ermittelt")
	}
}

func telemetrySourceMatch(match, lang string) string {
	switch match {
	case "dns_name_full":
		return choose(lang, "Full DNS name", "Vollständiger DNS-Name")
	case "exact_alias":
		return choose(lang, "Exact firewall-name or DNS alias", "Exakter Firewallname oder DNS-Alias")
	case "short_alias":
		return choose(lang, "Short registered hostname", "Kurzer registrierter Hostname")
	default:
		return choose(lang, "Not established", "Nicht ermittelt")
	}
}

func telemetryDatasetTitle(id, lang string) string {
	switch id {
	case "traffic", "traffic_volume", "traffic_over_time", "traffic_timeline", "traffic_trend":
		return choose(lang, "Traffic log observations", "Verkehrslogbeobachtungen")
	case "actions", "traffic_actions", "action":
		return choose(lang, "Recorded traffic actions", "Protokollierte Verkehrsaktionen")
	case "applications", "top_applications", "application":
		return choose(lang, "Application observations", "Anwendungsbeobachtungen")
	case "top_sources", "sources", "source", "source_ips":
		return choose(lang, "Source observations", "Quellbeobachtungen")
	case "top_destinations", "destinations", "destination", "destination_ips":
		return choose(lang, "Destination observations", "Zielbeobachtungen")
	case "policies", "top_policies", "policy":
		return choose(lang, "Policy log observations", "Richtlinienlogbeobachtungen")
	case "reported_bytes":
		return choose(lang, "Reported traffic counters", "Gemeldete Verkehrszähler")
	case "security", "security_events", "security_subtypes":
		return choose(lang, "Security log observations", "Sicherheitslogbeobachtungen")
	case "vpn", "vpn_events":
		return choose(lang, "VPN log observations", "VPN-Logbeobachtungen")
	default:
		return choose(lang, "Additional log observations", "Weitere Logbeobachtungen")
	}
}
