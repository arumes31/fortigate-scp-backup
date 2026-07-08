package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// Minimal i18n layer: English is the canonical language, German is provided
// as a translation. The active language comes from the `lang` cookie
// (default "en") and is toggled via POST /lang.

const defaultLang = "en"

// langFromRequest returns "en" or "de" for the request: the explicit cookie
// wins, otherwise the browser's Accept-Language is honoured (relevant for
// first visits and public topology share links, which have no toggle chrome),
// falling back to English.
func langFromRequest(r *http.Request) string {
	if c, err := r.Cookie("lang"); err == nil && (c.Value == "de" || c.Value == "en") {
		return c.Value
	}
	// With exactly two languages a q-value parse is overkill: the first
	// language tag decides.
	accept := strings.ToLower(r.Header.Get("Accept-Language"))
	if strings.HasPrefix(accept, "de") {
		return "de"
	}
	return defaultLang
}

// handleSetLang stores the language cookie and redirects back. POST-only so a
// prefetch cannot flip the language.
func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lang := r.FormValue("lang")
	if lang != "de" {
		lang = "en"
	}
	http.SetCookie(w, &http.Cookie{
		Name: "lang", Value: lang, Path: "/",
		MaxAge: 365 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	back := r.FormValue("back")
	// Local paths only: "//host" and "/\host" are protocol-relative in
	// browsers and would make this an open redirect.
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.HasPrefix(back, "/\\") {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// uiMsgs is the UI chrome catalog: key -> lang -> text.
var uiMsgs = map[string]map[string]string{
	// Audit page
	"audit.title":            {"en": "Audit & Compliance Insights", "de": "Audit & Compliance Insights"},
	"audit.critical":         {"en": "Critical findings", "de": "Kritische Findings"},
	"audit.warnings":         {"en": "Warnings", "de": "Warnungen"},
	"audit.firewalls":        {"en": "Firewalls", "de": "Firewalls"},
	"audit.audited":          {"en": "Audited", "de": "Auditiert"},
	"audit.custom_rules":     {"en": "Custom audit rules", "de": "Eigene Audit-Regeln"},
	"audit.rule_name":        {"en": "Rule name (e.g. SSH port check)", "de": "Regel-Name (z.B. SSH Port Check)"},
	"audit.rule_pattern":     {"en": "Search pattern (e.g. set admin-sport 443)", "de": "Such-Muster (z.B. set admin-sport 443)"},
	"audit.rule_remediation": {"en": "Remediation (CLI commands)", "de": "Behebung (CLI Kommandos)"},
	"audit.rule_add":         {"en": "Add rule", "de": "Regel hinzufügen"},
	"audit.rules_configured": {"en": "Configured rules:", "de": "Konfigurierte Regeln:"},
	"audit.rule_delete":      {"en": "Delete rule", "de": "Regel löschen"},
	"audit.exemptions":       {"en": "Active exemptions", "de": "Aktive Ausnahmen (Exemptions)"},
	"audit.exemption_reason": {"en": "Reason:", "de": "Grund:"},
	"audit.exemption_none":   {"en": `No exemptions defined. Use the "Exempt" button on a firewall's findings.`, "de": `Keine Ausnahmen definiert. Verwenden Sie den "Ausnahme"-Button bei den Findings einer Firewall.`},
	"audit.exemption_revoke": {"en": "Revoke", "de": "Aufheben"},
	"audit.per_firewall":     {"en": "Compliance & audit per firewall", "de": "Compliance & Audit je Firewall"},
	"audit.latest_configs":   {"en": "Evaluation of the latest configurations", "de": "Auswertung der neuesten Konfigurationen"},
	"audit.topology_link":    {"en": "Network topology →", "de": "Netzwerk-Topologie →"},
	"audit.search":           {"en": "Search FQDN, model, ticket or finding...", "de": "Suche FQDN, Modell, Ticket oder Finding..."},
	"audit.col_firewall":     {"en": "Firewall", "de": "Firewall"},
	"audit.col_system":       {"en": "System", "de": "Systemdaten"},
	"audit.col_scores":       {"en": "Compliance scores", "de": "Compliance Scores"},
	"audit.col_ticket":       {"en": "Change ticket", "de": "Change Ticket"},
	"audit.col_actions":      {"en": "Actions & details", "de": "Aktionen & Details"},
	"audit.no_firewalls":     {"en": "No firewalls configured.", "de": "Keine Firewalls konfiguriert."},
	"audit.loading":          {"en": "loading…", "de": "lädt…"},

	// Audit page (JS strings)
	"audit.no_backup":      {"en": "— No backup —", "de": "— Kein Backup —"},
	"audit.model":          {"en": "Model:", "de": "Modell:"},
	"audit.backup":         {"en": "Backup:", "de": "Backup:"},
	"audit.computed":       {"en": "Audit computed:", "de": "Audit berechnet:"},
	"audit.ticket_id":      {"en": "e.g. INC-10298", "de": "z.B. INC-10298"},
	"audit.ticket_comment": {"en": "Comment...", "de": "Kommentar..."},
	"audit.details_show":   {"en": "Show details", "de": "Details anzeigen"},
	"audit.details_hide":   {"en": "Hide details", "de": "Details ausblenden"},
	"audit.n_critical":     {"en": "critical", "de": "kritisch"},
	"audit.n_warnings":     {"en": "warnings", "de": "Warnungen"},
	"audit.clean":          {"en": "clean", "de": "sauber"},
	"audit.recheck":        {"en": "↻ Re-check", "de": "↻ Neu prüfen"},
	"audit.recheck_title":  {"en": "Recompute audit", "de": "Audit neu berechnen"},
	"audit.load_error":     {"en": "Failed to load", "de": "Fehler beim Laden"},
	"audit.retry":          {"en": "Retry", "de": "Erneut versuchen"},
	"audit.exempt":         {"en": "Exempt", "de": "Ausnahme"},
	"audit.exempt_reason":  {"en": "Reason for exemption...", "de": "Grund für Ausnahme..."},
	"audit.show_cli":       {"en": "Show remediation (CLI)", "de": "Behebung (CLI) anzeigen"},
	"audit.show_context":   {"en": "Show config context (line %d)", "de": "Konfigurations-Kontext (Zeile %d) anzeigen"},
	"audit.findings_title": {"en": "Security & compliance findings", "de": "Sicherheits- & Compliance-Findings"},
	"audit.findings_none":  {"en": "No active findings for this firewall!", "de": "Keine aktiven Findings für diese Firewall vorhanden!"},
	"audit.exempted_title": {"en": "Ignored findings (exempted):", "de": "Ignorierte Findings (Exempted):"},
	"audit.exempted_note":  {"en": "(registered as exemption)", "de": "(Als Ausnahme registriert)"},
	"audit.upgrade_title":  {"en": "FortiOS upgrade path", "de": "FortiOS Upgrade-Pfad"},
	"audit.upgrade_note":   {"en": "Recommended path for updating the operating system:", "de": "Empfohlener Pfad zur Aktualisierung des Betriebssystems:"},

	// Topology page
	"topo.title":       {"en": "Network topology", "de": "Netzwerk-Topologie"},
	"topo.firewall":    {"en": "Firewall:", "de": "Firewall:"},
	"topo.hint":        {"en": "Scroll = zoom · Drag = pan · Click firewall/switch = faceplate", "de": "Scrollen = Zoom · Ziehen = Verschieben · Klick auf Firewall/Switch = Frontblende"},
	"topo.reset":       {"en": "⤢ Reset view", "de": "⤢ Ansicht zurücksetzen"},
	"topo.share":       {"en": "Public link:", "de": "Öffentlicher Link:"},
	"topo.share_24h":   {"en": "24 hours", "de": "24 Stunden"},
	"topo.share_7d":    {"en": "7 days", "de": "7 Tage"},
	"topo.share_30d":   {"en": "30 days", "de": "30 Tage"},
	"topo.share_never": {"en": "Unlimited", "de": "Unbegrenzt"},
	"topo.share_make":  {"en": "Create link", "de": "Link erstellen"},
	"topo.copy":        {"en": "Copy", "de": "Kopieren"},
	"topo.copied":      {"en": "✓ Copied", "de": "✓ Kopiert"},
	"topo.created":     {"en": "created", "de": "erstellt"},
	"topo.expires":     {"en": "expires", "de": "läuft ab"},
	"topo.no_expiry":   {"en": "unlimited", "de": "unbegrenzt"},
	"topo.revoke":      {"en": "Revoke", "de": "Widerrufen"},
	"topo.share_fail":  {"en": "Could not create link:", "de": "Link konnte nicht erstellt werden:"},
	"topo.copy_hint":   {"en": "Click to copy", "de": "Klicken zum Kopieren"},
	"topo.shared_view": {"en": "READ-ONLY · SHARED VIEW", "de": "NUR LESEN · GETEILTE ANSICHT"},

	// Topology renderer (JS strings, injected as window.I18N)
	"topo.loading":     {"en": "loading…", "de": "lädt…"},
	"topo.no_backup":   {"en": "No backup available — no topology to display.", "de": "Kein Backup vorhanden — keine Topologie verfügbar."},
	"topo.load_error":  {"en": "Failed to load topology.", "de": "Fehler beim Laden der Topologie."},
	"topo.internet":    {"en": "Internet", "de": "Internet"},
	"topo.external":    {"en": "External networks / provider", "de": "Externe Netze / Provider"},
	"topo.route":       {"en": "Static route", "de": "Statische Route"},
	"topo.route_dst":   {"en": "Destination", "de": "Ziel"},
	"topo.gateway":     {"en": "Gateway", "de": "Gateway"},
	"topo.direct":      {"en": "direct", "de": "direkt"},
	"topo.no_vlan":     {"en": "no VLAN", "de": "ohne VLAN"},
	"topo.ports":       {"en": "Ports", "de": "Ports"},
	"topo.no_ports":    {"en": "No ports found.", "de": "Keine Ports gefunden."},
	"topo.role":        {"en": "Role", "de": "Rolle"},
	"topo.mgmt_access": {"en": "Mgmt access", "de": "Mgmt-Zugriff"},
	"topo.serial":      {"en": "Serial", "de": "Seriennummer"},
	"topo.alias":       {"en": "Alias", "de": "Alias"},
	"topo.parent":      {"en": "Parent", "de": "Parent"},
	"topo.legend_wan":  {"en": "WAN", "de": "WAN"},
	"topo.legend_ip":   {"en": "IP configured", "de": "IP konfiguriert"},
	"topo.legend_none": {"en": "unconfigured", "de": "unkonfiguriert"},
	"topo.legend_vlan": {"en": "VLAN parent", "de": "VLAN-Parent"},

	// Graylog device inventory (extension)
	"topo.device":       {"en": "Device", "de": "Gerät"},
	"topo.devices":      {"en": "Devices", "de": "Geräte"},
	"topo.seen":         {"en": "Seen", "de": "Gesehen"},
	"topo.shared_mac":   {"en": "MAC seen with multiple IPs", "de": "MAC mit mehreren IPs gesehen"},
	"topo.shared_ip":    {"en": "IP shared by multiple MACs", "de": "IP von mehreren MACs verwendet"},
	"topo.fetch_now":    {"en": "⟳ Fetch device data", "de": "⟳ Gerätedaten abrufen"},
	"topo.fetching":     {"en": "fetching device data…", "de": "Gerätedaten werden abgerufen…"},
	"topo.dev_updated":  {"en": "device data updated", "de": "Gerätedaten aktualisiert"},
	"topo.fetch_failed": {"en": "Device data fetch failed.", "de": "Gerätedaten-Abruf fehlgeschlagen."},
	"topo.legend_share": {"en": "MAC/IP shared", "de": "MAC/IP geteilt"},

	// Switch interlinks / MC-LAG
	"topo.interlink":     {"en": "Interlink", "de": "Interlink"},
	"topo.mclag_group":   {"en": "MC-LAG Peer Group", "de": "MC-LAG-Peer-Gruppe"},
	"topo.mclag_info":    {"en": "Switches forming an MC-LAG pair (ICL detected)", "de": "Switches im MC-LAG-Verbund (ICL erkannt)"},
	"topo.link_detected": {"en": "detected via MAC match", "de": "per MAC-Zuordnung erkannt"},
}

// i18nJSON renders the whole catalog for a language as a JSON object (used by
// templates as `window.I18N = {{i18nJSON .Base.Lang}}`). Serializing every key
// costs a few hundred bytes per page and removes the failure mode of a
// hand-maintained JS-key list drifting from the catalog (a missed key would
// silently render as its raw name).
func i18nJSON(lang string) template.JS {
	m := make(map[string]string, len(uiMsgs))
	for k := range uiMsgs {
		m[k] = tr(lang, k)
	}
	blob, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return template.JS(blob) //nolint:gosec // values come from the static catalog above
}

// tr renders a UI catalog message in the given language, falling back to
// English, then to the key itself.
func tr(lang, key string, args ...any) string {
	m, ok := uiMsgs[key]
	if !ok {
		return key
	}
	s, ok := m[lang]
	if !ok || s == "" {
		s = m["en"]
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// localizeFindings substitutes the German text when the UI language is "de"
// and strips the duplicate field from the payload.
func localizeFindings(fs []auditFinding, lang string) []auditFinding {
	out := make([]auditFinding, len(fs))
	copy(out, fs)
	for i := range out {
		if lang == "de" && out[i].TextDE != "" {
			out[i].Text = out[i].TextDE
		}
		out[i].TextDE = ""
	}
	return out
}
