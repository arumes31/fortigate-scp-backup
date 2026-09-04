package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
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
		MaxAge: 365 * 24 * 3600, HttpOnly: true, Secure: s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	// Open-redirect guard: only follow a local, host-less path. url.Parse
	// populates Scheme/Host for "https://evil.com" and "//evil.com"; the
	// prefix checks additionally reject "/\evil", which browsers normalise to
	// "//evil" (a protocol-relative jump off-site). Anything else falls back to
	// "/". The validated request value itself is redirected (not a
	// reconstruction) so the check applies to exactly what is emitted.
	back := r.FormValue("back")
	if u, err := url.Parse(back); err != nil || u.IsAbs() || u.Hostname() != "" ||
		!strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") ||
		strings.HasPrefix(back, "/\\") {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// uiMsgs is the UI chrome catalog: key -> lang -> text.
var uiMsgs = map[string]map[string]string{
	// Audit page
	"audit.title":                      {"en": "Audit & Compliance Insights", "de": "Audit & Compliance Insights"},
	"audit.critical":                   {"en": "Critical findings", "de": "Kritische Findings"},
	"audit.warnings":                   {"en": "Warnings", "de": "Warnungen"},
	"audit.firewalls":                  {"en": "Firewalls", "de": "Firewalls"},
	"audit.audited":                    {"en": "Audited", "de": "Auditiert"},
	"audit.custom_rules":               {"en": "Custom audit rules", "de": "Eigene Audit-Regeln"},
	"audit.rule_name":                  {"en": "Rule name (e.g. SSH port check)", "de": "Regel-Name (z.B. SSH Port Check)"},
	"audit.rule_pattern":               {"en": "Search pattern (e.g. set admin-sport 443)", "de": "Such-Muster (z.B. set admin-sport 443)"},
	"audit.rule_severity":              {"en": "Severity", "de": "Schweregrad"},
	"audit.rule_remediation":           {"en": "Remediation (CLI commands)", "de": "Behebung (CLI Kommandos)"},
	"audit.rule_add":                   {"en": "Add rule", "de": "Regel hinzufügen"},
	"audit.rules_configured":           {"en": "Configured rules:", "de": "Konfigurierte Regeln:"},
	"audit.rule_delete":                {"en": "Delete rule", "de": "Regel löschen"},
	"audit.exemptions":                 {"en": "Active exemptions", "de": "Aktive Ausnahmen (Exemptions)"},
	"audit.exemption_reason":           {"en": "Reason:", "de": "Grund:"},
	"audit.exemption_none":             {"en": `No exemptions defined. Use the "Exempt" button on a firewall's findings.`, "de": `Keine Ausnahmen definiert. Verwenden Sie den "Ausnahme"-Button bei den Findings einer Firewall.`},
	"audit.exemption_revoke":           {"en": "Revoke", "de": "Aufheben"},
	"audit.exemption_global_badge":     {"en": "GLOBAL (all firewalls)", "de": "GLOBAL (alle Firewalls)"},
	"audit.exemption_make_global":      {"en": "Make global", "de": "Global machen"},
	"audit.exemption_make_global_hint": {"en": "Apply this exemption to every firewall, not just this one", "de": "Diese Ausnahme auf alle Firewalls anwenden, nicht nur auf diese"},
	"audit.exemption_make_local":       {"en": "Make firewall-only", "de": "Nur diese Firewall"},
	"audit.exemption_make_local_hint":  {"en": "Restrict this exemption back to its original firewall", "de": "Diese Ausnahme wieder auf die ursprüngliche Firewall beschränken"},
	"audit.per_firewall":               {"en": "Compliance & audit per firewall", "de": "Compliance & Audit je Firewall"},
	"audit.latest_configs":             {"en": "Evaluation of the latest configurations", "de": "Auswertung der neuesten Konfigurationen"},
	"audit.topology_link":              {"en": "Network topology →", "de": "Netzwerk-Topologie →"},
	"audit.search":                     {"en": "Search FQDN, model, ticket or finding...", "de": "Suche FQDN, Modell, Ticket oder Finding..."},
	"audit.filter":                     {"en": "Filter audit results", "de": "Audit-Ergebnisse filtern"},
	"audit.col_firewall":               {"en": "Firewall", "de": "Firewall"},
	"audit.col_system":                 {"en": "System", "de": "Systemdaten"},
	"audit.col_scores":                 {"en": "Compliance scores", "de": "Compliance Scores"},
	"audit.col_ticket":                 {"en": "Change ticket", "de": "Change Ticket"},
	"audit.col_actions":                {"en": "Actions & details", "de": "Aktionen & Details"},
	"audit.no_firewalls":               {"en": "No firewalls configured.", "de": "Keine Firewalls konfiguriert."},
	"audit.loading":                    {"en": "loading…", "de": "lädt…"},
	"audit.cve_db_live":                {"en": "CVE database: live (NVD + CISA KEV)", "de": "CVE-Datenbank: live (NVD + CISA KEV)"},
	"audit.cve_db_fallback":            {"en": "CVE database: offline fallback (never refreshed live)", "de": "CVE-Datenbank: Offline-Fallback (noch nie live aktualisiert)"},
	"audit.cve_db_never":               {"en": "no live update yet", "de": "noch kein Live-Update"},
	"audit.cve_db_updated":             {"en": "updated", "de": "aktualisiert"},
	"audit.cve_db_error":               {"en": "last refresh attempt failed", "de": "letzter Aktualisierungsversuch fehlgeschlagen"},
	"audit.cve_db_refresh":             {"en": "Refresh now", "de": "Jetzt aktualisieren"},

	// Audit page (JS strings)
	"audit.no_backup":              {"en": "— No backup —", "de": "— Kein Backup —"},
	"audit.model":                  {"en": "Model:", "de": "Modell:"},
	"audit.backup":                 {"en": "Backup:", "de": "Backup:"},
	"audit.computed":               {"en": "Audit computed:", "de": "Audit berechnet:"},
	"audit.ticket_id":              {"en": "e.g. INC-10298", "de": "z.B. INC-10298"},
	"audit.ticket_comment":         {"en": "Comment...", "de": "Kommentar..."},
	"audit.ticket_id_label":        {"en": "Ticket ID", "de": "Ticket-ID"},
	"audit.ticket_comment_label":   {"en": "Comment", "de": "Kommentar"},
	"audit.exemption_reason_label": {"en": "Reason", "de": "Grund"},
	"audit.details_show":           {"en": "Show details", "de": "Details anzeigen"},
	"audit.details_hide":           {"en": "Hide details", "de": "Details ausblenden"},
	"audit.n_critical":             {"en": "critical", "de": "kritisch"},
	"audit.n_warnings":             {"en": "warnings", "de": "Warnungen"},
	"audit.clean":                  {"en": "clean", "de": "sauber"},
	"audit.recheck":                {"en": "↻ Re-check", "de": "↻ Neu prüfen"},
	"audit.recheck_title":          {"en": "Recompute audit", "de": "Audit neu berechnen"},
	"audit.load_error":             {"en": "Failed to load", "de": "Fehler beim Laden"},
	"audit.retry":                  {"en": "Retry", "de": "Erneut versuchen"},
	"audit.exempt":                 {"en": "Exempt", "de": "Ausnahme"},
	"audit.exempt_reason":          {"en": "Reason for exemption...", "de": "Grund für Ausnahme..."},
	"audit.show_cli":               {"en": "Show remediation (CLI)", "de": "Behebung (CLI) anzeigen"},
	"audit.show_context":           {"en": "Show config context (line %d)", "de": "Konfigurations-Kontext (Zeile %d) anzeigen"},
	"audit.findings_title":         {"en": "Security & compliance findings", "de": "Sicherheits- & Compliance-Findings"},
	"audit.findings_none":          {"en": "No active findings for this firewall!", "de": "Keine aktiven Findings für diese Firewall vorhanden!"},
	"audit.exempted_title":         {"en": "Ignored findings (exempted):", "de": "Ignorierte Findings (Exempted):"},
	"audit.exempted_note":          {"en": "(registered as exemption)", "de": "(Als Ausnahme registriert)"},
	"audit.upgrade_title":          {"en": "FortiOS upgrade path", "de": "FortiOS Upgrade-Pfad"},
	"audit.upgrade_note":           {"en": "Recommended path for updating the operating system:", "de": "Empfohlener Pfad zur Aktualisierung des Betriebssystems:"},

	// Topology page
	"topo.title":              {"en": "Network topology", "de": "Netzwerk-Topologie"},
	"topo.firewall":           {"en": "Firewall:", "de": "Firewall:"},
	"topo.hint":               {"en": "Scroll = zoom · Drag = pan · Click firewall/switch = faceplate", "de": "Scrollen = Zoom · Ziehen = Verschieben · Klick auf Firewall/Switch = Frontblende"},
	"topo.reset":              {"en": "⤢ Reset view", "de": "⤢ Ansicht zurücksetzen"},
	"topo.maximize":           {"en": "Maximize", "de": "Vollbild"},
	"topo.exit_max":           {"en": "Exit", "de": "Schließen"},
	"topo.debug":              {"en": "Debug", "de": "Debug"},
	"topo.debug_hint":         {"en": "Show every query this page made and what came back", "de": "Alle Abfragen dieser Seite und deren Ergebnisse anzeigen"},
	"topo.debug_title":        {"en": "Debug — queried data & results", "de": "Debug — abgefragte Daten & Ergebnisse"},
	"topo.debug_empty":        {"en": "No queries recorded yet — reload the topology or trigger a device fetch.", "de": "Noch keine Abfragen erfasst — Topologie neu laden oder Gerätedaten abrufen."},
	"topo.debug_no_body":      {"en": "no response body", "de": "keine Antwortdaten"},
	"topo.debug_truncated":    {"en": "truncated, full size", "de": "gekürzt, volle Größe"},
	"topo.debug_topology":     {"en": "Topology data", "de": "Topologiedaten"},
	"topo.debug_devices":      {"en": "Device data", "de": "Gerätedaten"},
	"topo.debug_refresh":      {"en": "Device refresh (manual)", "de": "Gerätedaten-Refresh (manuell)"},
	"topo.debug_portdiag":     {"en": "Port diagnostics", "de": "Port-Diagnose"},
	"topo.ap":                 {"en": "AP", "de": "AP"},
	"topo.share":              {"en": "Public link:", "de": "Öffentlicher Link:"},
	"topo.share_24h":          {"en": "24 hours", "de": "24 Stunden"},
	"topo.share_7d":           {"en": "7 days", "de": "7 Tage"},
	"topo.share_30d":          {"en": "30 days", "de": "30 Tage"},
	"topo.share_never":        {"en": "Unlimited", "de": "Unbegrenzt"},
	"topo.share_make":         {"en": "Create link", "de": "Link erstellen"},
	"topo.share_embed":        {"en": "Embed (topology only)", "de": "Einbetten (nur Topologie)"},
	"topo.share_devices":      {"en": "Include devices", "de": "Geräte einschließen"},
	"topo.share_devices_hint": {"en": "Expose client MAC/IP/hostname and 802.1X identity on this public link", "de": "Client-MAC/IP/Hostname und 802.1X-Identität auf diesem öffentlichen Link sichtbar machen"},
	"topo.copy":               {"en": "Copy", "de": "Kopieren"},
	"topo.copied":             {"en": "✓ Copied", "de": "✓ Kopiert"},
	"topo.created":            {"en": "created", "de": "erstellt"},
	"topo.expires":            {"en": "expires", "de": "läuft ab"},
	"topo.no_expiry":          {"en": "unlimited", "de": "unbegrenzt"},
	"topo.revoke":             {"en": "Revoke", "de": "Widerrufen"},
	"topo.share_fail":         {"en": "Could not create link:", "de": "Link konnte nicht erstellt werden:"},
	"topo.copy_hint":          {"en": "Click to copy", "de": "Klicken zum Kopieren"},
	"topo.shared_view":        {"en": "READ-ONLY · SHARED VIEW", "de": "NUR LESEN · GETEILTE ANSICHT"},

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
	"topo.vlan_colors": {"en": "VLANs", "de": "VLANs"},

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
	"topo.no_devices":   {"en": "No devices found — check that device-detection / DHCP logging is enabled on the FortiGate.", "de": "Keine Geräte gefunden — prüfen Sie, ob Geräteerkennung / DHCP-Logging auf dem FortiGate aktiviert ist."},
	"topo.live":         {"en": "Live", "de": "Live"},
	"topo.live_hint":    {"en": "Poll Graylog for device data every minute (auto-stops after 10 min)", "de": "Gerätedaten jede Minute von Graylog abrufen (stoppt automatisch nach 10 Min)"},
	"topo.legend_share": {"en": "MAC/IP shared", "de": "MAC/IP geteilt"},

	// Switch interlinks / MC-LAG
	"topo.interlink":     {"en": "Interlink", "de": "Interlink"},
	"topo.mclag_group":   {"en": "MC-LAG Peer Group", "de": "MC-LAG-Peer-Gruppe"},
	"topo.mclag_info":    {"en": "Switches forming an MC-LAG pair (ICL detected)", "de": "Switches im MC-LAG-Verbund (ICL erkannt)"},
	"topo.link_detected": {"en": "detected via MAC match", "de": "per MAC-Zuordnung erkannt"},
	"topo.mclag_icl":     {"en": "MC-LAG ICL", "de": "MC-LAG ICL"},
	"topo.isl":           {"en": "ISL", "de": "ISL"},
	"topo.tagged":        {"en": "Tagged VLANs", "de": "Tagged VLANs"},
	"topo.all_vlans":     {"en": "all", "de": "alle"},

	// Zones / DHCP / SD-WAN / VPN / HA / wireless
	"topo.zone":          {"en": "Zone", "de": "Zone"},
	"topo.checks":        {"en": "Health checks", "de": "Health-Checks"},
	"topo.remote_gw":     {"en": "Remote gateway", "de": "Remote-Gateway"},
	"topo.egress":        {"en": "Egress interface", "de": "Egress-Interface"},
	"topo.vpn_tunnels":   {"en": "IPsec VPN tunnels", "de": "IPsec-VPN-Tunnel"},
	"topo.vpn_none":      {"en": "No IPsec VPN tunnels configured.", "de": "Keine IPsec-VPN-Tunnel konfiguriert."},
	"topo.vpn_up":        {"en": "up", "de": "aktiv"},
	"topo.vpn_down":      {"en": "down", "de": "inaktiv"},
	"topo.vpn_unknown":   {"en": "no state logged", "de": "kein Status geloggt"},
	"topo.bundles":       {"en": "Aggregates & switch bundles", "de": "Aggregate & Switch-Bündel"},
	"topo.bundle_member": {"en": "Bundle", "de": "Bündel"},
	"topo.members":       {"en": "Members", "de": "Mitglieder"},
	"topo.iface_type":    {"en": "Type", "de": "Typ"},
	"topo.ha_heartbeat":  {"en": "HA heartbeat", "de": "HA-Heartbeat"},
	"topo.admin_down":    {"en": "Administratively down", "de": "Administrativ deaktiviert"},
	"topo.media":         {"en": "Media", "de": "Medium"},
	"topo.optic":         {"en": "Optic", "de": "Optik"},
	"topo.optic_empty":   {"en": "empty cage", "de": "leerer Slot"},
	"topo.port_errors":   {"en": "Errors", "de": "Fehler"},
	"topo.lldp_neighbor": {"en": "LLDP neighbor", "de": "LLDP-Nachbar"},
	"topo.fan":           {"en": "Fan", "de": "Lüfter"},
	"topo.err_ports":     {"en": "ports with errors", "de": "Ports mit Fehlern"},
	"topo.live_routes":   {"en": "Live routes", "de": "Aktive Routen"},
	"topo.tcn":           {"en": "STP changes", "de": "STP-Änderungen"},
	"topo.sdwan_sla":     {"en": "SD-WAN SLA", "de": "SD-WAN-SLA"},
	"topo.throughput":    {"en": "Throughput", "de": "Durchsatz"},
	"topo.ssh_collected": {"en": "SSH", "de": "SSH"},
	"topo.led_admin":     {"en": "admin state (up / down)", "de": "Admin-Status (auf / ab)"},
	"topo.ha_standby":    {"en": "HA peer (standby)", "de": "HA-Peer (Standby)"},
	"topo.group":         {"en": "Group", "de": "Gruppe"},
	"topo.switch_groups": {"en": "Switch groups", "de": "Switch-Gruppen"},
	"topo.nac":           {"en": "NAC segment", "de": "NAC-Segment"},
	"topo.aps":           {"en": "Access Points", "de": "Access Points"},
	"topo.ap_port":       {"en": "Switch port", "de": "Switch-Port"},
	"topo.profile":       {"en": "Profile", "de": "Profil"},
	"topo.ssid_name":     {"en": "SSID", "de": "SSID"},
	"topo.security":      {"en": "Security", "de": "Sicherheit"},

	// Search / filters / device panel / context menu
	"topo.status_down":    {"en": "administratively down", "de": "administrativ deaktiviert"},
	"topo.stale":          {"en": "stale (>24h)", "de": "veraltet (>24h)"},
	"topo.search_ph":      {"en": "Search name / IP / MAC…", "de": "Suche Name / IP / MAC…"},
	"topo.no_match":       {"en": "no match", "de": "kein Treffer"},
	"topo.routes":         {"en": "Routes", "de": "Routen"},
	"topo.edge_switches":  {"en": "Edge switches", "de": "Edge-Switches"},
	"topo.hide_stale":     {"en": "Hide stale", "de": "Veraltete ausblenden"},
	"topo.run_diag":       {"en": "Run diagnostics", "de": "Diagnose ausführen"},
	"topo.diag_running":   {"en": "Running…", "de": "Läuft…"},
	"topo.diag_ran":       {"en": "Queried", "de": "Abgefragt"},
	"topo.diag_busy":      {"en": "A diagnostics query is already running for this firewall — try again shortly.", "de": "Für diese Firewall läuft bereits eine Diagnose — bitte gleich erneut versuchen."},
	"topo.diag_error":     {"en": "Diagnostics failed (SSH unreachable or disabled).", "de": "Diagnose fehlgeschlagen (SSH nicht erreichbar oder deaktiviert)."},
	"topo.diag_none":      {"en": "No diagnostic output returned.", "de": "Keine Diagnose-Ausgabe erhalten."},
	"topo.dev_filter_ph":  {"en": "Filter MAC / IP / host / VLAN…", "de": "Filter MAC / IP / Host / VLAN…"},
	"topo.stp_blocked":    {"en": "Blocked port(s)", "de": "Blockierte(r) Port(s)"},
	"topo.history":        {"en": "History (48h)", "de": "Verlauf (48h)"},
	"topo.multi_mac":      {"en": "several MACs — mini-switch/AP?", "de": "mehrere MACs — Mini-Switch/AP?"},
	"topo.uplink":         {"en": "Uplink", "de": "Uplink"},
	"topo.icl":            {"en": "MC-LAG ICL", "de": "MC-LAG ICL"},
	"topo.mclag_peer":     {"en": "MC-LAG peer", "de": "MC-LAG-Partner"},
	"topo.dual_homed":     {"en": "Dual-homed", "de": "Dual-homed"},
	"topo.suspected_team": {"en": "Suspected teamed server", "de": "Vermuteter Team-Server"},
	"topo.also_on":        {"en": "also on", "de": "auch an"},
	"topo.src_graylog":    {"en": "Data source: Graylog client logs", "de": "Datenquelle: Graylog-Client-Logs"},
	"topo.src_ssh":        {"en": "Data source: SSH (FortiSwitch MAC table + ARP/802.1X)", "de": "Datenquelle: SSH (FortiSwitch-MAC-Tabelle + ARP/802.1X)"},
	"topo.src_config":     {"en": "Data source: configuration", "de": "Datenquelle: Konfiguration"},
	"topo.poe_delivering": {"en": "Delivering", "de": "Liefert"},
	"topo.poe_searching":  {"en": "searching (no powered device)", "de": "sucht (kein Verbraucher)"},
	"topo.poe_off":        {"en": "off", "de": "aus"},
	"topo.poe_fault":      {"en": "fault", "de": "Fehler"},
	"topo.poe_of":         {"en": "of", "de": "von"},
	"topo.poe_class":      {"en": "class", "de": "Klasse"},
	"topo.poe_budget":     {"en": "switch budget", "de": "Switch-Budget"},
	"topo.port_security":  {"en": "Port-security violation", "de": "Port-Security-Verletzung"},
	"topo.violations":     {"en": "violation(s)", "de": "Verletzung(en)"},
	"topo.flaps":          {"en": "link events (48h) — possible flapping", "de": "Link-Ereignisse (48h) — mögliches Flapping"},
	"topo.quarantine":     {"en": "Quarantine VLAN", "de": "Quarantäne-VLAN"},
	"topo.dot1x_auth":     {"en": "802.1X authorized", "de": "802.1X autorisiert"},
	"topo.dot1x_unauth":   {"en": "802.1X unauthorized", "de": "802.1X nicht autorisiert"},
	"topo.port_devices":   {"en": "Devices on port", "de": "Geräte am Port"},
	"topo.wifi_clients":   {"en": "WiFi clients", "de": "WLAN-Clients"},
	"topo.bpdu_fix":       {"en": "Re-enable after clearing the loop", "de": "Nach Beheben des Loops reaktivieren"},
	"topo.first_seen":     {"en": "First seen", "de": "Zuerst gesehen"},
	"topo.ctx_copy":       {"en": "Copy", "de": "Kopieren"},
	"topo.ctx_faceplate":  {"en": "Open faceplate", "de": "Frontblende öffnen"},
	"topo.ctx_expand":     {"en": "Expand", "de": "Aufklappen"},
	"topo.ctx_collapse":   {"en": "Collapse", "de": "Zuklappen"},

	// Dashboard page (currently-running card)
	"dashboard.running_title":      {"en": "Currently running", "de": "Läuft gerade"},
	"dashboard.running_since":      {"en": "since", "de": "seit"},
	"dashboard.running_backup":     {"en": "SSH backup", "de": "SSH-Backup"},
	"dashboard.running_analysis":   {"en": "Graylog analysis", "de": "Graylog-Analyse"},
	"dashboard.running_devicedata": {"en": "Topology data refresh", "de": "Topologie-Daten-Update"},
	"dashboard.running_sshdiag":    {"en": "SSH diagnostics", "de": "SSH-Diagnose"},
	"dashboard.running_live":       {"en": "Live view", "de": "Live-Ansicht"},
	"dashboard.running_audit":      {"en": "Audit scan", "de": "Audit-Scan"},

	// Dashboard page (failing firewalls table)
	"dashboard.failing_title": {"en": "Failing Firewalls", "de": "Fehlgeschlagene Firewalls"},
	"dashboard.all_firewalls": {"en": "All Firewalls", "de": "Alle Firewalls"},
	"dashboard.col_id":        {"en": "ID", "de": "ID"},
	"dashboard.col_fqdn":      {"en": "FQDN", "de": "FQDN"},
	"dashboard.col_last_ok":   {"en": "Last Success", "de": "Letzter Erfolg"},
	"dashboard.col_error":     {"en": "Error", "de": "Fehler"},
	"dashboard.col_actions":   {"en": "Actions", "de": "Aktionen"},
	"dashboard.never":         {"en": "never", "de": "nie"},
	"dashboard.retry":         {"en": "Retry", "de": "Wiederholen"},
	"dashboard.test":          {"en": "Test", "de": "Test"},
	"dashboard.backups":       {"en": "Backups", "de": "Backups"},
	"dashboard.failing_none":  {"en": "No failing firewalls.", "de": "Keine fehlgeschlagenen Firewalls."},

	// Dashboard page (stale backups card)
	"dashboard.stale_title": {"en": "Stale backups", "de": "Veraltete Backups"},
	"dashboard.stale_desc":  {"en": "firewall(s) overdue but not reporting a failure", "de": "Firewall(s) überfällig, aber ohne Fehlermeldung"},
	"dashboard.col_age":     {"en": "Age", "de": "Alter"},
	"dashboard.col_cadence": {"en": "Cadence", "de": "Takt"},
	"dashboard.stale_ago":   {"en": "ago", "de": "her"},
	"dashboard.stale_every": {"en": "expected every", "de": "erwartet alle"},
	"dashboard.backup_now":  {"en": "Backup now", "de": "Jetzt sichern"},

	// Dashboard page (blocked switch ports card)
	"dashboard.blocked_title":       {"en": "Blocked switch ports (STP / BPDU / loop guard)", "de": "Blockierte Switch-Ports (STP / BPDU / Loop Guard)"},
	"dashboard.blocked_unit":        {"en": "port(s)", "de": "Port(s)"},
	"dashboard.col_firewall":        {"en": "Firewall", "de": "Firewall"},
	"dashboard.col_switch":          {"en": "Switch", "de": "Switch"},
	"dashboard.col_port":            {"en": "Port", "de": "Port"},
	"dashboard.col_reason":          {"en": "Reason", "de": "Grund"},
	"dashboard.col_since":           {"en": "Since", "de": "Seit"},
	"dashboard.topology":            {"en": "Topology", "de": "Topologie"},
	"dashboard.check":               {"en": "Check", "de": "Prüfen"},
	"dashboard.check_all":           {"en": "Check All", "de": "Alle prüfen"},
	"dashboard.checking":            {"en": "Checking…", "de": "Prüfe…"},
	"dashboard.check_recovered":     {"en": "Recovered — removed", "de": "Behoben — entfernt"},
	"dashboard.check_still_blocked": {"en": "Still blocked (confirmed just now)", "de": "Weiterhin blockiert (soeben bestätigt)"},
	"dashboard.check_failed":        {"en": "Check failed", "de": "Prüfung fehlgeschlagen"},
	"dashboard.check_busy":          {"en": "Busy, try again shortly", "de": "Beschäftigt, bitte gleich erneut versuchen"},

	// Dashboard page (Graylog logging status card, from the FGT ADM VPN config)
	"dashboard.graylog_title":      {"en": "Graylog logging issues", "de": "Graylog-Logging-Probleme"},
	"dashboard.graylog_help_title": {"en": "How to fix", "de": "Fehlerbehebung"},
	"dashboard.graylog_help_1":     {"en": `Check "Firewallname" in FGT ADM VPN Config — it must match the device's hostname on the FortiGate.`, "de": `"Firewallname" in FGT ADM VPN Config prüfen — muss dem Gerätenamen (Hostname) auf dem FortiGate entsprechen.`},
	"dashboard.graylog_help_2":     {"en": `For an HA cluster, "Cluster Hostnames" in FGT ADM VPN Config must correctly list both member hostnames.`, "de": `Bei einem HA-Cluster müssen die "Cluster Hostnames" in FGT ADM VPN Config beide Mitglieder-Hostnamen korrekt auflisten.`},
	"dashboard.graylog_help_3":     {"en": `The ADM IPsec tunnel to RO must be up.`, "de": `Der ADM-IPsec-Tunnel zu RO muss aktiv sein.`},
	"dashboard.graylog_help_4":     {"en": `Restart syslog on the firewall via FortiManager script "reenable-syslog".`, "de": `Syslog auf der Firewall über das FortiManager-Skript "reenable-syslog" neu starten.`},
	"dashboard.col_site":           {"en": "Site", "de": "Standort"},
	"dashboard.col_status":         {"en": "Status", "de": "Status"},
	"dashboard.col_checked":        {"en": "Last checked", "de": "Zuletzt geprüft"},
	"dashboard.gl_offline":         {"en": "offline", "de": "offline"},
	"dashboard.gl_error":           {"en": "error", "de": "Fehler"},
	"dashboard.gl_config_missing":  {"en": "not configured", "de": "nicht konfiguriert"},

	// Dashboard page (DNS record issues card, from the FGT ADM VPN config)
	"dashboard.dns_title":      {"en": "DNS record issues (ADM VPN)", "de": "DNS-Record-Probleme (ADM VPN)"},
	"dashboard.col_dns_name":   {"en": "DNS name", "de": "DNS-Name"},
	"dashboard.col_resolved":   {"en": "Resolves to", "de": "Löst auf zu"},
	"dashboard.col_expected":   {"en": "Expected", "de": "Erwartet"},
	"dashboard.dns_unresolved": {"en": "no DNS record", "de": "kein DNS-Eintrag"},
	"dashboard.dns_mismatch":   {"en": "wrong IP", "de": "falsche IP"},

	// Dashboard page (expiring licenses card)
	"dashboard.lic_title":       {"en": "Expiring licenses", "de": "Ablaufende Lizenzen"},
	"dashboard.lic_col_service": {"en": "First expiring service", "de": "Zuerst ablaufender Dienst"},
	"dashboard.lic_col_expiry":  {"en": "Expiry", "de": "Ablauf"},
	"dashboard.lic_expired":     {"en": "expired", "de": "abgelaufen"},
	"dashboard.lic_days":        {"en": "days", "de": "Tage"},

	// Licenses page
	"lic.title":                 {"en": "License Inventory", "de": "Lizenz-Inventar"},
	"lic.summary":               {"en": "FortiGuard entitlements", "de": "FortiGuard-Lizenzen"},
	"lic.devices":               {"en": "devices", "de": "Geräte"},
	"lic.expiring":              {"en": "expiring ≤ 60d", "de": "laufen ≤ 60 T. ab"},
	"lic.expired":               {"en": "expired", "de": "abgelaufen"},
	"lic.unknown":               {"en": "no data", "de": "keine Daten"},
	"lic.note":                  {"en": "Collected daily per device via SSH (get system status, diagnose autoupdate versions). Covers FortiGuard service entitlements — the FortiCare hardware/support contract is not exposed by these commands. HA clusters report the primary's serial.", "de": "Täglich pro Gerät via SSH erfasst (get system status, diagnose autoupdate versions). Umfasst FortiGuard-Dienstlizenzen — der FortiCare-Hardware-/Support-Vertrag ist über diese Kommandos nicht auslesbar. HA-Cluster melden die Seriennummer des Primary."},
	"lic.inventory":             {"en": "Devices", "de": "Geräte"},
	"lic.search":                {"en": "Search licenses…", "de": "Lizenzen durchsuchen…"},
	"lic.refresh_all":           {"en": "Refresh All", "de": "Alle aktualisieren"},
	"lic.refresh":               {"en": "Refresh", "de": "Aktualisieren"},
	"lic.details":               {"en": "Details", "de": "Details"},
	"lic.col_firewall":          {"en": "Firewall", "de": "Firewall"},
	"lic.col_hostname":          {"en": "Hostname", "de": "Hostname"},
	"lic.col_serial":            {"en": "Serial", "de": "Seriennummer"},
	"lic.col_model":             {"en": "Model", "de": "Modell"},
	"lic.col_firmware":          {"en": "Firmware", "de": "Firmware"},
	"lic.col_registration":      {"en": "Registration", "de": "Registrierung"},
	"lic.col_expiry":            {"en": "Contract expiry", "de": "Vertragsablauf"},
	"lic.col_fetched":           {"en": "Fetched", "de": "Abgerufen"},
	"lic.col_actions":           {"en": "Actions", "de": "Aktionen"},
	"lic.col_service":           {"en": "Service", "de": "Dienst"},
	"lic.col_version":           {"en": "Version", "de": "Version"},
	"lic.col_last_update":       {"en": "Last update", "de": "Letztes Update"},
	"lic.col_result":            {"en": "Result", "de": "Ergebnis"},
	"lic.pill_expired":          {"en": "EXPIRED", "de": "ABGELAUFEN"},
	"lic.pill_unknown":          {"en": "unknown", "de": "unbekannt"},
	"lic.lapsed":                {"en": "lapsed", "de": "ausgelaufen"},
	"lic.lapsed_hint":           {"en": "Services whose contract already ended; they do not drive the device status while active entitlements remain. See details.", "de": "Dienste mit bereits beendetem Vertrag; sie bestimmen den Gerätestatus nicht, solange aktive Lizenzen bestehen. Siehe Details."},
	"lic.none":                  {"en": "No firewalls configured.", "de": "Keine Firewalls konfiguriert."},
	"lic.managed_devices":       {"en": "Managed switches & access points", "de": "Verwaltete Switches & Access Points"},
	"lic.devices_note":          {"en": "The FortiGate does not expose FortiCare contracts of managed switches/APs — look the serial up in FortiCloud asset management.", "de": "Die FortiGate zeigt keine FortiCare-Verträge verwalteter Switches/APs — Seriennummer im FortiCloud-Asset-Management nachschlagen."},
	"lic.col_type":              {"en": "Type", "de": "Typ"},
	"lic.col_name":              {"en": "Name", "de": "Name"},
	"lic.col_status":            {"en": "Status", "de": "Status"},
	"lic.kind_switch":           {"en": "Switch", "de": "Switch"},
	"lic.kind_ap":               {"en": "AP", "de": "AP"},
	"lic.online":                {"en": "online", "de": "online"},
	"lic.offline":               {"en": "offline", "de": "offline"},
	"lic.origin_logs":           {"en": "logs", "de": "Logs"},
	"lic.origin_logs_hint":      {"en": "Seen in Graylog logs/diagnostics — not reported by the firewall's CLI in the last sweep.", "de": "In Graylog-Logs/Diagnosen gesehen — von der CLI der Firewall im letzten Durchlauf nicht gemeldet."},
	"lic.serial_from_logs_hint": {"en": "Serial resolved from Graylog logs (switch offline).", "de": "Seriennummer aus Graylog-Logs ermittelt (Switch offline)."},

	// IPAM page
	"ipam.title":            {"en": "Fleet IPAM", "de": "Flotten-IPAM"},
	"ipam.loading":          {"en": "Loading…", "de": "Lädt…"},
	"ipam.last_updated":     {"en": "Last updated", "de": "Zuletzt aktualisiert"},
	"ipam.update_now":       {"en": "Update now", "de": "Jetzt aktualisieren"},
	"ipam.updating":         {"en": "Updating —", "de": "Aktualisiere —"},
	"ipam.never":            {"en": "not computed yet", "de": "noch nicht berechnet"},
	"ipam.firewalls":        {"en": "firewalls", "de": "Firewalls"},
	"ipam.prefixes":         {"en": "unique prefixes", "de": "eindeutige Präfixe"},
	"ipam.overlaps":         {"en": "overlaps", "de": "Überschneidungen"},
	"ipam.overlaps_title":   {"en": "Cross-firewall overlaps", "de": "Firewall-übergreifende Überschneidungen"},
	"ipam.no_overlaps":      {"en": "No cross-firewall overlaps found.", "de": "Keine firewall-übergreifenden Überschneidungen gefunden."},
	"ipam.table_title":      {"en": "All prefixes", "de": "Alle Präfixe"},
	"ipam.search":           {"en": "Search prefixes or IP…", "de": "Präfixe oder IP durchsuchen…"},
	"ipam.col_prefix":       {"en": "Prefix", "de": "Präfix"},
	"ipam.col_firewall":     {"en": "Firewall", "de": "Firewall"},
	"ipam.col_source":       {"en": "Source", "de": "Quelle"},
	"ipam.col_name":         {"en": "Name / detail", "de": "Name / Detail"},
	"ipam.col_kind":         {"en": "Kind", "de": "Art"},
	"ipam.col_contains":     {"en": "Contains", "de": "Enthält"},
	"ipam.col_firewalls":    {"en": "Firewalls", "de": "Firewalls"},
	"ipam.finalizing":       {"en": "Computing overlaps…", "de": "Berechne Überschneidungen…"},
	"ipam.more_rows":        {"en": "more rows — refine your search", "de": "weitere Zeilen — Suche verfeinern"},
	"ipam.kind_duplicate":   {"en": "exact duplicate", "de": "exaktes Duplikat"},
	"ipam.kind_containment": {"en": "containment", "de": "Teilmenge"},
	"ipam.src_interface":    {"en": "interface", "de": "Interface"},
	"ipam.src_secondary":    {"en": "secondary IP", "de": "sekundäre IP"},
	"ipam.src_route":        {"en": "static route", "de": "statische Route"},
	"ipam.src_dhcp":         {"en": "DHCP scope", "de": "DHCP-Bereich"},
	"ipam.src_address":      {"en": "address object", "de": "Adressobjekt"},
	"ipam.error":            {"en": "Failed to load IPAM data.", "de": "IPAM-Daten konnten nicht geladen werden."},
	"ipam.note":             {"en": "Aggregated from each firewall's latest config backup: interface networks, secondary IPs, DHCP scopes, static routes and subnet address objects. Same-firewall overlaps are expected and not flagged; 0.0.0.0/0 and /32 hosts are excluded from overlap analysis.", "de": "Aggregiert aus dem jeweils letzten Konfigurations-Backup: Interface-Netze, sekundäre IPs, DHCP-Bereiche, statische Routen und Subnetz-Adressobjekte. Überschneidungen innerhalb derselben Firewall sind normal und werden nicht markiert; 0.0.0.0/0 und /32-Hosts sind von der Analyse ausgenommen."},
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
