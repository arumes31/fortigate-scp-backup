package reportmodel

const (
	Available           = "available"
	RequiresGraylog     = "requires_graylog"
	RequiresIntegration = "requires_integration"
	NotImplemented      = "not_implemented"
)

func datasetDefinitions() []DatasetDefinition {
	return []DatasetDefinition{
		{
			ID: "source", Name: "Backup provenance", NameDE: "Herkunft der Sicherung", Status: Available, Source: "backup",
			Description:   "Immutable source identity and observation time. A backup is a configuration snapshot, not a measured traffic interval.",
			DescriptionDE: "Unveränderliche Quellenkennung und Zeitpunkt der Sicherung. Eine Sicherung ist eine Konfigurationsaufnahme, kein gemessener Verkehrszeitraum.",
			Columns:       []DatasetColumn{{"firewall_id", "Firewall ID", "Firewall-ID", "integer"}, {"backup_id", "Backup ID", "Sicherungs-ID", "integer"}, {"backup_at", "Backup time", "Sicherungszeitpunkt", "datetime"}, {"checksum", "Source checksum", "Quellprüfsumme", "string"}},
			RequiredData:  []string{"Committed configuration backup"},
		},
		{
			ID: "publications", Name: "Configured publications", NameDE: "Konfigurierte Veröffentlichungen", Status: Available, Source: "backup",
			Description:   "VIP and virtual-server inventory with configured policy outcomes, mapping limitations, and source evidence.",
			DescriptionDE: "VIP- und Virtual-Server-Inventar mit konfigurierten Regelergebnissen, Zuordnungsgrenzen und Quellenbelegen.",
			Columns:       []DatasetColumn{{"vdom", "VDOM", "VDOM", "string"}, {"name", "Object", "Objekt", "string"}, {"kind", "Type category", "Typkategorie", "enum"}, {"outcome", "Configured outcome", "Konfiguriertes Ergebnis", "enum"}, {"geo_status", "Geographic restriction", "Geografische Einschränkung", "enum"}, {"evidence", "Evidence", "Beleg", "string"}},
			RequiredData:  []string{"Complete FortiOS configuration backup"},
		},
		{
			ID: "policy_traces", Name: "Ordered policy traces", NameDE: "Geordnete Regelspuren", Status: Available, Source: "backup",
			Description:   "Complete evaluated rule order for each selected publication; filtering never removes earlier rules from the analysis.",
			DescriptionDE: "Vollständige bewertete Regelreihenfolge je ausgewählter Veröffentlichung; Filter entfernen keine früheren Regeln aus der Analyse.",
			Columns:       []DatasetColumn{{"sequence", "Configuration order", "Konfigurationsreihenfolge", "integer"}, {"id", "Policy ID", "Regel-ID", "string"}, {"action", "Action", "Aktion", "string"}, {"effect", "Evaluated effect", "Bewertete Wirkung", "string"}, {"evidence", "Evidence", "Beleg", "string"}},
			RequiredData:  []string{"Publication and policy definitions in the same backup"},
		},
		{
			ID: "technical_inventory", Name: "Technical configuration inventory", NameDE: "Technisches Konfigurationsinventar", Status: Available, Source: "backup",
			Description:   "Allowlisted interfaces, routing, SD-WAN, DHCP/DNS, VPN, HA, administration, logging, time, policies, and inspection metadata.",
			DescriptionDE: "Freigegebene Metadaten zu Schnittstellen, Routing, SD-WAN, DHCP/DNS, VPN, HA, Administration, Logging, Zeit, Regeln und Prüfprofilen.",
			Columns:       []DatasetColumn{{"section_id", "Section", "Abschnitt", "enum"}, {"vdom", "VDOM", "VDOM", "string"}, {"label", "Object", "Objekt", "string"}, {"value", "Configured metadata", "Konfigurierte Metadaten", "string"}, {"evidence", "Evidence", "Beleg", "string"}},
			RequiredData:  []string{"Configuration backup; credentials and arbitrary raw blocks are excluded"},
		},
		{
			ID: "findings", Name: "Configuration findings", NameDE: "Konfigurationsfeststellungen", Status: Available, Source: "backup",
			Description:   "Evidence-based configuration review topics and recommendations; findings do not certify live security or compliance.",
			DescriptionDE: "Belegte Konfigurationsthemen und Empfehlungen; Feststellungen bestätigen weder aktuelle Sicherheit noch vollständige Compliance.",
			Columns:       []DatasetColumn{{"category", "Category", "Kategorie", "enum"}, {"vdom", "VDOM", "VDOM", "string"}, {"priority", "Priority", "Priorität", "enum"}, {"title", "Review topic", "Prüfthema", "string"}, {"recommendation", "Recommendation", "Empfehlung", "string"}},
			RequiredData:  []string{"Completed configuration assessment"},
		},
		{
			ID: "configuration_counts", Name: "Configuration counts", NameDE: "Konfigurationszahlen", Status: Available, Source: "backup",
			Description:   "Fixed, audience-safe counts by finding priority, publication type, configured outcome, and geographic assessment.",
			DescriptionDE: "Feste, zielgruppengerechte Zahlen nach Priorität, Veröffentlichungstyp, konfiguriertem Ergebnis und geografischer Bewertung.",
			Columns:       []DatasetColumn{{"chart", "Chart", "Diagramm", "enum"}, {"category", "Category", "Kategorie", "enum"}, {"count", "Count", "Anzahl", "integer"}},
			RequiredData:  []string{"Selected configuration assessment"},
		},
		{
			ID: "traffic", Name: "Observed traffic", NameDE: "Beobachteter Datenverkehr", Status: RequiresGraylog, Source: "graylog",
			Description:   "Timestamped, device-scoped FortiGate log-record counts, with optional terminal-session byte counters when the required fields exist.",
			DescriptionDE: "Zeitbezogene, gerätebezogene FortiGate-Logzahlen mit optionalen Bytezählern bei Sitzungsende, sofern die erforderlichen Felder vorhanden sind.",
			Columns:       []DatasetColumn{{"time", "Time", "Zeit", "datetime"}, {"category", "Group", "Gruppe", "string"}, {"count", "Observed records", "Beobachtete Datensätze", "integer"}, {"bytes", "Reported bytes", "Gemeldete Bytes", "integer"}},
			RequiredData:  []string{"Configured Graylog access", "Device-attributed FortiGate traffic logs", "Canonical type/subtype and the grouping or counter fields required by each dataset"},
		},
		{
			ID: "security_events", Name: "Observed security events", NameDE: "Beobachtete Sicherheitsereignisse", Status: RequiresGraylog, Source: "graylog",
			Description:   "Observed IPS, antivirus, web/DNS, application-control, and DLP events depend on received log types and fields.",
			DescriptionDE: "Beobachtete IPS-, Antivirus-, Web/DNS-, Anwendungskontroll- und DLP-Ereignisse hängen von empfangenen Logtypen und Feldern ab.",
			Columns:       []DatasetColumn{{"category", "Event category", "Ereigniskategorie", "string"}, {"action", "Recorded action", "Protokollierte Aktion", "string"}, {"count", "Observed records", "Beobachtete Datensätze", "integer"}},
			RequiredData:  []string{"Configured Graylog access", "Device-attributed FortiGate security logs", "Mapped subtype and action fields"},
		},
		{
			ID: "vpn_events", Name: "Observed VPN events", NameDE: "Beobachtete VPN-Ereignisse", Status: RequiresGraylog, Source: "graylog",
			Description:   "VPN event counts require VPN event logs. Event counts alone do not establish uptime, concurrent sessions, or completed connection duration.",
			DescriptionDE: "VPN-Ereigniszahlen benötigen VPN-Logs. Ereigniszahlen allein belegen weder Verfügbarkeit noch gleichzeitige Sitzungen oder vollständige Verbindungsdauer.",
			Columns:       []DatasetColumn{{"action", "Recorded event", "Protokolliertes Ereignis", "string"}, {"count", "Observed records", "Beobachtete Datensätze", "integer"}},
			RequiredData:  []string{"Configured Graylog access", "Device-attributed VPN event logs"},
		},
	}
}

func capabilityDefinitions() []Capability {
	const admin = "https://docs.fortinet.com/document/fortianalyzer/8.0.0/administration-guide/"
	return []Capability{
		{ID: "configuration_reports", Name: "Configuration, forwarding, and account reports", NameDE: "Konfigurations-, Weiterleitungs- und Kundenberichte", Status: Available, Description: "Three report audiences built from one bounded, secret-free configuration assessment.", DescriptionDE: "Drei Zielgruppen auf Grundlage einer begrenzten Konfigurationsanalyse ohne Geheimnisse.", Datasets: []string{"source", "publications", "policy_traces", "technical_inventory", "findings"}, Requirements: []string{"Complete saved configuration backup"}},
		{ID: "profiles", Name: "Portable report profiles", NameDE: "Übertragbare Berichtsprofile", Status: Available, Description: "Sections, filters, layout, branding, language, safe macros, and fixed count charts.", DescriptionDE: "Abschnitte, Filter, Layout, Branding, Sprache, sichere Platzhalter und feste Zähldiagramme.", Datasets: []string{"configuration_counts"}, SourceURL: admin + "227385/reports-settings-tab"},
		{ID: "traffic_reports", Name: "Traffic and application reports", NameDE: "Verkehrs- und Anwendungsberichte", Status: RequiresGraylog, Description: "Uses available Graylog traffic observations; missing fields and bounded retrieval are reported explicitly.", DescriptionDE: "Nutzt verfügbare Graylog-Verkehrsbeobachtungen; fehlende Felder und begrenzter Abruf werden ausdrücklich ausgewiesen.", Requirements: []string{"Configured Graylog access", "Reliable per-firewall message attribution", "Traffic fields for the requested time window"}, Datasets: []string{"traffic"}, SourceURL: admin + "385104/report-guidance"},
		{ID: "security_reports", Name: "Security event reports", NameDE: "Sicherheitsereignisberichte", Status: RequiresGraylog, Description: "Reports received threat-control observations, not an assertion that undetected threats are absent.", DescriptionDE: "Berichtet empfangene Beobachtungen von Sicherheitskontrollen; bestätigt nicht die Abwesenheit unerkannter Bedrohungen.", Requirements: []string{"Graylog security event logs and mapped fields"}, Datasets: []string{"security_events"}, SourceURL: admin + "385104/report-guidance"},
		{ID: "vpn_activity", Name: "VPN activity reports", NameDE: "VPN-Aktivitätsberichte", Status: RequiresGraylog, Description: "Observed VPN event summaries depend on VPN logs, separately from configured tunnels.", DescriptionDE: "Zusammenfassungen beobachteter VPN-Ereignisse benötigen VPN-Logs, unabhängig von konfigurierten Tunneln.", Requirements: []string{"Graylog VPN event logs"}, Datasets: []string{"vpn_events"}},
		{ID: "sdwan_performance", Name: "SD-WAN performance and SLA", NameDE: "SD-WAN-Leistung und SLA", Status: RequiresIntegration, Description: "Configured probes and rules do not establish measured latency, loss, jitter, SLA compliance, or service availability.", DescriptionDE: "Konfigurierte Prüfungen und Regeln belegen keine gemessene Latenz, Verluste, Schwankungen, SLA-Erfüllung oder Verfügbarkeit.", Requirements: []string{"Mapped SD-WAN health measurements with timestamps and coverage"}},
		{ID: "system_performance", Name: "System performance and throughput billing", NameDE: "Systemleistung und Durchsatzabrechnung", Status: RequiresIntegration, Description: "Requires reliable time series and accounting semantics; raw event counts are insufficient for utilization or billing.", DescriptionDE: "Benötigt belastbare Zeitreihen und Abrechnungssemantik; reine Ereigniszahlen reichen für Auslastung oder Abrechnung nicht aus.", Requirements: []string{"Performance counters", "Interface capacity and observation intervals", "Accounting and deduplication rules"}},
		{ID: "endpoint_vulnerability", Name: "Endpoint vulnerability reports", NameDE: "Berichte zu Endpunktschwachstellen", Status: RequiresIntegration, Description: "Requires endpoint vulnerability observations and security metadata from endpoint-management integrations.", DescriptionDE: "Benötigt beobachtete Endpunktschwachstellen und Sicherheitsmetadaten aus Endpunktverwaltungsintegrationen.", Requirements: []string{"FortiClient EMS or equivalent endpoint data", "Vulnerability metadata"}, SourceURL: admin + "663430/using-the-template-endpoint-security-vulnerability-report"},
		{ID: "security_rating", Name: "Security rating and compliance reports", NameDE: "Sicherheitsbewertungen und Compliance-Berichte", Status: RequiresIntegration, Description: "Configuration checks are not a Fortinet security rating or a certification of an entire standard.", DescriptionDE: "Konfigurationsprüfungen sind weder eine Fortinet-Sicherheitsbewertung noch eine Zertifizierung eines vollständigen Standards.", Requirements: []string{"Authorized security-rating results", "Required Fortinet licenses or independent control evidence"}, SourceURL: admin + "201528/security-rating-update"},
		{ID: "fabric_incidents", Name: "Fabric and incident reports", NameDE: "Fabric- und Vorfallsberichte", Status: RequiresIntegration, Description: "Anomaly-login and deception incident reports require correlated incidents and the corresponding product logs or alert handlers.", DescriptionDE: "Berichte über Anmeldeanomalien und Täuschungsvorfälle benötigen korrelierte Vorfälle sowie passende Produktlogs oder Alarmregeln.", Requirements: []string{"Incident data", "FortiAuthenticator/FortiDeceptor or equivalent integrations"}, SourceURL: admin + "509997/using-the-template-fortideceptor-incident-report"},
		{ID: "shadow_ai", Name: "Shadow IT and AI usage reports", NameDE: "Berichte zu Schatten-IT und KI-Nutzung", Status: RequiresIntegration, Description: "Requires observed application usage and maintained application/risk classifications.", DescriptionDE: "Benötigt beobachtete Anwendungsnutzung und gepflegte Anwendungs- und Risikoklassifikationen.", Requirements: []string{"Application observations", "Application classifications and risk metadata"}, SourceURL: admin + "2854/list-of-report-templates"},
		{ID: "other_products", Name: "Reports for other Fortinet products", NameDE: "Berichte für weitere Fortinet-Produkte", Status: RequiresIntegration, Description: "Email, WAF, endpoint, sandbox, NAC, ADC, and other product analytics require their own sources.", DescriptionDE: "E-Mail-, WAF-, Endpunkt-, Sandbox-, NAC-, ADC- und weitere Produktanalysen benötigen eigene Quellen.", Requirements: []string{"Product-specific logs and normalized schemas"}, SourceURL: admin + "2854/list-of-report-templates"},
		{ID: "ai_reporting", Name: "AI-assisted investigations and reporting", NameDE: "KI-gestützte Untersuchungen und Berichte", Status: RequiresIntegration, Description: "An AI service is not enabled by report templates and requires a separate configured data and authorization boundary.", DescriptionDE: "Berichtsvorlagen aktivieren keinen KI-Dienst; erforderlich sind getrennte Daten- und Berechtigungsgrenzen.", Requirements: []string{"Configured AI service", "Authorized data access and service entitlement"}, SourceURL: admin + "541468/using-fortiai"},
		{ID: "custom_sql", Name: "Arbitrary SQL datasets", NameDE: "Beliebige SQL-Datensätze", Status: NotImplemented, Description: "Report profiles use allowlisted datasets; imported profiles cannot execute SQL.", DescriptionDE: "Berichtsprofile nutzen freigegebene Datensätze; importierte Profile können kein SQL ausführen.", Requirements: []string{"A separate, bounded analytics query service"}, SourceURL: admin + "495456/creating-datasets"},
		{ID: "distribution", Name: "Email and remote-server distribution", NameDE: "Verteilung per E-Mail und Remote-Server", Status: NotImplemented, Description: "Downloadable reports do not automatically configure recipients or remote uploads.", DescriptionDE: "Herunterladbare Berichte konfigurieren keine Empfänger oder Remote-Uploads automatisch.", Requirements: []string{"Explicit delivery destinations", "Configured transport and credentials"}, SourceURL: admin + "108255/creating-output-profiles"},
		{ID: "fleet_reports", Name: "Combined reports across devices", NameDE: "Zusammengefasste Berichte über mehrere Geräte", Status: NotImplemented, Description: "Current reports retain a single firewall source; combined reports require explicit fleet scope and per-source freshness.", DescriptionDE: "Aktuelle Berichte behalten eine einzelne Firewall-Quelle; zusammengefasste Berichte benötigen einen ausdrücklichen Geräteumfang und Quellenaktualität.", Requirements: []string{"Fleet selection and access scoping", "Per-firewall source provenance"}, SourceURL: admin + "227385/reports-settings-tab"},
	}
}
