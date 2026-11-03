package reportmodel

func SectionDefinitions() []Option {
	return []Option{
		{"interfaces", "Interfaces and zones", "Schnittstellen und Zonen"},
		{"routing", "Routing configuration", "Routing-Konfiguration"},
		{"sdwan", "SD-WAN configuration", "SD-WAN-Konfiguration"},
		{"dhcp_dns", "DHCP and DNS", "DHCP und DNS"},
		{"vpn", "VPN configuration", "VPN-Konfiguration"},
		{"ha", "High availability configuration", "Hochverfügbarkeitskonfiguration"},
		{"administrators", "Administrative access", "Administrationszugriff"},
		{"logging", "Logging configuration", "Logging-Konfiguration"},
		{"time", "Time synchronization", "Zeitsynchronisierung"},
		{"policies", "Firewall policies", "Firewall-Regeln"},
		{"local_in", "Local-in policies", "Local-in-Regeln"},
		{"inspection", "Inspection profile definitions", "Inspektionsprofile"},
	}
}

func ChartDefinitions() []Option {
	return []Option{
		{"priority", "Findings by priority", "Feststellungen nach Priorität"},
		{"type", "Configured publications by type", "Konfigurierte Veröffentlichungen nach Typ"},
		{"outcome", "Configured publication outcomes", "Ergebnisse der konfigurierten Veröffentlichungen"},
		{"geo", "Geographic restriction assessment", "Bewertung geografischer Einschränkungen"},
	}
}

func TypeDefinitions() []Option {
	return []Option{
		{"static_nat", "Static IPv4 mapping", "Statische IPv4-Zuordnung"},
		{"virtual_server", "Virtual server", "Virtueller Server"},
		{"fqdn", "FQDN mapping", "FQDN-Zuordnung"},
		{"access_proxy", "Access proxy", "Zugriffsproxy"},
		{"dns_translation", "DNS translation", "DNS-Übersetzung"},
		{"ipv6", "IPv6 mapping", "IPv6-Zuordnung"},
		{"nat46", "NAT46 mapping", "NAT46-Zuordnung"},
		{"nat64", "NAT64 mapping", "NAT64-Zuordnung"},
		{"other", "Other or unknown mapping", "Andere oder unbekannte Zuordnung"},
	}
}

func OutcomeDefinitions() []Option {
	return []Option{
		{"Configured permit", "Configured permit", "Konfigurierte Freigabe"},
		{"Configured deny", "Configured deny", "Konfigurierte Sperre"},
		{"Conditional", "Conditional", "Bedingt"},
		{"Indeterminate", "Indeterminate", "Unbestimmt"},
		{"No enabled policy reference", "No enabled policy reference", "Keine aktive Regelreferenz"},
		{"Disabled", "Disabled", "Deaktiviert"},
	}
}

func PriorityDefinitions() []Option {
	return []Option{
		{"High", "High", "Hoch"},
		{"Medium", "Medium", "Mittel"},
		{"Low", "Low", "Niedrig"},
		{"Informational", "Informational", "Informativ"},
	}
}

func GeoDefinitions() []Option {
	return []Option{
		{"Applicable", "Applicable to evaluated paths", "Auf bewertete Pfade anwendbar"},
		{"Partial", "Partial", "Teilweise"},
		{"Not applicable", "Not applicable", "Nicht anwendbar"},
		{"Not found", "No matching restriction found", "Keine passende Einschränkung gefunden"},
		{"Indeterminate", "Indeterminate", "Unbestimmt"},
	}
}
