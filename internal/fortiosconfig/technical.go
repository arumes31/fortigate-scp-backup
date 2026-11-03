package fortiosconfig

import (
	"fmt"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// Each technical section has an explicit allowlist. Raw blocks, comments,
// scripts, credential blobs, certificate bodies and private keys never enter
// the reporting model, even when their values contain newlines/CLI keywords.
type sectionSpec struct {
	name, title, titleDE string
	keys                 []string
	objects              bool
}

func technical(doc *document, findings []reportmodel.Finding) ([]reportmodel.Section, []reportmodel.Finding) {
	specs := []sectionSpec{
		{"system interface", "Interfaces", "Schnittstellen", []string{"vdom", "ip", "mode", "role", "interface", "vlanid", "status", "allowaccess", "mtu-override", "mtu"}, true},
		{"system zone", "Zones", "Zonen", []string{"interface", "intrazone"}, true},
		{"router static", "Static routes", "Statische Routen", []string{"dst", "gateway", "device", "distance", "priority", "status"}, true},
		{"router policy", "Policy routes", "Policy-Routen", []string{"input-device", "src", "dst", "protocol", "start-port", "end-port", "output-device", "gateway", "status"}, true},
		{"router bgp", "BGP configuration", "BGP-Konfiguration", []string{"as", "router-id", "graceful-restart", "ebgp-multipath", "ibgp-multipath"}, false},
		{"router ospf", "OSPF configuration", "OSPF-Konfiguration", []string{"router-id", "default-information-originate"}, false},
		{"system sdwan", "SD-WAN configuration", "SD-WAN-Konfiguration", []string{"status", "load-balance-mode"}, false},
		{"system dhcp server", "DHCP server configuration", "DHCP-Server-Konfiguration", []string{"interface", "status", "default-gateway", "netmask", "dns-service", "dns-server1", "dns-server2", "lease-time"}, true},
		{"system dns", "DNS configuration", "DNS-Konfiguration", []string{"primary", "secondary", "protocol", "server-hostname"}, false},
		{"vpn ipsec phase1-interface", "IPsec phase 1 definitions", "IPsec-Phase-1-Definitionen", []string{"interface", "type", "remote-gw", "ike-version", "proposal", "dhgrp", "nattraversal", "dpd", "status"}, true},
		{"vpn ipsec phase2-interface", "IPsec phase 2 definitions", "IPsec-Phase-2-Definitionen", []string{"phase1name", "proposal", "pfs", "dhgrp", "src-subnet", "dst-subnet", "auto-negotiate"}, true},
		{"vpn ssl settings", "SSL VPN configuration", "SSL-VPN-Konfiguration", []string{"status", "port", "source-interface", "source-address", "ssl-min-proto-ver", "servercert", "default-portal"}, false},
		{"system ha", "HA configuration", "HA-Konfiguration", []string{"mode", "group-name", "group-id", "hbdev", "session-pickup", "override", "priority", "monitor"}, false},
		{"system admin", "Administrative access", "Administrationszugriff", []string{"accprofile", "vdom", "remote-auth", "two-factor", "trusthost1", "trusthost2", "trusthost3", "trusthost4", "trusthost5", "trusthost6", "trusthost7", "trusthost8", "trusthost9", "trusthost10"}, true},
		{"system global", "Global administration settings", "Globale Administrationseinstellungen", []string{"hostname", "admin-port", "admin-sport", "admin-ssh-port", "admin-https-ssl-versions", "admintimeout", "timezone"}, false},
		{"log syslogd setting", "Syslog destination", "Syslog-Ziel", []string{"status", "server", "mode", "port", "facility", "source-ip", "enc-algorithm"}, false},
		{"log syslogd2 setting", "Additional syslog destination", "Weiteres Syslog-Ziel", []string{"status", "server", "mode", "port", "facility", "source-ip", "enc-algorithm"}, false},
		{"log fortianalyzer setting", "FortiAnalyzer destination", "FortiAnalyzer-Ziel", []string{"status", "server", "upload-option", "reliable", "enc-algorithm"}, false},
		{"system ntp", "Time synchronization", "Zeitsynchronisierung", []string{"ntpsync", "type", "syncinterval", "server-mode"}, false},
		{"firewall policy", "Firewall policies in configuration order", "Firewall-Regeln in Konfigurationsreihenfolge", []string{"name", "status", "srcintf", "dstintf", "srcaddr", "dstaddr", "action", "schedule", "service", "match-vip", "srcaddr-negate", "dstaddr-negate", "service-negate", "nat", "logtraffic", "utm-status", "inspection-mode", "ssl-ssh-profile", "ips-sensor", "av-profile", "webfilter-profile", "dnsfilter-profile", "application-list", "profile-group"}, true},
		{"firewall local-in-policy", "Local-in policies (FortiGate services)", "Local-in-Regeln (FortiGate-Dienste)", []string{"intf", "srcaddr", "dstaddr", "action", "service", "schedule", "status"}, true},
		{"ips sensor", "IPS profile definitions", "IPS-Profildefinitionen", []string{"block-malicious-url", "scan-botnet-connections"}, true},
		{"antivirus profile", "Antivirus profile definitions", "Antivirus-Profildefinitionen", []string{"feature-set"}, true},
		{"webfilter profile", "Web filter profile definitions", "Webfilter-Profildefinitionen", []string{"feature-set"}, true},
		{"firewall ssl-ssh-profile", "SSL/SSH inspection profile definitions", "SSL/SSH-Inspektionsprofildefinitionen", []string{"ssl-exemptions-log", "ssl-anomalies-log", "use-ssl-server"}, true},
	}
	sections := make([]reportmodel.Section, 0, len(specs))
	for _, spec := range specs {
		section := reportmodel.Section{Title: spec.title, TitleDE: spec.titleDE, Rows: []reportmodel.Row{}}
		nodes := doc.tables(spec.name)
		if spec.objects {
			nodes = doc.objects(spec.name)
		}
		for _, n := range nodes {
			var values []string
			for _, key := range spec.keys {
				if value, ok := n.values[key]; ok {
					values = append(values, key+"="+display(strings.Join(value, " ")))
				}
			}
			if len(values) == 0 {
				values = append(values, "Definition present; relevant settings are omitted/default or nested.")
			}
			label := "VDOM " + display(n.vdom())
			if n.kind == "edit" {
				label += " / " + display(n.name)
			}
			section.Rows = append(section.Rows, reportmodel.Row{Label: label, Value: strings.Join(values, "; "), Evidence: n.evidence()})
		}
		if len(section.Rows) > 0 {
			sections = append(sections, section)
		}
	}
	// Nested inventories are matched by their owning parent, avoiding accidental
	// interpretation of unrelated generic "members" or "service" tables.
	for _, table := range doc.tables("system sdwan") {
		section := reportmodel.Section{Title: "SD-WAN members and rules", TitleDE: "SD-WAN-Mitglieder und Regeln", Rows: []reportmodel.Row{}}
		for _, child := range table.children {
			if child.kind != "config" {
				continue
			}
			keys := map[string][]string{"members": {"interface", "gateway", "zone", "cost", "priority", "status"}, "service": {"name", "mode", "src", "dst", "priority-members", "health-check", "status"}, "health-check": {"server", "protocol", "members", "interval", "failtime", "recoverytime"}, "zone": {"service-sla-tie-break", "minimum-sla-meet-members"}}[child.name]
			if len(keys) == 0 {
				continue
			}
			for _, entry := range child.children {
				if entry.kind != "edit" {
					continue
				}
				var values []string
				for _, key := range keys {
					if value := entry.get(key); value != "" {
						values = append(values, key+"="+display(value))
					}
				}
				section.Rows = append(section.Rows, reportmodel.Row{Label: "VDOM " + display(table.vdom()) + " / " + display(child.name) + " / " + display(entry.name), Value: strings.Join(values, "; "), Evidence: entry.evidence()})
			}
		}
		if len(section.Rows) > 0 {
			sections = append(sections, section)
		}
	}
	for _, iface := range doc.objects("system interface") {
		if iface.get("role") != "wan" {
			continue
		}
		if contains(iface.values["allowaccess"], "https") || contains(iface.values["allowaccess"], "ssh") || contains(iface.values["allowaccess"], "http") || contains(iface.values["allowaccess"], "telnet") {
			findings = append(findings, reportmodel.Finding{ID: "management:" + iface.vdom() + ":" + iface.name, Priority: "Medium", Title: "Review administration on WAN-designated interfaces", TitleDE: "Administration auf WAN-Schnittstellen prüfen", Detail: "An interface configured with the WAN role enables an administrative service. Trusted hosts and local-in policies may further restrict it.", DetailDE: "Eine Schnittstelle mit WAN-Rolle erlaubt einen Administrationsdienst. Trusted Hosts und Local-in-Regeln können den Zugriff weiter einschränken.", Recommendation: "Validate the intended management path and its source restrictions.", RecommendationDE: "Vorgesehenen Administrationspfad und Quelleinschränkungen prüfen.", Evidence: iface.evidence()})
		}
	}
	for _, phase := range append(doc.objects("vpn ipsec phase1-interface"), doc.objects("vpn ipsec phase2-interface")...) {
		weak := false
		for _, proposal := range phase.values["proposal"] {
			if strings.Contains(proposal, "des-") || strings.Contains(proposal, "-md5") {
				weak = true
			}
		}
		for _, group := range phase.values["dhgrp"] {
			if group == "1" || group == "2" || group == "5" {
				weak = true
			}
		}
		if weak {
			findings = append(findings, reportmodel.Finding{ID: "vpn-crypto:" + phase.vdom() + ":" + phase.name, Priority: "Medium", Title: "Review legacy VPN cryptography", TitleDE: "Veraltete VPN-Kryptografie prüfen", Detail: "A VPN definition includes a legacy algorithm or Diffie-Hellman group.", DetailDE: "Eine VPN-Definition enthält veraltete Kryptografie oder eine ältere Diffie-Hellman-Gruppe.", Recommendation: "Review peer compatibility and agree a stronger cryptographic configuration before changing either endpoint.", RecommendationDE: "Kompatibilität der Gegenstelle prüfen und stärkere Kryptografie vor Änderungen beidseitig abstimmen.", Evidence: phase.evidence()})
		}
	}
	for _, ha := range doc.tables("system ha") {
		if ha.get("mode") == "a-p" || ha.get("mode") == "a-a" {
			findings = append(findings, reportmodel.Finding{ID: "resilience:" + ha.vdom(), Priority: "Informational", Title: "Validate the configured HA recovery procedure", TitleDE: "Konfiguriertes HA-Wiederherstellungsverfahren prüfen", Detail: "High availability is configured; this snapshot does not establish current member health or tested failover.", DetailDE: "Hochverfügbarkeit ist konfiguriert; die Sicherung belegt weder den aktuellen Zustand der Mitglieder noch einen getesteten Failover.", Recommendation: "Agree a recovery objective, validate the runbook, and schedule an authorized failover exercise.", RecommendationDE: "Wiederherstellungsziel abstimmen, Runbook prüfen und einen freigegebenen Failover-Test planen.", Evidence: ha.evidence()})
		}
	}
	for _, name := range []string{"log syslogd setting", "log syslogd2 setting", "log fortianalyzer setting"} {
		for _, logging := range doc.tables(name) {
			if logging.get("status") == "enable" {
				findings = append(findings, reportmodel.Finding{ID: fmt.Sprintf("logging:%s:%s", logging.vdom(), name), Priority: "Informational", Title: "Verify remote log delivery and retention", TitleDE: "Remote-Logübertragung und Aufbewahrung prüfen", Detail: "A remote logging destination is configured; successful ingestion and retention are not established by the backup.", DetailDE: "Ein Remote-Logging-Ziel ist konfiguriert; erfolgreiche Verarbeitung und Aufbewahrung sind durch die Sicherung nicht belegt.", Recommendation: "Confirm event delivery and the agreed retention period in the receiving system.", RecommendationDE: "Ereignisempfang und vereinbarte Aufbewahrungsdauer im Zielsystem prüfen.", Evidence: logging.evidence()})
			}
		}
	}
	return sections, findings
}
