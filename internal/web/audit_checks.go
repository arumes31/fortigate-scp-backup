package web

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// This file holds the curated audit check set. Sources: Fortinet "Hardening
// your FortiGate" guide, FortiOS best-practice documentation, Selectel and
// community hardening guides. Every check emits a stable CheckID and, where a
// single config statement is the trigger, the exact line plus ±3 lines of
// context (see audit_scan.go). Messages are English (canonical) with a German
// rendering in TextDE.

// ---------------------------------------------------------------------------
// Structural checks
// ---------------------------------------------------------------------------

var (
	re3DES = regexp.MustCompile(`(?i)\b3des\b`)
	reDES  = regexp.MustCompile(`(?i)\bdes\b`)
	reMD5  = regexp.MustCompile(`(?i)\bmd5\b`)
)

// wanDevices returns the interface names that face the internet: role wan or
// device of a default route.
func wanDevices(doc *cfgDoc, routes []StaticRoute) map[string]bool {
	wan := map[string]bool{}
	for _, b := range doc.blocksUnder("config system interface") {
		if role, _, ok := doc.settingDirect(b, "role"); ok && strings.EqualFold(role, "wan") {
			wan[b.Name] = true
		}
	}
	for _, r := range routes {
		if r.Device == "" {
			continue
		}
		if r.Dst == "" || strings.HasPrefix(r.Dst, "0.0.0.0") {
			wan[r.Device] = true
		}
	}
	return wan
}

// checkInterfaces audits management access per interface.
func checkInterfaces(doc *cfgDoc, routes []StaticRoute) []auditFinding {
	var out []auditFinding
	wan := wanDevices(doc, routes)
	exposedMgmt := 0

	for _, b := range doc.blocksUnder("config system interface") {
		val, idx, ok := doc.settingDirect(b, "allowaccess")
		if !ok {
			continue
		}
		access := strings.Fields(strings.ToLower(val))
		has := func(t string) bool {
			for _, a := range access {
				if a == t {
					return true
				}
			}
			return false
		}
		mgmt := has("https") || has("ssh") || has("http") || has("telnet") || has("snmp")
		if mgmt {
			exposedMgmt++
		}

		if has("telnet") {
			out = append(out, doc.findingAt("intf-telnet", "intf-telnet:"+b.Name, "critical",
				fmt.Sprintf("Telnet management enabled on interface '%s' (unencrypted)", b.Name),
				fmt.Sprintf("Telnet-Management auf Interface '%s' aktiviert (unverschlüsselt)", b.Name),
				fmt.Sprintf("config system interface\n  edit %s\n  set allowaccess <access-without-telnet>\nnext\nend", b.Name),
				idx, b))
		}
		if has("http") {
			out = append(out, doc.findingAt("intf-http", "intf-http:"+b.Name, "warning",
				fmt.Sprintf("Plaintext HTTP management enabled on interface '%s'", b.Name),
				fmt.Sprintf("Klartext-HTTP-Management auf Interface '%s' aktiviert", b.Name),
				fmt.Sprintf("config system interface\n  edit %s\n  set allowaccess <access-without-http>\nnext\nend", b.Name),
				idx, b))
		}
		if wan[b.Name] && mgmt {
			out = append(out, doc.findingAt("intf-wan-mgmt", "intf-wan-mgmt:"+b.Name, "critical",
				fmt.Sprintf("Management access allowed on WAN interface '%s' — attack surface from the internet", b.Name),
				fmt.Sprintf("Management-Zugriff auf WAN-Interface '%s' erlaubt — Angriffsfläche aus dem Internet", b.Name),
				fmt.Sprintf("config system interface\n  edit %s\n  unset allowaccess\nnext\nend\n"+
					"# Manage only via a dedicated MGMT interface or with trusthost restrictions.", b.Name),
				idx, b))
		}
		if wan[b.Name] && has("ping") {
			out = append(out, doc.findingAt("intf-ping-wan", "intf-ping-wan:"+b.Name, "info",
				fmt.Sprintf("Ping allowed on WAN interface '%s' (eases reconnaissance)", b.Name),
				fmt.Sprintf("Ping auf WAN-Interface '%s' erlaubt (erleichtert Reconnaissance)", b.Name),
				fmt.Sprintf("config system interface\n  edit %s\n  set allowaccess <access-without-ping>\nnext\nend", b.Name),
				idx, b))
		}
	}

	if exposedMgmt > 0 {
		out = append(out, auditFinding{
			CheckID: "mgmt-exposed", Key: "mgmt-exposed", Severity: "info",
			Text:        fmt.Sprintf("%d interface(s) expose management access (HTTPS/SSH/HTTP/Telnet/SNMP)", exposedMgmt),
			TextDE:      fmt.Sprintf("%d Interface(s) mit Management-Zugriff (HTTPS/SSH/HTTP/Telnet/SNMP)", exposedMgmt),
			Remediation: "Restrict management access to a dedicated interface and set trusthost per administrator.",
		})
	}
	return out
}

// checkGlobal audits `config system global` hardening settings.
func checkGlobal(doc *cfgDoc) []auditFinding {
	var out []auditFinding
	g, ok := doc.block("config system global")
	if !ok {
		return nil
	}

	if val, idx, ok := doc.settingDirect(g, "admin-telnet"); ok && strings.EqualFold(val, "enable") {
		out = append(out, doc.findingAt("global-admin-telnet", "global-admin-telnet", "critical",
			"Admin Telnet globally enabled",
			"Admin-Telnet global aktiviert",
			"config system global\n  set admin-telnet disable\nend", idx, g))
	}
	if val, idx, ok := doc.settingDirect(g, "admin-ssh-v1"); ok && strings.EqualFold(val, "enable") {
		out = append(out, doc.findingAt("global-ssh-v1", "global-ssh-v1", "critical",
			"SSH protocol version 1 enabled (cryptographically broken)",
			"SSH-Protokoll Version 1 aktiviert (kryptografisch gebrochen)",
			"config system global\n  set admin-ssh-v1 disable\nend", idx, g))
	}
	if val, idx, ok := doc.settingDirect(g, "ssl-min-proto-version"); ok {
		lv := strings.ToLower(val)
		if lv == "sslv3" || lv == "ssl3" || lv == "tlsv1" || lv == "tls1-0" || lv == "tls1-1" || lv == "tlsv1-1" {
			out = append(out, doc.findingAt("global-weak-tls", "global-weak-tls", "critical",
				fmt.Sprintf("Obsolete SSL/TLS protocol configured as minimum (%s)", val),
				fmt.Sprintf("Veraltetes SSL/TLS-Protokoll als Minimum konfiguriert (%s)", val),
				"config system global\n  set ssl-min-proto-version TLSv1-2\nend", idx, g))
		}
	}
	if val, idx, ok := doc.settingDirect(g, "strong-crypto"); ok && strings.EqualFold(val, "disable") {
		out = append(out, doc.findingAt("global-strong-crypto", "global-strong-crypto", "critical",
			"strong-crypto is disabled — weak ciphers and hashes allowed system-wide",
			"strong-crypto ist deaktiviert — schwache Cipher und Hashes werden systemweit erlaubt",
			"config system global\n  set strong-crypto enable\nend", idx, g))
	}
	if val, idx, ok := doc.settingDirect(g, "ssl-static-key-ciphers"); ok && strings.EqualFold(val, "enable") {
		out = append(out, doc.findingAt("global-static-keys", "global-static-keys", "warning",
			"Static SSL ciphers (without forward secrecy) are allowed",
			"Statische SSL-Cipher (ohne Forward Secrecy) sind erlaubt",
			"config system global\n  set ssl-static-key-ciphers disable\nend", idx, g))
	}
	if val, idx, ok := doc.settingDirect(g, "admin-https-redirect"); ok && strings.EqualFold(val, "disable") {
		out = append(out, doc.findingAt("global-http-redirect", "global-http-redirect", "info",
			"HTTP→HTTPS redirect for administration is disabled",
			"HTTP→HTTPS-Redirect für die Verwaltung ist deaktiviert",
			"config system global\n  set admin-https-redirect enable\nend", idx, g))
	}
	if val, idx, ok := doc.settingDirect(g, "admin-sport"); !ok || val == "443" {
		line := g.Start
		if ok {
			line = idx
		}
		out = append(out, doc.findingAt("global-admin-sport-default", "global-admin-sport-default", "info",
			"HTTPS management port is the default 443 — port scans find the GUI immediately",
			"HTTPS-Verwaltungsport ist der Standard-Port 443 — Port-Scans finden das GUI sofort",
			"config system global\n  set admin-sport <non-standard-port, e.g. 9443>\nend", line, g))
	}
	if val, idx, ok := doc.settingDirect(g, "admintimeout"); ok {
		if n, err := strconv.Atoi(val); err == nil && n > 30 {
			out = append(out, doc.findingAt("global-admintimeout", "global-admintimeout", "warning",
				fmt.Sprintf("Admin idle timeout is very high (%d minutes) — unattended sessions stay open", n),
				fmt.Sprintf("Admin-Idle-Timeout ist sehr hoch (%d Minuten) — unbeaufsichtigte Sessions bleiben lange offen", n),
				"config system global\n  set admintimeout 10\nend", idx, g))
		}
	}
	if val, idx, ok := doc.settingDirect(g, "admin-maintainer"); ok && strings.EqualFold(val, "enable") {
		out = append(out, doc.findingAt("global-maintainer", "global-maintainer", "warning",
			"Maintainer account (console password recovery) is enabled",
			"Maintainer-Account (Passwort-Recovery über Konsole) ist aktiviert",
			"config system global\n  set admin-maintainer disable\nend", idx, g))
	}
	if val, idx, ok := doc.settingDirect(g, "rest-api-key-url-query"); ok && strings.EqualFold(val, "enable") {
		out = append(out, doc.findingAt("global-rest-api-query", "global-rest-api-query", "warning",
			"REST API keys may be passed as URL query — keys end up in logs and proxies",
			"REST-API-Keys dürfen als URL-Query übergeben werden — Keys landen in Logs und Proxies",
			"config system global\n  set rest-api-key-url-query disable\nend", idx, g))
	}
	if val, _, ok := doc.settingDirect(g, "pre-login-banner"); !ok || !strings.EqualFold(val, "enable") {
		out = append(out, auditFinding{
			CheckID: "global-pre-login-banner", Key: "global-pre-login-banner", Severity: "info",
			Text:        "No pre-login banner configured (legal warning before sign-in)",
			TextDE:      "Kein Pre-Login-Banner konfiguriert (rechtlicher Warnhinweis vor Anmeldung)",
			Remediation: "config system global\n  set pre-login-banner enable\nend",
		})
	}
	return out
}

// checkAdmins audits `config system admin`: 2FA, default account, trusted hosts.
func checkAdmins(doc *cfgDoc) []auditFinding {
	var out []auditFinding
	for _, b := range doc.blocksUnder("config system admin") {
		user := b.Name
		if _, _, ok := doc.findDirect(b, "set two-factor"); !ok {
			out = append(out, doc.findingAt("admin-no-2fa", "admin-no-2fa:"+user, "critical",
				fmt.Sprintf("Administrator '%s' has no two-factor authentication (2FA)", user),
				fmt.Sprintf("Administrator '%s' hat keine Zwei-Faktor-Authentifizierung (2FA) aktiviert", user),
				fmt.Sprintf("config system admin\n  edit %s\n  set two-factor fortitoken/email/sms\nnext\nend", user),
				b.Start, b))
		}
		if _, _, ok := doc.findDirect(b, "set trusthost"); !ok {
			out = append(out, doc.findingAt("admin-no-trusthost", "admin-no-trusthost:"+user, "warning",
				fmt.Sprintf("Administrator '%s' has no trusted hosts — login possible from any IP", user),
				fmt.Sprintf("Administrator '%s' hat keine Trusted Hosts — Login von jeder IP möglich", user),
				fmt.Sprintf("config system admin\n  edit %s\n  set trusthost1 <mgmt-net>/<mask>\nnext\nend", user),
				b.Start, b))
		}
		if user == "admin" {
			out = append(out, doc.findingAt("admin-default-account", "admin-default-account", "warning",
				"Default administrator account 'admin' still exists",
				"Standard-Administrator-Account 'admin' existiert noch",
				"Create a new admin with a different name, then:\nconfig system admin\n  delete admin\nend",
				b.Start, b))
		}
	}
	return out
}

// checkPasswordPolicy flags a disabled or missing password policy.
func checkPasswordPolicy(doc *cfgDoc) []auditFinding {
	remediation := "config system password-policy\n  set status enable\n  set minimum-length 12\n  set min-lower-case-letter 1\n  set min-upper-case-letter 1\n  set min-non-alphanumeric 1\n  set min-number 1\nend"
	b, ok := doc.block("config system password-policy")
	if !ok {
		return []auditFinding{{
			CheckID: "pwpolicy-disabled", Key: "pwpolicy-disabled", Severity: "warning",
			Text:        "No password policy configured (complexity/length not enforced)",
			TextDE:      "Keine Passwort-Richtlinie konfiguriert (Komplexität/Länge werden nicht erzwungen)",
			Remediation: remediation,
		}}
	}
	if val, idx, found := doc.settingDirect(b, "status"); found && strings.EqualFold(val, "disable") {
		return []auditFinding{doc.findingAt("pwpolicy-disabled", "pwpolicy-disabled", "warning",
			"Global password policy (password-policy) is disabled",
			"Globale Passwort-Richtlinie (password-policy) ist deaktiviert",
			remediation, idx, b)}
	}
	return nil
}

// checkVPNCrypto audits IPsec proposals and DH groups line by line.
func checkVPNCrypto(doc *cfgDoc) []auditFinding {
	var out []auditFinding
	seen := map[string]bool{}
	for i, raw := range doc.lines {
		trimmed := strings.TrimSpace(raw)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "set proposal") {
			blk := enclosingBlock(doc, i)
			if (reDES.MatchString(lower) || re3DES.MatchString(lower)) && !seen["vpn-weak-cipher"] {
				seen["vpn-weak-cipher"] = true
				out = append(out, doc.findingAt("vpn-weak-cipher", "vpn-weak-cipher", "critical",
					"Weak IPsec encryption (DES/3DES) enabled in proposals",
					"Schwache IPsec-Verschlüsselung (DES/3DES) in Proposals aktiviert",
					"config vpn ipsec phase1-interface\n  edit <tunnel>\n  set proposal aes256-sha256 aes128gcm-prfsha256\nnext\nend", i, blk))
			}
			if reMD5.MatchString(lower) && !seen["vpn-weak-hash"] {
				seen["vpn-weak-hash"] = true
				out = append(out, doc.findingAt("vpn-weak-hash", "vpn-weak-hash", "warning",
					"Weak IPsec integrity (MD5) enabled in proposals",
					"Schwache IPsec-Integrität (MD5) in Proposals aktiviert",
					"config vpn ipsec phase1-interface\n  edit <tunnel>\n  set proposal aes256-sha256\nnext\nend", i, blk))
			}
		}

		if strings.HasPrefix(lower, "set dhgrp") && !seen["vpn-weak-dhgrp"] {
			for _, p := range strings.Fields(lower)[2:] {
				if p == "1" || p == "2" || p == "5" {
					seen["vpn-weak-dhgrp"] = true
					out = append(out, doc.findingAt("vpn-weak-dhgrp", "vpn-weak-dhgrp", "warning",
						"Weak Diffie-Hellman group (1/2/5) configured",
						"Schwache Diffie-Hellman-Gruppe (1/2/5) konfiguriert",
						"config vpn ipsec phase1-interface\n  edit <tunnel>\n  set dhgrp 14 19 20 21\nnext\nend", i, enclosingBlock(doc, i)))
					break
				}
			}
		}
	}
	return out
}

// enclosingBlock returns the innermost block containing the line (fallback:
// a pseudo block spanning the file so context rendering still works).
func enclosingBlock(doc *cfgDoc, lineIdx int) cfgBlock {
	best := cfgBlock{Start: 0, End: len(doc.lines) - 1, Depth: -1}
	for _, b := range doc.blocks {
		if b.Start <= lineIdx && lineIdx <= b.End && b.Depth > best.Depth {
			best = b
		}
	}
	return best
}

// checkSSLVPN audits `config vpn ssl settings`.
func checkSSLVPN(doc *cfgDoc) []auditFinding {
	b, ok := doc.block("config vpn ssl settings")
	if !ok {
		return nil
	}
	if val, _, found := doc.settingDirect(b, "status"); found && strings.EqualFold(val, "disable") {
		return nil
	}
	// Consider SSL-VPN in use only when it is bound to an interface.
	if _, _, bound := doc.settingDirect(b, "source-interface"); !bound {
		return nil
	}

	var out []auditFinding
	if val, idx, found := doc.settingDirect(b, "port"); !found || val == "443" || val == "10443" {
		line := b.Start
		if found {
			line = idx
		}
		out = append(out, doc.findingAt("sslvpn-default-port", "sslvpn-default-port", "warning",
			"SSL-VPN runs on a default port (443/10443) — a favourite target of automated scans",
			"SSL-VPN läuft auf einem Standard-Port (443/10443) — bevorzugtes Ziel automatisierter Scans",
			"config vpn ssl settings\n  set port <non-standard-port>\nend\n# Better: replace SSL-VPN with IPsec/ZTNA (Fortinet recommendation).", line, b))
	}
	if _, _, found := doc.settingDirect(b, "source-address"); !found {
		out = append(out, doc.findingAt("sslvpn-no-source-address", "sslvpn-no-source-address", "info",
			"SSL-VPN without source address restriction (source-address) — reachable worldwide",
			"SSL-VPN ohne Beschränkung der Quelladressen (source-address) — weltweit erreichbar",
			"config vpn ssl settings\n  set source-address <allowed-addresses>\nend\n# Also consider geo-blocking via local-in policy.", b.Start, b))
	}
	if val, idx, found := doc.settingDirect(b, "ssl-min-proto-ver"); found {
		lv := strings.ToLower(val)
		if lv == "tls1-0" || lv == "tls1-1" {
			out = append(out, doc.findingAt("sslvpn-weak-tls", "sslvpn-weak-tls", "critical",
				fmt.Sprintf("SSL-VPN accepts obsolete TLS (%s)", val),
				fmt.Sprintf("SSL-VPN akzeptiert veraltetes TLS (%s)", val),
				"config vpn ssl settings\n  set ssl-min-proto-ver tls1-2\nend", idx, b))
		}
	}
	return out
}

// checkSNMP flags default communities and v1/v2c usage.
func checkSNMP(doc *cfgDoc) []auditFinding {
	var out []auditFinding
	communities := doc.blocksUnder("config system snmp community")
	for _, b := range communities {
		if val, idx, ok := doc.settingDirect(b, "name"); ok {
			lv := strings.ToLower(val)
			if lv == "public" || lv == "private" {
				out = append(out, doc.findingAt("snmp-default-community", "snmp-default-community:"+val, "critical",
					fmt.Sprintf("SNMP community with default name '%s' configured", val),
					fmt.Sprintf("SNMP-Community mit Standard-Namen '%s' konfiguriert", val),
					"config system snmp community\n  edit <id>\n  set name <random-community-string>\nnext\nend\n# Better: move to SNMPv3 with authentication and encryption.", idx, b))
			}
		}
	}
	if len(communities) > 0 {
		b := communities[0]
		out = append(out, doc.findingAt("snmp-v1v2c", "snmp-v1v2c", "info",
			"SNMP v1/v2c in use (community strings travel unencrypted)",
			"SNMP v1/v2c in Verwendung (Community-Strings werden unverschlüsselt übertragen)",
			"config system snmp user\n  edit <user>\n  set security-level auth-priv\n  set auth-proto sha256\n  set priv-proto aes256\nnext\nend", b.Start, b))
	}
	return out
}

// checkAutoInstall flags enabled USB auto-install.
func checkAutoInstall(doc *cfgDoc) []auditFinding {
	b, ok := doc.block("config system auto-install")
	if !ok {
		return nil
	}
	var out []auditFinding
	for _, name := range []string{"auto-install-config", "auto-install-image"} {
		if val, idx, found := doc.settingDirect(b, name); found && strings.EqualFold(val, "enable") {
			out = append(out, doc.findingAt("auto-install-usb", "auto-install-usb:"+name, "warning",
				fmt.Sprintf("USB auto-install is enabled (%s) — physical access suffices to replace config/firmware", name),
				fmt.Sprintf("USB-Auto-Install ist aktiviert (%s) — physischer Zugriff genügt, um Konfiguration/Firmware zu ersetzen", name),
				"config system auto-install\n  set auto-install-config disable\n  set auto-install-image disable\nend", idx, b))
		}
	}
	return out
}

// checkNTP flags explicitly disabled time synchronisation.
func checkNTP(doc *cfgDoc) []auditFinding {
	b, ok := doc.block("config system ntp")
	if !ok {
		return nil
	}
	if val, idx, found := doc.settingDirect(b, "ntpsync"); found && strings.EqualFold(val, "disable") {
		return []auditFinding{doc.findingAt("ntp-disabled", "ntp-disabled", "info",
			"NTP time synchronisation is disabled — log timestamps and certificate validation unreliable",
			"NTP-Zeitsynchronisation ist deaktiviert — Log-Zeitstempel und Zertifikatsprüfung unzuverlässig",
			"config system ntp\n  set ntpsync enable\n  set type fortiguard\nend", idx, b)}
	}
	return nil
}

// checkRemoteLogging warns when neither FortiAnalyzer nor syslog forwarding
// is enabled.
func checkRemoteLogging(doc *cfgDoc) []auditFinding {
	enabled := func(path string) bool {
		b, ok := doc.block(path)
		if !ok {
			return false
		}
		val, _, found := doc.settingDirect(b, "status")
		return found && strings.EqualFold(val, "enable")
	}
	if enabled("config log fortianalyzer setting") || enabled("config log fortianalyzer-cloud setting") ||
		enabled("config log syslogd setting") || enabled("config log syslogd2 setting") {
		return nil
	}
	return []auditFinding{{
		CheckID: "log-no-remote", Key: "log-no-remote", Severity: "warning",
		Text:        "No remote log forwarding active (FortiAnalyzer/syslog) — logs can be tampered with after a compromise",
		TextDE:      "Keine Remote-Log-Weiterleitung aktiv (FortiAnalyzer/Syslog) — bei Kompromittierung sind Logs manipulierbar",
		Remediation: "config log syslogd setting\n  set status enable\n  set server <syslog-server>\nend\n# or\nconfig log fortianalyzer setting\n  set status enable\n  set server <faz-ip>\nend",
	}}
}

// checkPolicies flags any/any/ALL accept policies and aggregates no-log
// accept policies.
func checkPolicies(doc *cfgDoc) []auditFinding {
	var out []auditFinding
	var noLogIDs []string
	for _, b := range doc.blocksUnder("config firewall policy") {
		action, _, _ := doc.settingDirect(b, "action")
		if !strings.EqualFold(action, "accept") {
			continue
		}
		src, _, _ := doc.settingDirect(b, "srcaddr")
		dst, _, _ := doc.settingDirect(b, "dstaddr")
		svc, _, _ := doc.settingDirect(b, "service")
		if strings.EqualFold(src, "all") && strings.EqualFold(dst, "all") && strings.EqualFold(svc, "ALL") {
			out = append(out, doc.findingAt("policy-any-any", "policy-any-any:"+b.Name, "critical",
				fmt.Sprintf("Firewall policy %s allows EVERYTHING (srcaddr all, dstaddr all, service ALL)", b.Name),
				fmt.Sprintf("Firewall-Policy %s erlaubt ALLES (srcaddr all, dstaddr all, service ALL)", b.Name),
				fmt.Sprintf("config firewall policy\n  edit %s\n  set srcaddr <specific>\n  set dstaddr <specific>\n  set service <required-services>\nnext\nend", b.Name),
				b.Start, b))
		}
		if val, _, found := doc.settingDirect(b, "logtraffic"); found && strings.EqualFold(val, "disable") {
			noLogIDs = append(noLogIDs, b.Name)
		}
	}
	if len(noLogIDs) > 0 {
		out = append(out, auditFinding{
			CheckID: "policy-no-log", Key: "policy-no-log", Severity: "info",
			Text:        fmt.Sprintf("%d accept policy(s) without traffic logging: ID %s", len(noLogIDs), strings.Join(noLogIDs, ", ")),
			TextDE:      fmt.Sprintf("%d Accept-Policy(s) ohne Traffic-Logging: ID %s", len(noLogIDs), strings.Join(noLogIDs, ", ")),
			Remediation: "config firewall policy\n  edit <id>\n  set logtraffic all\nnext\nend",
		})
	}
	return out
}

// auditSecurityFabric reports when the Security Fabric is not configured.
func auditSecurityFabric(doc *cfgDoc) []auditFinding {
	if _, ok := doc.block("config system csf"); ok {
		return nil
	}
	return []auditFinding{{
		CheckID: "fabric-csf", Key: "fabric-csf", Severity: "info",
		Text:        "Fortinet Security Fabric (CSF) is not configured",
		TextDE:      "Fortinet Security Fabric (CSF) ist nicht konfiguriert",
		Remediation: "config system csf\n  set status enable\n  set upstream-ip <upstream_ip>\nend",
	}}
}

// runStructuralChecks runs every block-scanner based check.
func runStructuralChecks(doc *cfgDoc, routes []StaticRoute) []auditFinding {
	var out []auditFinding
	out = append(out, checkInterfaces(doc, routes)...)
	out = append(out, checkGlobal(doc)...)
	out = append(out, checkAdmins(doc)...)
	out = append(out, checkPasswordPolicy(doc)...)
	out = append(out, checkVPNCrypto(doc)...)
	out = append(out, checkSSLVPN(doc)...)
	out = append(out, checkSNMP(doc)...)
	out = append(out, checkAutoInstall(doc)...)
	out = append(out, checkNTP(doc)...)
	out = append(out, checkRemoteLogging(doc)...)
	out = append(out, checkPolicies(doc)...)
	out = append(out, auditSecurityFabric(doc)...)
	return out
}

// ---------------------------------------------------------------------------
// FortiOS lifecycle: upgrade paths and CVE exposure
// ---------------------------------------------------------------------------

// osTrain describes one FortiOS release train. Latest patch levels as of
// July 2026 (sources: Fortinet release notes / upgrade path tool).
type osTrain struct {
	train  string // "7.6"
	latest string // "7.6.7"
	noteEN string // lifecycle note, "" when fully supported
	noteDE string
}

var fortiOSTrains = []osTrain{
	{"6.0", "6.0.17", "End of Support", "End of Support"},
	{"6.2", "6.2.16", "End of Support", "End of Support"},
	{"6.4", "6.4.15", "End of Support", "End of Support"},
	{"7.0", "7.0.17", "End of Support since 09/2025", "End of Support seit 09/2025"},
	{"7.2", "7.2.13", "End of Support 09/2026", "End of Support 09/2026"},
	{"7.4", "7.4.12", "", ""},
	{"7.6", "7.6.7", "", ""},
	{"8.0", "8.0.1", "newest release train", "neuester Release-Train"},
}

// recommendedTrain: upgrades are recommended up to this train; anything
// beyond is offered as optional.
const recommendedTrain = "7.6"

// getUpgradePath returns the recommended upgrade steps for a FortiOS version
// in English and German, following the latest patch of each intermediate
// train. It never suggests a downgrade: a version already on the newest patch
// of the recommended train reports "up to date".
func getUpgradePath(version string) (en, de []string) {
	major, minor, patch, ok := splitVersion(version)
	if !ok {
		return []string{"No upgrade path information available"},
			[]string{"Keine Upgrade-Pfad-Informationen verfügbar"}
	}
	train := fmt.Sprintf("%d.%d", major, minor)

	idx := -1
	for i, t := range fortiOSTrains {
		if t.train == train {
			idx = i
			break
		}
	}
	if idx == -1 {
		return []string{fmt.Sprintf("Unknown release train %s — verify the upgrade path manually (docs.fortinet.com/upgrade-tool)", train)},
			[]string{fmt.Sprintf("Unbekannter Release-Train %s — Upgrade-Pfad manuell prüfen (docs.fortinet.com/upgrade-tool)", train)}
	}

	recIdx := 0
	for i, t := range fortiOSTrains {
		if t.train == recommendedTrain {
			recIdx = i
		}
	}

	cur := fortiOSTrains[idx]

	// Patch up within the current train first.
	if _, _, lp, lok := splitVersion(cur.latest); lok && patch < lp {
		en = append(en, fmt.Sprintf("%s (latest %s patch)", cur.latest, cur.train))
		de = append(de, fmt.Sprintf("%s (letzter %s-Patch)", cur.latest, cur.train))
	}
	// Then the latest patch of each following train up to the recommended one.
	for i := idx + 1; i <= recIdx && i < len(fortiOSTrains); i++ {
		t := fortiOSTrains[i]
		if t.noteEN != "" {
			en = append(en, fmt.Sprintf("%s (%s)", t.latest, t.noteEN))
			de = append(de, fmt.Sprintf("%s (%s)", t.latest, t.noteDE))
		} else {
			en = append(en, fmt.Sprintf("%s (latest %s patch)", t.latest, t.train))
			de = append(de, fmt.Sprintf("%s (letzter %s-Patch)", t.latest, t.train))
		}
	}

	if len(en) == 0 {
		en = append(en, fmt.Sprintf("✓ Up to date — %s is the newest patch of the recommended %s train", version, cur.train))
		de = append(de, fmt.Sprintf("✓ Aktuell — %s ist der neueste Patch des empfohlenen %s-Trains", version, cur.train))
	}
	// Newer trains beyond the recommendation are optional.
	for i := max(idx+1, recIdx+1); i < len(fortiOSTrains); i++ {
		t := fortiOSTrains[i]
		en = append(en, fmt.Sprintf("%s (optional: %s)", t.latest, t.noteEN))
		de = append(de, fmt.Sprintf("%s (optional: %s)", t.latest, t.noteDE))
	}
	return en, de
}

func splitVersion(v string) (major, minor, patch int, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, 0, false
	}
	if minor, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, false
	}
	if patch, err = strconv.Atoi(parts[2]); err != nil {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}

// cveRange marks a train as vulnerable below a fixed patch level.
type cveRange struct{ major, minor, fixedPatch int }

type cveDef struct {
	id          string
	summaryEN   string
	summaryDE   string
	severity    string
	remediation string
	ranges      []cveRange
}

// cveDefs lists known exploited/critical FortiOS CVEs (table-driven so new
// entries are one line). Fixed versions per Fortinet PSIRT advisories.
var cveDefs = []cveDef{
	{
		id:          "CVE-2022-40684",
		summaryEN:   "authentication bypass on the admin interface (actively exploited)",
		summaryDE:   "Authentication Bypass auf Admin-Interface (aktiv ausgenutzt)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.2.2 / 7.0.7. Disable HTTPS management on WAN immediately.",
		ranges:      []cveRange{{7, 2, 2}, {7, 0, 7}},
	},
	{
		id:          "CVE-2022-42475",
		summaryEN:   "SSL-VPN heap overflow RCE (actively exploited)",
		summaryDE:   "SSL-VPN Heap-Overflow RCE (aktiv ausgenutzt)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.2.3 / 7.0.9 / 6.4.11 / 6.2.12 or disable SSL-VPN.",
		ranges:      []cveRange{{7, 2, 3}, {7, 0, 9}, {6, 4, 11}, {6, 2, 12}},
	},
	{
		id:          "CVE-2023-27997",
		summaryEN:   "SSL-VPN heap buffer overflow (XORtigate, actively exploited)",
		summaryDE:   "SSL-VPN Heap Buffer Overflow (XORtigate, aktiv ausgenutzt)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.4.0 / 7.2.5 / 7.0.12 / 6.4.13 / 6.2.15 or disable SSL-VPN.",
		ranges:      []cveRange{{7, 2, 5}, {7, 0, 12}, {6, 4, 13}, {6, 2, 15}, {6, 0, 17}},
	},
	{
		id:          "CVE-2024-21762",
		summaryEN:   "SSL-VPN out-of-bounds write RCE (actively exploited)",
		summaryDE:   "SSL-VPN Out-of-bounds Write RCE (aktiv ausgenutzt)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.4.3 / 7.2.7 / 7.0.14 / 6.4.15 or disable SSL-VPN web mode.",
		ranges:      []cveRange{{7, 4, 3}, {7, 2, 7}, {7, 0, 14}, {6, 4, 15}},
	},
	{
		id:          "CVE-2024-23113",
		summaryEN:   "FGFM daemon format string RCE (actively exploited)",
		summaryDE:   "FGFM-Daemon Format-String RCE (aktiv ausgenutzt)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.4.3 / 7.2.7 / 7.0.14. Remove fgfm access from interfaces.",
		ranges:      []cveRange{{7, 4, 3}, {7, 2, 7}, {7, 0, 14}},
	},
	{
		id:          "CVE-2024-55591",
		summaryEN:   "authentication bypass via Node.js websocket (actively exploited)",
		summaryDE:   "Authentication Bypass über Node.js-Websocket (aktiv ausgenutzt)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.0.17. Disable HTTP/HTTPS management on WAN.",
		ranges:      []cveRange{{7, 0, 17}},
	},
	{
		id:          "CVE-2025-24472",
		summaryEN:   "authentication bypass (CSF proxy requests)",
		summaryDE:   "Authentication Bypass (CSF-Proxy-Requests)",
		severity:    "critical",
		remediation: "Upgrade to FortiOS >= 7.0.17.",
		ranges:      []cveRange{{7, 0, 17}},
	},
}

// getCVEs maps a FortiOS version to known-vulnerable CVE findings and flags
// end-of-support trains.
func getCVEs(version string) []models.AuditFinding {
	major, minor, patch, ok := splitVersion(version)
	if !ok {
		return nil
	}
	var findings []models.AuditFinding
	for _, def := range cveDefs {
		for _, r := range def.ranges {
			if major == r.major && minor == r.minor && patch < r.fixedPatch {
				findings = append(findings, models.AuditFinding{
					CheckID: "cve", Key: "cve:" + def.id,
					Severity:    def.severity,
					Text:        fmt.Sprintf("Critical vulnerability %s: %s", def.id, def.summaryEN),
					TextDE:      fmt.Sprintf("Kritische Sicherheitslücke %s: %s", def.id, def.summaryDE),
					Remediation: def.remediation,
				})
				break
			}
		}
	}

	train := fmt.Sprintf("%d.%d", major, minor)
	for _, t := range fortiOSTrains {
		if t.train == train && strings.HasPrefix(t.noteEN, "End of Support") && !strings.Contains(t.noteEN, "2026") {
			findings = append(findings, models.AuditFinding{
				CheckID: "eol-train", Key: "eol-train",
				Severity:    "warning",
				Text:        fmt.Sprintf("FortiOS %s is end-of-support — no more security patches", train),
				TextDE:      fmt.Sprintf("FortiOS %s ist End-of-Support — keine Sicherheits-Patches mehr", train),
				Remediation: "Upgrade to a supported release train (7.4/7.6), see upgrade path.",
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Compliance scoring
// ---------------------------------------------------------------------------

// Frameworks score by the fraction of relevant checks without findings.
var complianceChecks = map[string][]string{
	"pci": {"intf-telnet", "intf-http", "global-admin-telnet", "vpn-weak-cipher", "vpn-weak-hash",
		"pwpolicy-disabled", "admin-no-2fa", "global-weak-tls", "log-no-remote", "policy-any-any"},
	"cis": {"intf-telnet", "global-weak-tls", "intf-wan-mgmt", "admin-no-trusthost", "pwpolicy-disabled",
		"vpn-weak-dhgrp", "snmp-default-community", "global-admintimeout", "auto-install-usb", "global-maintainer"},
	"hipaa": {"intf-telnet", "intf-http", "pwpolicy-disabled", "admin-no-2fa", "vpn-weak-cipher",
		"log-no-remote", "global-weak-tls", "sslvpn-weak-tls"},
}

// calculateComplianceScores derives framework scores from the structured
// findings (by CheckID), replacing the old duplicate text matching.
func calculateComplianceScores(findings []models.AuditFinding) (pci, cis, hipaa int) {
	failed := map[string]bool{}
	for _, f := range findings {
		if f.CheckID != "" {
			failed[f.CheckID] = true
		}
	}
	score := func(ids []string) int {
		bad := 0
		for _, id := range ids {
			if failed[id] {
				bad++
			}
		}
		return ((len(ids) - bad) * 100) / len(ids)
	}
	return score(complianceChecks["pci"]), score(complianceChecks["cis"]), score(complianceChecks["hipaa"])
}

// sortFindings orders findings by severity (critical → warning → info), then
// by line number for stable display.
func sortFindings(fs []models.AuditFinding) {
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := rank[fs[i].Severity], rank[fs[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return fs[i].Line < fs[j].Line
	})
}
