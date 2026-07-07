package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

type auditFinding = models.AuditFinding

// auditRow is one firewall's audit result.
type auditRow struct {
	FwID      int
	FQDN      string
	Model     string
	Version   string
	Findings  []auditFinding
	HasConfig bool
}

// versionCount is one entry of the FortiOS version distribution.
type versionCount struct {
	Version string
	Count   int
}

type auditData struct {
	Base     BaseData
	Rows     []auditRow
	Versions []versionCount
	Critical int
	Warnings int
	Error    string
}

var (
	// FortiGate configs start with e.g. "#config-version=FGT60F-7.2.5-FW-build1517-..."
	reConfigVersion = regexp.MustCompile(`(?i)#config-version=([A-Za-z0-9]+)-([0-9]+\.[0-9]+\.[0-9]+)`)
	reAllowAccess   = regexp.MustCompile(`(?i)set allowaccess ([^\r\n]+)`)
)

// handleAudit renders the audit / compliance page: per-firewall FortiOS version
// and management-exposure findings parsed from the newest stored config.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refs, err := s.store.ListFirewallRefs(ctx)
	if err != nil {
		s.logger.Error("audit list firewalls failed", "err", err)
		s.render(w, "audit.html", auditData{Base: s.base(r, "Audit", "audit"), Error: "Failed to load firewalls."})
		return
	}

	rows := make([]auditRow, 0, len(refs))
	verCounts := map[string]int{}
	crit, warn := 0, 0
	for _, ref := range refs {
		plain, filename, ok := s.latestConfig(ref.ID)
		row := auditRow{FwID: ref.ID, FQDN: ref.FQDN, HasConfig: ok}
		if ok {
			row.Model, row.Version = parseFortiOSVersion(plain)

			// Load from database cache
			findings, err := s.store.GetAuditFindings(ctx, ref.ID)
			if err != nil || len(findings) == 0 || findings[0].BackupFilename != filename {
				// Cache is empty, stale, or error - run parser and save!
				findings = auditFindingsForBackup(ref.ID, filename, plain)
				if err := s.store.SaveAuditFindings(ctx, ref.ID, findings); err != nil {
					s.logger.Error("failed to cache audit findings", "fw_id", ref.ID, "err", err)
				}
			}

			row.Findings = findings

			key := row.Version
			if key == "" {
				key = "unknown"
			}
			verCounts[key]++
			for _, f := range row.Findings {
				switch f.Severity {
				case "critical":
					crit++
				case "warning":
					warn++
				}
			}
		} else {
			verCounts["no backup"]++
		}
		rows = append(rows, row)
	}

	versions := make([]versionCount, 0, len(verCounts))
	for v, c := range verCounts {
		versions = append(versions, versionCount{Version: v, Count: c})
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].Count != versions[j].Count {
			return versions[i].Count > versions[j].Count
		}
		return versions[i].Version < versions[j].Version
	})

	s.render(w, "audit.html", auditData{
		Base:     s.base(r, "Audit", "audit"),
		Rows:     rows,
		Versions: versions,
		Critical: crit,
		Warnings: warn,
	})
}

// latestConfig returns the decrypted newest .conf for a firewall, the config filename, or ok=false
// when the firewall has no readable backup.
func (s *Server) latestConfig(fwID int) (string, string, bool) {
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))
	entries, err := os.ReadDir(fwDir)
	if err != nil {
		return "", "", false
	}
	var latest string
	var latestMod time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if latest == "" || info.ModTime().After(latestMod) {
			latest = e.Name()
			latestMod = info.ModTime()
		}
	}
	if latest == "" {
		return "", "", false
	}
	raw, err := os.ReadFile(filepath.Join(fwDir, latest))
	if err != nil {
		return "", "", false
	}
	plain, err := s.cipher.Decrypt(raw)
	if err != nil {
		s.logger.Error("audit decrypt failed", "fw_id", fwID, "err", err)
		return "", "", false
	}
	return string(plain), latest, true
}

// parseFortiOSVersion extracts the model and firmware version from a config's
// "#config-version" header (empty strings when not present).
func parseFortiOSVersion(cfg string) (model, version string) {
	if m := reConfigVersion.FindStringSubmatch(cfg); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

func auditFindingsForBackup(fwID int, filename string, cfg string) []models.AuditFinding {
	findings := auditFindings(cfg)
	for i := range findings {
		findings[i].FwID = fwID
		findings[i].BackupFilename = filename
	}
	return findings
}

// auditFindings derives management-exposure and compliance findings from a config:
// telnet/plaintext-HTTP management, weak ciphers (DES/3DES), weak hashes (MD5),
// weak DH groups, missing admin 2FA, default accounts, and weak SSL/TLS protocols.
func auditFindings(cfg string) []models.AuditFinding {
	var out []models.AuditFinding
	var telnet, httpMgmt, pingMgmt bool
	exposedMgmt := 0
	for _, m := range reAllowAccess.FindAllStringSubmatch(cfg, -1) {
		hasMgmt := false
		for _, t := range strings.Fields(strings.ToLower(m[1])) {
			switch t {
			case "telnet":
				telnet, hasMgmt = true, true
			case "http":
				httpMgmt, hasMgmt = true, true
			case "ssh", "https":
				hasMgmt = true
			case "ping":
				pingMgmt = true
			}
		}
		if hasMgmt {
			exposedMgmt++
		}
	}

	if telnet {
		out = append(out, models.AuditFinding{
			Severity:    "critical",
			Text:        "Telnet-Management aktiviert (allowaccess telnet)",
			Remediation: "config system interface\n  edit <interface>\n  set allowaccess <access-without-telnet>\nnext\nend",
		})
	}
	if strings.Contains(strings.ToLower(cfg), "set admin-telnet enable") {
		out = append(out, models.AuditFinding{
			Severity:    "critical",
			Text:        "Admin-Telnet global aktiviert",
			Remediation: "config system global\n  set admin-telnet disable\nend",
		})
	}
	if httpMgmt {
		out = append(out, models.AuditFinding{
			Severity:    "warning",
			Text:        "Klartext-HTTP-Management aktiviert (allowaccess http)",
			Remediation: "config system interface\n  edit <interface>\n  set allowaccess <access-without-http>\nnext\nend",
		})
	}
	if pingMgmt {
		out = append(out, models.AuditFinding{
			Severity:    "info",
			Text:        "Ping auf Management-Interfaces erlaubt",
			Remediation: "config system interface\n  edit <interface>\n  set allowaccess <access-without-ping>\nnext\nend",
		})
	}
	if exposedMgmt > 0 {
		out = append(out, models.AuditFinding{
			Severity:    "info",
			Text:        fmt.Sprintf("%d Interface(s) mit Management-Zugriff exponiert", exposedMgmt),
			Remediation: "config system interface\n  edit <interface>\n  set allowaccess <restrict-to-ssh-https>\nnext\nend",
		})
	}

	// 1. Two-Factor Authentication (2FA) Audit for Administrators
	adminBlockRegex := regexp.MustCompile(`(?s)config system admin\s*(.*?)\s*end`)
	if match := adminBlockRegex.FindStringSubmatch(cfg); len(match) > 1 {
		adminBlock := match[1]
		editRegex := regexp.MustCompile(`(?s)edit\s+["']?([^"'\s]+)["']?\s*(.*?)\s*next`)
		edits := editRegex.FindAllStringSubmatch(adminBlock, -1)
		for _, edit := range edits {
			username := edit[1]
			userConfig := edit[2]

			// Check if two-factor authentication is configured
			if !strings.Contains(userConfig, "set two-factor") {
				out = append(out, models.AuditFinding{
					Severity:    "critical",
					Text:        fmt.Sprintf("Administrator '%s' hat keine Zwei-Faktor-Authentifizierung (2FA) aktiviert", username),
					Remediation: fmt.Sprintf("config system admin\n  edit %s\n  set two-factor email/sms/fortitoken\nnext\nend", username),
				})
			}

			// Check if default 'admin' account exists
			if username == "admin" {
				out = append(out, models.AuditFinding{
					Severity:    "warning",
					Text:        "Standard-Administrator-Account 'admin' existiert noch",
					Remediation: "config system admin\n  rename admin to <new_secure_username>\nend",
				})
			}
		}
	}

	// 2. Proposal audits & Cryptographic checks (DES, 3DES, MD5, DH-Groups, TLS)
	re3DES := regexp.MustCompile(`(?i)\b3des\b`)
	reDES := regexp.MustCompile(`(?i)\bdes\b`)
	reMD5 := regexp.MustCompile(`(?i)\bmd5\b`)

	var hasDES, has3DES, hasMD5, hasWeakDH, hasMinSSLWeak, hasPasswordPolicyDisabled bool

	lines := strings.Split(cfg, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		// proposal check
		if strings.HasPrefix(lower, "set proposal") {
			if reDES.MatchString(lower) {
				hasDES = true
			}
			if re3DES.MatchString(lower) {
				has3DES = true
			}
			if reMD5.MatchString(lower) {
				hasMD5 = true
			}
		}

		// weak Diffie-Hellman groups check (1, 2, 5)
		if strings.HasPrefix(lower, "set dhgrp") {
			parts := strings.Fields(lower)
			for _, part := range parts {
				if part == "1" || part == "2" || part == "5" {
					hasWeakDH = true
				}
			}
		}

		// outdated SSL/TLS minimum protocol
		if strings.HasPrefix(lower, "set ssl-min-proto-version") {
			if strings.Contains(lower, "ssl3") || strings.Contains(lower, "tls1-0") || strings.Contains(lower, "tls1-1") {
				hasMinSSLWeak = true
			}
		}
	}

	// Global password policy disabled check
	if strings.Contains(strings.ToLower(cfg), "config system password-policy") {
		if match := regexp.MustCompile(`(?s)config system password-policy\s*(.*?)\s*end`).FindStringSubmatch(cfg); len(match) > 1 {
			if strings.Contains(match[1], "set status disable") {
				hasPasswordPolicyDisabled = true
			}
		}
	}

	if hasDES {
		out = append(out, models.AuditFinding{
			Severity:    "critical",
			Text:        "Schwache IPsec-Verschlüsselung (DES) in Proposals aktiviert",
			Remediation: "config vpn ipsec phase1-interface\n  edit <tunnel>\n  set proposal aes128-sha256 aes256-sha256\nnext\nend",
		})
	}
	if has3DES {
		out = append(out, models.AuditFinding{
			Severity:    "critical",
			Text:        "Schwache IPsec-Verschlüsselung (3DES) in Proposals aktiviert",
			Remediation: "config vpn ipsec phase1-interface\n  edit <tunnel>\n  set proposal aes128-sha256 aes256-sha256\nnext\nend",
		})
	}
	if hasMD5 {
		out = append(out, models.AuditFinding{
			Severity:    "warning",
			Text:        "Schwache IPsec-Integrität (MD5) in Proposals aktiviert",
			Remediation: "config vpn ipsec phase1-interface\n  edit <tunnel>\n  set proposal aes128-sha256 aes256-sha256\nnext\nend",
		})
	}
	if hasWeakDH {
		out = append(out, models.AuditFinding{
			Severity:    "warning",
			Text:        "Schwache Diffie-Hellman-Gruppe (DH-Gruppe 1/2/5) aktiviert",
			Remediation: "config vpn ipsec phase1-interface\n  edit <tunnel>\n  set dhgrp 14 16\nnext\nend",
		})
	}
	if hasMinSSLWeak {
		out = append(out, models.AuditFinding{
			Severity:    "critical",
			Text:        "Veraltetes SSL/TLS-Protokoll als Minimum konfiguriert (SSLv3/TLS1.0/TLS1.1)",
			Remediation: "config system global\n  set ssl-min-proto-version tls1-2\nend",
		})
	}
	if hasPasswordPolicyDisabled {
		out = append(out, models.AuditFinding{
			Severity:    "warning",
			Text:        "Globale Passwort-Richtlinie (password-policy) ist deaktiviert",
			Remediation: "config system password-policy\n  set status enable\nend",
		})
	}

	if len(out) == 0 {
		out = append(out, models.AuditFinding{
			Severity:    "info",
			Text:        "Keine offensichtlichen Management-Findings",
			Remediation: "Keine Aktion erforderlich.",
		})
	}
	return out
}
