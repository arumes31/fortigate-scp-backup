package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	_ "modernc.org/sqlite"
)

type auditFinding = models.AuditFinding

// insightsTimeLayout is the wall-clock timestamp format used across the
// insights database (exemptions, topology shares, audit cache metadata).
const insightsTimeLayout = "2006-01-02 15:04:05"

// insightsDB opens the per-server SQLite insights database once and sets up
// the schemas. Held on the Server (not a package global) so tests and future
// multi-instance setups each get their own handle. A failed open is retried
// on the next call rather than latched for the process lifetime (e.g. the
// data directory appearing after startup).
func (s *Server) insightsDB() (*sql.DB, error) {
	s.insightsMu.Lock()
	defer s.insightsMu.Unlock()
	if s.insights != nil {
		return s.insights, nil
	}

	db, err := s.openInsightsDB()
	if err != nil {
		return nil, err
	}
	s.insights = db
	return db, nil
}

// openInsightsDB creates the data directory, opens the SQLite file and runs
// schema setup + migrations. Called under s.insightsMu.
func (s *Server) openInsightsDB() (*sql.DB, error) {
	// 0o700: the insights DB holds audit results derived from configs.
	if err := os.MkdirAll(s.cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(s.cfg.DataDir, "forti-insights.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	// Set pragmas
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, pragmaErr := db.Exec(pragma); pragmaErr != nil {
			_ = db.Close()
			return nil, pragmaErr
		}
	}

	// Create tables
	queries := []string{
		`CREATE TABLE IF NOT EXISTS custom_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			pattern TEXT,
			severity TEXT,
			remediation TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS exemptions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fw_id INTEGER,
			finding_text TEXT,
			reason TEXT,
			created_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS change_tickets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			backup_filename TEXT UNIQUE,
			ticket_id TEXT,
			details TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS compliance_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fw_id INTEGER,
			timestamp DATETIME,
			pci_score INTEGER,
			cis_score INTEGER,
			hipaa_score INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS audit_cache (
			fw_id INTEGER PRIMARY KEY,
			backup_filename TEXT NOT NULL,
			computed_at TEXT NOT NULL,
			results_json TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS topology_shares (
			token TEXT PRIMARY KEY,
			fw_id INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT
		)`,
	}
	for _, q := range queries {
		if _, execErr := db.Exec(q); execErr != nil {
			_ = db.Close()
			return nil, execErr
		}
	}
	// Migration: exemptions match on the stable finding key (check id +
	// object) instead of the exact finding text, which breaks whenever a
	// finding contains dynamic parts. Ignore the duplicate-column error on
	// re-runs.
	if _, err := db.Exec(`ALTER TABLE exemptions ADD COLUMN finding_key TEXT DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		_ = db.Close()
		return nil, err
	}
	// Backfill: map pre-i18n exemption rows (German finding texts, empty
	// finding_key) to stable keys so upgrades keep existing exemptions active.
	s.backfillExemptionKeys(db)
	return db, nil
}

// Pre-i18n finding texts (the German literals the checks emitted before the
// English-canonical rewrite) mapped to stable finding keys. Keys with the
// "check:" prefix exempt every instance of that check — the old findings were
// global while the new ones are per-object, so a broader match preserves the
// operator's intent.
var legacyExemptionTexts = map[string]string{
	"Telnet-Management aktiviert (allowaccess telnet)":                            "check:intf-telnet",
	"Admin-Telnet global aktiviert":                                               "global-admin-telnet",
	"Klartext-HTTP-Management aktiviert (allowaccess http)":                       "check:intf-http",
	"Ping auf Management-Interfaces erlaubt":                                      "check:intf-ping-wan",
	"Standard-Administrator-Account 'admin' existiert noch":                       "admin-default-account",
	"Schwache IPsec-Verschlüsselung (DES) in Proposals aktiviert":                 "vpn-weak-cipher",
	"Schwache IPsec-Verschlüsselung (3DES) in Proposals aktiviert":                "vpn-weak-cipher",
	"Schwache IPsec-Integrität (MD5) in Proposals aktiviert":                      "vpn-weak-hash",
	"Schwache Diffie-Hellman-Gruppe (DH-Gruppe 1/2/5) aktiviert":                  "vpn-weak-dhgrp",
	"Veraltetes SSL/TLS-Protokoll als Minimum konfiguriert (SSLv3/TLS1.0/TLS1.1)": "global-weak-tls",
	"Globale Passwort-Richtlinie (password-policy) ist deaktiviert":               "pwpolicy-disabled",
	"Fortinet Security Fabric (CSF) ist nicht konfiguriert":                       "fabric-csf",
}

var (
	reLegacyAdmin2FA = regexp.MustCompile(`^Administrator '(.+)' hat keine Zwei-Faktor`)
	reLegacyShadow   = regexp.MustCompile(`^Shadow-Rule ID (\d+): wird durch ID (\d+) blockiert`)
	reLegacyCVE      = regexp.MustCompile(`Sicherheitslücke (CVE-\d{4}-\d+)`)
	reLegacyExposed  = regexp.MustCompile(`Interface\(s\) mit Management-Zugriff exponiert`)
	reLegacyCustom   = regexp.MustCompile(`^Eigene Regel '(.+)' verletzt`)
)

// legacyExemptionKey maps one pre-i18n finding text to its stable key
// ("" when unknown). Custom-rule texts are resolved via the rules table.
func legacyExemptionKey(db *sql.DB, text string) string {
	if key, ok := legacyExemptionTexts[text]; ok {
		return key
	}
	if m := reLegacyAdmin2FA.FindStringSubmatch(text); m != nil {
		return "admin-no-2fa:" + m[1]
	}
	if m := reLegacyShadow.FindStringSubmatch(text); m != nil {
		return "shadow-rule:" + m[1] + "-" + m[2]
	}
	if m := reLegacyCVE.FindStringSubmatch(text); m != nil {
		return "cve:" + m[1]
	}
	if reLegacyExposed.MatchString(text) {
		return "mgmt-exposed"
	}
	if m := reLegacyCustom.FindStringSubmatch(text); m != nil {
		var id int64
		if err := db.QueryRow("SELECT id FROM custom_rules WHERE name = ?", m[1]).Scan(&id); err == nil {
			return "custom:" + strconv.FormatInt(id, 10)
		}
	}
	return ""
}

// backfillExemptionKeys assigns stable finding keys to exemption rows created
// before the key column existed. Idempotent: only rows with an empty key are
// touched, and unmapped texts stay empty (still visible in the UI).
func (s *Server) backfillExemptionKeys(db *sql.DB) {
	rows, err := db.Query("SELECT id, finding_text FROM exemptions WHERE COALESCE(finding_key, '') = ''")
	if err != nil {
		return
	}
	type pending struct {
		id  int64
		key string
	}
	var updates []pending
	for rows.Next() {
		var id int64
		var text string
		if scanErr := rows.Scan(&id, &text); scanErr != nil {
			continue
		}
		if key := legacyExemptionKey(db, text); key != "" {
			updates = append(updates, pending{id: id, key: key})
		}
	}
	_ = rows.Close()
	for _, u := range updates {
		if _, err := db.Exec("UPDATE exemptions SET finding_key = ? WHERE id = ?", u.key, u.id); err != nil {
			s.logger.Warn("exemption key backfill failed", "id", u.id, "err", err)
		}
	}
	if len(updates) > 0 {
		s.logger.Info("backfilled legacy exemption keys", "count", len(updates))
	}
}

type customRule struct {
	ID          int64
	Name        string
	Pattern     string
	Severity    string
	Remediation string
}

type exemption struct {
	ID          int64
	FwID        int
	FindingKey  string
	FindingText string
	Reason      string
	CreatedAt   time.Time
}

// auditData is the audit page *shell*: the firewall list plus the custom
// rules / exemptions panels. Per-firewall results are fetched asynchronously
// from /audit/results/{fwID}.
type auditData struct {
	Base        BaseData
	Firewalls   []models.FirewallRef
	Error       string
	CustomRules []customRule
	Exemptions  []exemption
}

// Model structures for parsed config elements
type Interface struct {
	Name        string   `json:"name"`
	IP          string   `json:"ip"`
	Mask        string   `json:"mask"`
	AllowAccess []string `json:"allowaccess"`
	VlanID      int      `json:"vlan_id"`
	Interface   string   `json:"interface"` // Parent interface
	Role        string   `json:"role"`
	Alias       string   `json:"alias"`
}

type StaticRoute struct {
	ID      string `json:"id"`
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Device  string `json:"device"`
}

type Policy struct {
	ID      int      `json:"id"`
	SrcIntf []string `json:"srcintf"`
	DstIntf []string `json:"dstintf"`
	SrcAddr []string `json:"srcaddr"`
	DstAddr []string `json:"dstaddr"`
	Service []string `json:"service"`
	Action  string   `json:"action"`
}

type SwitchPort struct {
	Name string `json:"name"`
	Vlan string `json:"vlan"`
}

type FortiSwitch struct {
	SwitchID string       `json:"switch_id"`
	Name     string       `json:"name"`
	Ports    []SwitchPort `json:"ports"`
}

var reConfigVersion = regexp.MustCompile(`(?i)#config-version=([A-Za-z0-9]+)-([0-9]+\.[0-9]+\.[0-9]+)`)

// handleAudit renders the audit page shell: firewall list, custom rules and
// exemptions. The expensive per-firewall audit results are loaded by the page
// itself via GET /audit/results/{fwID} (cached in the insights DB).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db, err := s.insightsDB()
	if err != nil {
		s.logger.Error("failed to load insights database", "err", err)
	}

	refs, err := s.store.ListFirewallRefs(ctx)
	if err != nil {
		s.logger.Error("audit list firewalls failed", "err", err)
		s.render(w, "audit.html", auditData{Base: s.base(r, "Audit", "audit"), Error: "Failed to load firewalls."})
		return
	}

	s.render(w, "audit.html", auditData{
		Base:        s.base(r, "Audit", "audit"),
		Firewalls:   refs,
		CustomRules: loadCustomRules(db),
		Exemptions:  loadExemptions(db),
	})
}

// loadCustomRules fetches the custom rule list (empty on any error).
func loadCustomRules(db *sql.DB) []customRule {
	if db == nil {
		return nil
	}
	rows, err := db.Query("SELECT id, name, pattern, severity, remediation FROM custom_rules")
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []customRule
	for rows.Next() {
		var cr customRule
		if scanErr := rows.Scan(&cr.ID, &cr.Name, &cr.Pattern, &cr.Severity, &cr.Remediation); scanErr == nil {
			out = append(out, cr)
		}
	}
	return out
}

// loadExemptions fetches all exemptions (empty on any error).
func loadExemptions(db *sql.DB) []exemption {
	return queryExemptions(db, "SELECT id, fw_id, COALESCE(finding_key, ''), finding_text, reason, created_at FROM exemptions")
}

// loadExemptionsFor fetches the exemptions of one firewall.
func loadExemptionsFor(db *sql.DB, fwID int) []exemption {
	return queryExemptions(db,
		"SELECT id, fw_id, COALESCE(finding_key, ''), finding_text, reason, created_at FROM exemptions WHERE fw_id = ?", fwID)
}

func queryExemptions(db *sql.DB, query string, args ...any) []exemption {
	if db == nil {
		return nil
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []exemption
	for rows.Next() {
		var ex exemption
		var caRaw string
		if scanErr := rows.Scan(&ex.ID, &ex.FwID, &ex.FindingKey, &ex.FindingText, &ex.Reason, &caRaw); scanErr == nil {
			if t, tErr := time.Parse(insightsTimeLayout, caRaw); tErr == nil {
				ex.CreatedAt = t
			} else {
				ex.CreatedAt = time.Now()
			}
			out = append(out, ex)
		}
	}
	return out
}

func (s *Server) handleAuditExemption(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := s.insightsDB()
	if err != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}

	action := r.FormValue("action")
	if action == "delete" {
		idStr := r.FormValue("id")
		id, _ := strconv.Atoi(idStr)
		_, _ = db.Exec("DELETE FROM exemptions WHERE id = ?", id)
	} else {
		fwIDStr := r.FormValue("fw_id")
		fwID, _ := strconv.Atoi(fwIDStr)
		findingKey := r.FormValue("finding_key")
		findingText := r.FormValue("finding_text")
		reason := r.FormValue("reason")
		createdAt := time.Now().Format(insightsTimeLayout)

		_, _ = db.Exec("INSERT INTO exemptions (fw_id, finding_key, finding_text, reason, created_at) VALUES (?, ?, ?, ?, ?)",
			fwID, findingKey, findingText, reason, createdAt)
	}

	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// handleAuditCustomRule handles POST requests to register / delete custom rule patterns
func (s *Server) handleAuditCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := s.insightsDB()
	if err != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}

	action := r.FormValue("action")
	if action == "delete" {
		idStr := r.FormValue("id")
		id, _ := strconv.Atoi(idStr)
		_, _ = db.Exec("DELETE FROM custom_rules WHERE id = ?", id)
	} else {
		name := r.FormValue("name")
		pattern := r.FormValue("pattern")
		severity := r.FormValue("severity")
		remediation := r.FormValue("remediation")

		_, _ = db.Exec("INSERT INTO custom_rules (name, pattern, severity, remediation) VALUES (?, ?, ?, ?)",
			name, pattern, severity, remediation)
	}

	// Custom rules feed into the cached raw findings: recompute on next read.
	_, _ = db.Exec("DELETE FROM audit_cache")

	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// handleAuditTicket handles POST requests to attach change tickets to config files
func (s *Server) handleAuditTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := s.insightsDB()
	if err != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}

	filename := r.FormValue("backup_filename")
	ticketID := r.FormValue("ticket_id")
	details := r.FormValue("details")

	_, _ = db.Exec(`INSERT INTO change_tickets (backup_filename, ticket_id, details)
		VALUES (?, ?, ?)
		ON CONFLICT(backup_filename) DO UPDATE SET ticket_id = excluded.ticket_id, details = excluded.details`,
		filename, ticketID, details)

	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// parseConfigData extracts structured details for topology mapping including switches and VLANs
func parseConfigData(cfg string) ([]Interface, []StaticRoute, []Policy, []FortiSwitch) {
	var interfaces []Interface
	var routes []StaticRoute
	var policies []Policy
	var switches []FortiSwitch

	lines := strings.Split(cfg, "\n")
	var currentSection string
	var currentInterface *Interface
	var currentRoute *StaticRoute
	var currentPolicy *Policy
	var currentSwitch *FortiSwitch
	var currentPort *SwitchPort
	var inPorts bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if trimmed == "" {
			continue
		}

		if trimmed == "config system interface" {
			currentSection = "interface"
			continue
		} else if trimmed == "config router static" {
			currentSection = "route"
			continue
		} else if trimmed == "config firewall policy" {
			currentSection = "policy"
			continue
		} else if trimmed == "config switch-controller managed-switch" {
			currentSection = "switch"
			continue
		} else if trimmed == "end" {
			if currentSection == "interface" && currentInterface != nil {
				interfaces = append(interfaces, *currentInterface)
				currentInterface = nil
			}
			if currentSection == "route" && currentRoute != nil {
				routes = append(routes, *currentRoute)
				currentRoute = nil
			}
			if currentSection == "policy" && currentPolicy != nil {
				policies = append(policies, *currentPolicy)
				currentPolicy = nil
			}
			if currentSection == "switch" {
				if inPorts {
					inPorts = false
					continue
				}
				if currentSwitch != nil {
					switches = append(switches, *currentSwitch)
					currentSwitch = nil
				}
			}
			currentSection = ""
			continue
		}

		switch currentSection {
		case "interface":
			if strings.HasPrefix(lower, "edit ") {
				if currentInterface != nil {
					interfaces = append(interfaces, *currentInterface)
				}
				name := strings.Trim(trimmed[5:], `"`+"'")
				currentInterface = &Interface{Name: name}
			} else if strings.HasPrefix(lower, "next") {
				if currentInterface != nil {
					interfaces = append(interfaces, *currentInterface)
					currentInterface = nil
				}
			} else if currentInterface != nil {
				if strings.HasPrefix(lower, "set ip ") {
					parts := strings.Fields(trimmed[7:])
					if len(parts) >= 1 {
						currentInterface.IP = parts[0]
					}
					if len(parts) >= 2 {
						currentInterface.Mask = parts[1]
					}
				} else if strings.HasPrefix(lower, "set allowaccess ") {
					currentInterface.AllowAccess = strings.Fields(trimmed[16:])
				} else if strings.HasPrefix(lower, "set vlanid ") {
					vlanID, _ := strconv.Atoi(strings.TrimSpace(trimmed[11:]))
					currentInterface.VlanID = vlanID
				} else if strings.HasPrefix(lower, "set interface ") {
					currentInterface.Interface = strings.Trim(trimmed[14:], `"`+"'")
				} else if strings.HasPrefix(lower, "set role ") {
					currentInterface.Role = strings.ToLower(strings.Trim(trimmed[9:], `"`+"'"))
				} else if strings.HasPrefix(lower, "set alias ") {
					currentInterface.Alias = strings.Trim(trimmed[10:], `"`+"'")
				}
			}

		case "route":
			if strings.HasPrefix(lower, "edit ") {
				if currentRoute != nil {
					routes = append(routes, *currentRoute)
				}
				id := strings.Trim(trimmed[5:], `"`+"'")
				currentRoute = &StaticRoute{ID: id}
			} else if strings.HasPrefix(lower, "next") {
				if currentRoute != nil {
					routes = append(routes, *currentRoute)
					currentRoute = nil
				}
			} else if currentRoute != nil {
				if strings.HasPrefix(lower, "set dst ") {
					currentRoute.Dst = trimmed[8:]
				} else if strings.HasPrefix(lower, "set gateway ") {
					currentRoute.Gateway = trimmed[12:]
				} else if strings.HasPrefix(lower, "set device ") {
					currentRoute.Device = strings.Trim(trimmed[11:], `"`+"'")
				}
			}

		case "policy":
			if strings.HasPrefix(lower, "edit ") {
				if currentPolicy != nil {
					policies = append(policies, *currentPolicy)
				}
				idStr := strings.Trim(trimmed[5:], `"`+"'")
				id, _ := strconv.Atoi(idStr)
				currentPolicy = &Policy{ID: id}
			} else if strings.HasPrefix(lower, "next") {
				if currentPolicy != nil {
					policies = append(policies, *currentPolicy)
					currentPolicy = nil
				}
			} else if currentPolicy != nil {
				if strings.HasPrefix(lower, "set srcintf ") {
					fields := strings.Fields(trimmed[12:])
					for _, f := range fields {
						currentPolicy.SrcIntf = append(currentPolicy.SrcIntf, strings.Trim(f, `"`+"'"))
					}
				} else if strings.HasPrefix(lower, "set dstintf ") {
					fields := strings.Fields(trimmed[12:])
					for _, f := range fields {
						currentPolicy.DstIntf = append(currentPolicy.DstIntf, strings.Trim(f, `"`+"'"))
					}
				} else if strings.HasPrefix(lower, "set srcaddr ") {
					fields := strings.Fields(trimmed[12:])
					for _, f := range fields {
						currentPolicy.SrcAddr = append(currentPolicy.SrcAddr, strings.Trim(f, `"`+"'"))
					}
				} else if strings.HasPrefix(lower, "set dstaddr ") {
					fields := strings.Fields(trimmed[12:])
					for _, f := range fields {
						currentPolicy.DstAddr = append(currentPolicy.DstAddr, strings.Trim(f, `"`+"'"))
					}
				} else if strings.HasPrefix(lower, "set service ") {
					fields := strings.Fields(trimmed[12:])
					for _, f := range fields {
						currentPolicy.Service = append(currentPolicy.Service, strings.Trim(f, `"`+"'"))
					}
				} else if strings.HasPrefix(lower, "set action ") {
					currentPolicy.Action = strings.TrimSpace(trimmed[11:])
				}
			}

		case "switch":
			if strings.HasPrefix(lower, "config ports") {
				inPorts = true
				continue
			}

			if inPorts {
				if strings.HasPrefix(lower, "edit ") {
					if currentPort != nil && currentSwitch != nil {
						currentSwitch.Ports = append(currentSwitch.Ports, *currentPort)
					}
					name := strings.Trim(trimmed[5:], `"`+"'")
					currentPort = &SwitchPort{Name: name}
				} else if strings.HasPrefix(lower, "next") {
					if currentPort != nil && currentSwitch != nil {
						currentSwitch.Ports = append(currentSwitch.Ports, *currentPort)
						currentPort = nil
					}
				} else if currentPort != nil {
					if strings.HasPrefix(lower, "set vlan ") {
						currentPort.Vlan = strings.Trim(trimmed[9:], `"`+"'")
					}
				}
			} else {
				if strings.HasPrefix(lower, "edit ") {
					if currentSwitch != nil {
						switches = append(switches, *currentSwitch)
					}
					id := strings.Trim(trimmed[5:], `"`+"'")
					currentSwitch = &FortiSwitch{SwitchID: id}
				} else if strings.HasPrefix(lower, "next") {
					if currentSwitch != nil {
						switches = append(switches, *currentSwitch)
						currentSwitch = nil
					}
				} else if currentSwitch != nil {
					if strings.HasPrefix(lower, "set name ") {
						currentSwitch.Name = strings.Trim(trimmed[9:], `"`+"'")
					}
				}
			}
		}
	}

	return interfaces, routes, policies, switches
}

// findShadowRules implements Category 1 Feature 1. Policy attributes are
// precomputed into lowercase hash sets so the O(n²) pair loop pays O(sub)
// lookups per dimension instead of nested linear case-insensitive scans
// (relevant for rulebases with thousands of policies).
func findShadowRules(policies []Policy) []models.AuditFinding {
	var findings []models.AuditFinding

	lowerSet := func(vals []string) map[string]bool {
		m := make(map[string]bool, len(vals))
		for _, v := range vals {
			m[strings.ToLower(v)] = true
		}
		return m
	}
	type polSets struct {
		srcIntf, dstIntf, srcAddr, dstAddr, service map[string]bool
	}
	sets := make([]polSets, len(policies))
	for i, p := range policies {
		sets[i] = polSets{
			srcIntf: lowerSet(p.SrcIntf), dstIntf: lowerSet(p.DstIntf),
			srcAddr: lowerSet(p.SrcAddr), dstAddr: lowerSet(p.DstAddr),
			service: lowerSet(p.Service),
		}
	}

	covers := func(super map[string]bool, sub []string, wildcard string) bool {
		if super[wildcard] {
			return true
		}
		for _, s := range sub {
			if !super[strings.ToLower(s)] {
				return false
			}
		}
		return true
	}

	supersedes := func(s1 polSets, p2 Policy) bool {
		return covers(s1.srcIntf, p2.SrcIntf, "any") &&
			covers(s1.dstIntf, p2.DstIntf, "any") &&
			covers(s1.srcAddr, p2.SrcAddr, "all") &&
			covers(s1.dstAddr, p2.DstAddr, "all") &&
			covers(s1.service, p2.Service, "all")
	}

	for i := 1; i < len(policies); i++ {
		p2 := policies[i]
		for j := 0; j < i; j++ {
			p1 := policies[j]
			if supersedes(sets[j], p2) {
				findings = append(findings, models.AuditFinding{
					CheckID:     "shadow-rule",
					Key:         fmt.Sprintf("shadow-rule:%d-%d", p2.ID, p1.ID),
					Severity:    "warning",
					Text:        fmt.Sprintf("Shadow rule ID %d: blocked by ID %d", p2.ID, p1.ID),
					TextDE:      fmt.Sprintf("Shadow-Rule ID %d: wird durch ID %d blockiert", p2.ID, p1.ID),
					Remediation: fmt.Sprintf("Move the more specific policy ID %d before ID %d, or remove the redundant policy.", p2.ID, p1.ID),
				})
				break
			}
		}
	}
	return findings
}

// latestConfigFilename returns the newest backup filename for a firewall
// without reading or decrypting it (cheap cache-key lookup).
func (s *Server) latestConfigFilename(fwID int) (string, bool) {
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))
	entries, err := os.ReadDir(fwDir)
	if err != nil {
		return "", false
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
	return latest, latest != ""
}

// readConfig reads and decrypts one backup file of a firewall. The filename
// comes from latestConfigFilename so callers scan the directory only once.
func (s *Server) readConfig(fwID int, filename string) (string, bool) {
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))
	raw, err := os.ReadFile(filepath.Join(fwDir, filename))
	if err != nil {
		return "", false
	}
	plain, err := s.cipher.Decrypt(raw)
	if err != nil {
		s.logger.Error("audit decrypt failed", "fw_id", fwID, "err", err)
		return "", false
	}
	return string(plain), true
}

func parseFortiOSVersion(cfg string) (model, version string) {
	if m := reConfigVersion.FindStringSubmatch(cfg); m != nil {
		return m[1], m[2]
	}
	return "", ""
}
