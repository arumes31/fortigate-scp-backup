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

// insightsDB opens the per-server SQLite insights database once and sets up
// the schemas. Held on the Server (not a package global) so tests and future
// multi-instance setups each get their own handle.
func (s *Server) insightsDB() (*sql.DB, error) {
	s.insightsOnce.Do(func() {
		dbPath := filepath.Join(s.cfg.DataDir, "forti-insights.db")
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			s.insightsErr = err
			return
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
				s.insightsErr = pragmaErr
				return
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
				s.insightsErr = execErr
				return
			}
		}
		// Migration: exemptions match on the stable finding key (check id +
		// object) instead of the exact finding text, which breaks whenever a
		// finding contains dynamic parts. Ignore the duplicate-column error on
		// re-runs.
		if _, err := db.Exec(`ALTER TABLE exemptions ADD COLUMN finding_key TEXT DEFAULT ''`); err != nil &&
			!strings.Contains(err.Error(), "duplicate column") {
			_ = db.Close()
			s.insightsErr = err
			return
		}
		s.insights = db
	})
	return s.insights, s.insightsErr
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
	Status      string   `json:"status"` // "" or "up"/"down" when explicitly set
	Alias       string   `json:"alias"`
	Type        string   `json:"type"`
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
	if db == nil {
		return nil
	}
	rows, err := db.Query("SELECT id, fw_id, COALESCE(finding_key, ''), finding_text, reason, created_at FROM exemptions")
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []exemption
	for rows.Next() {
		var ex exemption
		var caRaw string
		if scanErr := rows.Scan(&ex.ID, &ex.FwID, &ex.FindingKey, &ex.FindingText, &ex.Reason, &caRaw); scanErr == nil {
			if t, tErr := time.Parse("2006-01-02 15:04:05", caRaw); tErr == nil {
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
		createdAt := time.Now().Format("2006-01-02 15:04:05")

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
				} else if strings.HasPrefix(lower, "set status ") {
					currentInterface.Status = strings.ToLower(strings.TrimSpace(trimmed[11:]))
				} else if strings.HasPrefix(lower, "set alias ") {
					currentInterface.Alias = strings.Trim(trimmed[10:], `"`+"'")
				} else if strings.HasPrefix(lower, "set type ") {
					currentInterface.Type = strings.ToLower(strings.TrimSpace(trimmed[9:]))
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

// findShadowRules implements Category 1 Feature 1
func findShadowRules(policies []Policy) []models.AuditFinding {
	var findings []models.AuditFinding

	contains := func(slice []string, val string) bool {
		for _, s := range slice {
			if strings.EqualFold(s, val) {
				return true
			}
		}
		return false
	}

	covers := func(super []string, sub []string, wildcard string) bool {
		if contains(super, wildcard) {
			return true
		}
		for _, s := range sub {
			if !contains(super, s) {
				return false
			}
		}
		return true
	}

	supersedes := func(p1, p2 Policy) bool {
		return covers(p1.SrcIntf, p2.SrcIntf, "any") &&
			covers(p1.DstIntf, p2.DstIntf, "any") &&
			covers(p1.SrcAddr, p2.SrcAddr, "all") &&
			covers(p1.DstAddr, p2.DstAddr, "all") &&
			covers(p1.Service, p2.Service, "ALL")
	}

	for i := 1; i < len(policies); i++ {
		p2 := policies[i]
		for j := 0; j < i; j++ {
			p1 := policies[j]
			if supersedes(p1, p2) {
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

func (s *Server) latestConfig(fwID int) (string, string, bool) {
	latest, ok := s.latestConfigFilename(fwID)
	if !ok {
		return "", "", false
	}
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))
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

func parseFortiOSVersion(cfg string) (model, version string) {
	if m := reConfigVersion.FindStringSubmatch(cfg); m != nil {
		return m[1], m[2]
	}
	return "", ""
}
