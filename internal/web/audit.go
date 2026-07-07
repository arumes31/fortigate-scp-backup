package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	_ "modernc.org/sqlite"
)

type auditFinding = models.AuditFinding

// SQLite instance for insights data
var (
	insightsDB    *sql.DB
	insightsOnce  sync.Once
	insightsDBErr error
)

// initInsightsDB opens the SQLite database and sets up the schemas
func initInsightsDB(dataDir string) (*sql.DB, error) {
	insightsOnce.Do(func() {
		dbPath := filepath.Join(dataDir, "forti-insights.db")
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			insightsDBErr = err
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
				insightsDBErr = pragmaErr
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
		}
		for _, q := range queries {
			if _, execErr := db.Exec(q); execErr != nil {
				_ = db.Close()
				insightsDBErr = execErr
				return
			}
		}
		insightsDB = db
	})
	return insightsDB, insightsDBErr
}

// Structs for UI data
type auditRow struct {
	FwID         int
	FQDN         string
	Model        string
	Version      string
	Findings     []auditFinding
	Exempted     []auditFinding
	HasConfig    bool
	UpgradePath  []string
	PciScore     int
	CisScore     int
	HipaaScore   int
	TicketID     string
	TicketDetail string

	// Topology data for JSON/JS consumption
	Interfaces []Interface
	Routes     []StaticRoute
	Policies   []Policy
	Switches   []FortiSwitch
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
	FindingText string
	Reason      string
	CreatedAt   time.Time
}

type versionCount struct {
	Version string
	Count   int
}

type auditData struct {
	Base        BaseData
	Rows        []auditRow
	Versions    []versionCount
	Critical    int
	Warnings    int
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

var (
	reConfigVersion = regexp.MustCompile(`(?i)#config-version=([A-Za-z0-9]+)-([0-9]+\.[0-9]+\.[0-9]+)`)
	reAllowAccess   = regexp.MustCompile(`(?i)set allowaccess ([^\r\n]+)`)
)

// handleAudit renders the audit page, compiling compliance results, CVE mapping, shadow rules,
// change management ticket details, custom policies, and network topology.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db, err := initInsightsDB(s.cfg.DataDir)
	if err != nil {
		s.logger.Error("failed to load insights database", "err", err)
	}

	// Fetch custom rules
	var customRules []customRule
	if db != nil {
		rows, err := db.Query("SELECT id, name, pattern, severity, remediation FROM custom_rules")
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var cr customRule
				if scanErr := rows.Scan(&cr.ID, &cr.Name, &cr.Pattern, &cr.Severity, &cr.Remediation); scanErr == nil {
					customRules = append(customRules, cr)
				}
			}
		}
	}

	// Fetch exemptions
	var exemptions []exemption
	if db != nil {
		rows, err := db.Query("SELECT id, fw_id, finding_text, reason, created_at FROM exemptions")
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var ex exemption
				var caRaw string
				if scanErr := rows.Scan(&ex.ID, &ex.FwID, &ex.FindingText, &ex.Reason, &caRaw); scanErr == nil {
					if t, tErr := time.Parse("2006-01-02 15:04:05", caRaw); tErr == nil {
						ex.CreatedAt = t
					} else {
						ex.CreatedAt = time.Now()
					}
					exemptions = append(exemptions, ex)
				}
			}
		}
	}

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

			// Parse topology including switches
			row.Interfaces, row.Routes, row.Policies, row.Switches = parseConfigData(plain)

			// Run checks
			rawFindings := auditFindingsForBackup(ref.ID, filename, plain)

			// 1. Add shadow rules
			shadowFindings := findShadowRules(row.Policies)
			for i := range shadowFindings {
				shadowFindings[i].FwID = ref.ID
				shadowFindings[i].BackupFilename = filename
			}
			rawFindings = append(rawFindings, shadowFindings...)

			// 2. Add Security Fabric audit
			fabricFindings := auditSecurityFabric(plain)
			for i := range fabricFindings {
				fabricFindings[i].FwID = ref.ID
				fabricFindings[i].BackupFilename = filename
			}
			rawFindings = append(rawFindings, fabricFindings...)

			// 3. Add CVE warnings
			cveFindings := getCVEs(row.Version)
			for i := range cveFindings {
				cveFindings[i].FwID = ref.ID
				cveFindings[i].BackupFilename = filename
			}
			rawFindings = append(rawFindings, cveFindings...)

			// 4. Custom Rules evaluation
			for _, cr := range customRules {
				if strings.Contains(plain, cr.Pattern) {
					rawFindings = append(rawFindings, models.AuditFinding{
						FwID:           ref.ID,
						BackupFilename: filename,
						Severity:       cr.Severity,
						Text:           fmt.Sprintf("Eigene Regel '%s' verletzt: Muster '%s' gefunden", cr.Name, cr.Pattern),
						Remediation:    cr.Remediation,
					})
				}
			}

			// Filter Exemptions
			var activeFindings []auditFinding
			var exemptedFindings []auditFinding

			for _, rf := range rawFindings {
				isExempt := false
				for _, ex := range exemptions {
					if ex.FwID == ref.ID && ex.FindingText == rf.Text {
						isExempt = true
						break
					}
				}
				if isExempt {
					exemptedFindings = append(exemptedFindings, rf)
				} else {
					activeFindings = append(activeFindings, rf)
				}
			}

			row.Findings = activeFindings
			row.Exempted = exemptedFindings

			// 5. Calculate upgrade path
			row.UpgradePath = getUpgradePath(row.Version)

			// 6. Calculate compliance scores
			row.PciScore, row.CisScore, row.HipaaScore = calculateComplianceScores(activeFindings, plain)

			// 7. Load Change Ticket
			if db != nil {
				_ = db.QueryRow("SELECT ticket_id, details FROM change_tickets WHERE backup_filename = ?", filename).Scan(&row.TicketID, &row.TicketDetail)
			}

			// Track version metrics
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
		Base:        s.base(r, "Audit", "audit"),
		Rows:        rows,
		Versions:    versions,
		Critical:    crit,
		Warnings:    warn,
		CustomRules: customRules,
		Exemptions:  exemptions,
	})
}

// handleAuditExemption handles POST requests to register / remove exemptions
func (s *Server) handleAuditExemption(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := initInsightsDB(s.cfg.DataDir)
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
		findingText := r.FormValue("finding_text")
		reason := r.FormValue("reason")
		createdAt := time.Now().Format("2006-01-02 15:04:05")

		_, _ = db.Exec("INSERT INTO exemptions (fw_id, finding_text, reason, created_at) VALUES (?, ?, ?, ?)",
			fwID, findingText, reason, createdAt)
	}

	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// handleAuditCustomRule handles POST requests to register / delete custom rule patterns
func (s *Server) handleAuditCustomRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := initInsightsDB(s.cfg.DataDir)
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

	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// handleAuditTicket handles POST requests to attach change tickets to config files
func (s *Server) handleAuditTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := initInsightsDB(s.cfg.DataDir)
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

	supersedes := func(p1, p2 Policy) bool {
		srcMatch := false
		if contains(p1.SrcIntf, "any") {
			srcMatch = true
		} else {
			allContained := true
			for _, s := range p2.SrcIntf {
				if !contains(p1.SrcIntf, s) {
					allContained = false
					break
				}
			}
			srcMatch = allContained
		}
		if !srcMatch {
			return false
		}

		dstMatch := false
		if contains(p1.DstIntf, "any") {
			dstMatch = true
		} else {
			allContained := true
			for _, d := range p2.DstIntf {
				if !contains(p1.DstIntf, d) {
					allContained = false
					break
				}
			}
			dstMatch = allContained
		}
		if !dstMatch {
			return false
		}

		srcAddrMatch := false
		if contains(p1.SrcAddr, "all") {
			srcAddrMatch = true
		} else {
			allContained := true
			for _, sa := range p2.SrcAddr {
				if !contains(p1.SrcAddr, sa) {
					allContained = false
					break
				}
			}
			srcAddrMatch = allContained
		}
		if !srcAddrMatch {
			return false
		}

		dstAddrMatch := false
		if contains(p1.DstAddr, "all") {
			dstAddrMatch = true
		} else {
			allContained := true
			for _, da := range p2.DstAddr {
				if !contains(p1.DstAddr, da) {
					allContained = false
					break
				}
			}
			dstAddrMatch = allContained
		}
		if !dstAddrMatch {
			return false
		}

		srvMatch := false
		if contains(p1.Service, "ALL") {
			srvMatch = true
		} else {
			allContained := true
			for _, sv := range p2.Service {
				if !contains(p1.Service, sv) {
					allContained = false
					break
				}
			}
			srvMatch = allContained
		}
		return srvMatch
	}

	for i := 1; i < len(policies); i++ {
		p2 := policies[i]
		for j := 0; j < i; j++ {
			p1 := policies[j]
			if supersedes(p1, p2) {
				findings = append(findings, models.AuditFinding{
					Severity:    "warning",
					Text:        fmt.Sprintf("Shadow-Rule ID %d: wird durch ID %d blockiert", p2.ID, p1.ID),
					Remediation: fmt.Sprintf("Verschieben Sie die spezifischere Policy ID %d vor ID %d, oder entfernen Sie die überflüssige Policy.", p2.ID, p1.ID),
				})
				break
			}
		}
	}
	return findings
}

// auditSecurityFabric implements Category 1 Feature 10
func auditSecurityFabric(cfg string) []models.AuditFinding {
	var findings []models.AuditFinding
	if !strings.Contains(cfg, "config system csf") {
		findings = append(findings, models.AuditFinding{
			Severity:    "info",
			Text:        "Fortinet Security Fabric (CSF) ist nicht konfiguriert",
			Remediation: "config system csf\n  set status enable\n  set upstream-ip <upstream_ip>\nend",
		})
	}
	return findings
}

// getUpgradePath implements Category 3 Feature 3
func getUpgradePath(version string) []string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return []string{"Keine Upgrade-Pfad-Informationen verfügbar"}
	}
	major := parts[0]
	minor := parts[1]

	switch major + "." + minor {
	case "6.0":
		return []string{"6.0.x", "6.2.16 (Latest 6.2)", "6.4.15 (Latest 6.4)", "7.0.16 (Latest 7.0)", "7.2.9 (Latest 7.2)", "7.4.3 (Latest 7.4)"}
	case "6.2":
		return []string{"6.2.x", "6.4.15 (Latest 6.4)", "7.0.16 (Latest 7.0)", "7.2.9 (Latest 7.2)", "7.4.3 (Latest 7.4)"}
	case "6.4":
		return []string{"6.4.x", "7.0.16 (Latest 7.0)", "7.2.9 (Latest 7.2)", "7.4.3 (Latest 7.4)"}
	case "7.0":
		return []string{"7.0.x", "7.2.9 (Latest 7.2)", "7.4.3 (Latest 7.4)", "7.6.0"}
	case "7.2":
		return []string{"7.2.x", "7.4.3 (Latest 7.4)", "7.6.0"}
	case "7.4":
		return []string{"7.4.x", "7.6.0"}
	default:
		return []string{version + " -> 7.6.0"}
	}
}

// getCVEs implements Category 3 Feature 4
func getCVEs(version string) []models.AuditFinding {
	var findings []models.AuditFinding
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return nil
	}
	vNum := func(idx int) int {
		n, _ := strconv.Atoi(parts[idx])
		return n
	}
	major, minor, patch := vNum(0), vNum(1), vNum(2)

	// CVE-2023-27997: SSLVPN Heap Buffer Overflow
	isVulnerable2023 := false
	if major == 7 && minor == 2 && patch < 5 {
		isVulnerable2023 = true
	} else if major == 7 && minor == 0 && patch < 12 {
		isVulnerable2023 = true
	} else if major == 6 && minor == 4 && patch < 13 {
		isVulnerable2023 = true
	} else if major == 6 && minor == 2 && patch < 15 {
		isVulnerable2023 = true
	} else if major == 6 && minor == 0 && patch < 17 {
		isVulnerable2023 = true
	}

	if isVulnerable2023 {
		findings = append(findings, models.AuditFinding{
			Severity:    "critical",
			Text:        "Kritische Sicherheitslücke CVE-2023-27997 (SSL-VPN Heap Buffer Overflow)",
			Remediation: "Upgrade auf FortiOS >= 7.2.5, 7.0.12 oder Deaktivierung des SSL-VPN.",
		})
	}

	// CVE-2024-21762: SSLVPN Remote Code Execution
	isVulnerable2024 := false
	if major == 7 && minor == 4 && patch < 3 {
		isVulnerable2024 = true
	} else if major == 7 && minor == 2 && patch < 7 {
		isVulnerable2024 = true
	} else if major == 7 && minor == 0 && patch < 14 {
		isVulnerable2024 = true
	}

	if isVulnerable2024 {
		findings = append(findings, models.AuditFinding{
			Severity:    "critical",
			Text:        "Kritische Sicherheitslücke CVE-2024-21762 (SSL-VPN Out-of-bounds Write RCE)",
			Remediation: "Upgrade auf FortiOS >= 7.4.3, 7.2.7, 7.0.14 oder Deaktivierung von SSL-VPN Web-Mode.",
		})
	}

	return findings
}

// calculateComplianceScores implements Category 7 Features 1, 2, 3
func calculateComplianceScores(findings []models.AuditFinding, cfg string) (pci, cis, hipaa int) {
	pciChecks, cisChecks, hipaaChecks := 5, 5, 4
	pciPass, cisPass, hipaaPass := 5, 5, 4

	for _, f := range findings {
		text := strings.ToLower(f.Text)

		if strings.Contains(text, "telnet") {
			pciPass--
		}
		if strings.Contains(text, "http-management") {
			pciPass--
		}
		if strings.Contains(text, "proposals") {
			pciPass--
		}
		if strings.Contains(text, "password-policy") {
			pciPass--
		}
		if strings.Contains(text, "zwei-faktor") {
			pciPass--
		}

		if strings.Contains(text, "telnet") {
			cisPass--
		}
		if strings.Contains(text, "ssl/tls-protokoll") {
			cisPass--
		}
		if strings.Contains(text, "allowaccess") {
			cisPass--
		}
		if strings.Contains(text, "password-policy") {
			cisPass--
		}
		if strings.Contains(text, "diffie-hellman") {
			cisPass--
		}

		if strings.Contains(text, "telnet") || strings.Contains(text, "http-management") {
			hipaaPass--
		}
		if strings.Contains(text, "password-policy") {
			hipaaPass--
		}
		if strings.Contains(text, "zwei-faktor") {
			hipaaPass--
		}
		if strings.Contains(text, "proposals") {
			hipaaPass--
		}
	}

	if pciPass < 0 {
		pciPass = 0
	}
	if cisPass < 0 {
		cisPass = 0
	}
	if hipaaPass < 0 {
		hipaaPass = 0
	}

	pci = (pciPass * 100) / pciChecks
	cis = (cisPass * 100) / cisChecks
	hipaa = (hipaaPass * 100) / hipaaChecks

	return pci, cis, hipaa
}

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

			if !strings.Contains(userConfig, "set two-factor") {
				out = append(out, models.AuditFinding{
					Severity:    "critical",
					Text:        fmt.Sprintf("Administrator '%s' hat keine Zwei-Faktor-Authentifizierung (2FA) aktiviert", username),
					Remediation: fmt.Sprintf("config system admin\n  edit %s\n  set two-factor email/sms/fortitoken\nnext\nend", username),
				})
			}

			if username == "admin" {
				out = append(out, models.AuditFinding{
					Severity:    "warning",
					Text:        "Standard-Administrator-Account 'admin' existiert noch",
					Remediation: "config system admin\n  rename admin to <new_secure_username>\nend",
				})
			}
		}
	}

	// 2. Proposal audits & Cryptographic checks
	re3DES := regexp.MustCompile(`(?i)\b3des\b`)
	reDES := regexp.MustCompile(`(?i)\bdes\b`)
	reMD5 := regexp.MustCompile(`(?i)\bmd5\b`)

	var hasDES, has3DES, hasMD5, hasWeakDH, hasMinSSLWeak, hasPasswordPolicyDisabled bool

	lines := strings.Split(cfg, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

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

		if strings.HasPrefix(lower, "set dhgrp") {
			parts := strings.Fields(lower)
			for _, part := range parts {
				if part == "1" || part == "2" || part == "5" {
					hasWeakDH = true
				}
			}
		}

		if strings.HasPrefix(lower, "set ssl-min-proto-version") {
			if strings.Contains(lower, "ssl3") || strings.Contains(lower, "tls1-0") || strings.Contains(lower, "tls1-1") {
				hasMinSSLWeak = true
			}
		}
	}

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
