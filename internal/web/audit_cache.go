package web

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// auditResult is the cached per-firewall audit computation: everything derived
// from one backup file. Exemptions are applied at read time, so toggling an
// exemption never triggers a recompute; custom rule changes bust the cache.
type auditResult struct {
	BackupFilename string    `json:"backup_filename"`
	ComputedAt     time.Time `json:"computed_at"`

	Model   string `json:"model"`
	Version string `json:"version"`

	Findings      []models.AuditFinding `json:"findings"`        // raw: pre-exemption
	UpgradePath   []string              `json:"upgrade_path"`    // English (canonical)
	UpgradePathDE []string              `json:"upgrade_path_de"` // German rendering

	PciScore   int `json:"pci_score"`
	CisScore   int `json:"cis_score"`
	HipaaScore int `json:"hipaa_score"`

	Interfaces []Interface   `json:"interfaces"`
	Routes     []StaticRoute `json:"routes"`
	Policies   []Policy      `json:"policies"`
	Switches   []FortiSwitch `json:"switches"`
}

// computeAudit runs the full audit for one decrypted configuration.
func computeAudit(fwID int, filename, plain string, customRules []customRule) *auditResult {
	res := &auditResult{
		BackupFilename: filename,
		ComputedAt:     time.Now(),
	}
	res.Model, res.Version = parseFortiOSVersion(plain)
	res.Interfaces, res.Routes, res.Policies, res.Switches = parseConfigData(plain)

	doc := parseCfg(plain)

	findings := runStructuralChecks(doc, res.Routes)
	findings = append(findings, findShadowRules(res.Policies)...)
	findings = append(findings, getCVEs(res.Version)...)

	for _, cr := range customRules {
		if idx := strings.Index(plain, cr.Pattern); idx >= 0 {
			lineIdx := strings.Count(plain[:idx], "\n")
			f := doc.findingAt(
				"custom", "custom:"+strconv.FormatInt(cr.ID, 10),
				cr.Severity,
				"Custom rule '"+cr.Name+"' violated: pattern '"+cr.Pattern+"' found",
				"Eigene Regel '"+cr.Name+"' verletzt: Muster '"+cr.Pattern+"' gefunden",
				cr.Remediation,
				lineIdx, enclosingBlock(doc, lineIdx))
			findings = append(findings, f)
		}
	}

	for i := range findings {
		findings[i].FwID = fwID
		findings[i].BackupFilename = filename
	}
	sortFindings(findings)
	res.Findings = findings

	res.PciScore, res.CisScore, res.HipaaScore = calculateComplianceScores(findings)
	res.UpgradePath, res.UpgradePathDE = getUpgradePath(res.Version)
	return res
}

// getCachedAudit returns the cached result for a firewall, if any.
func getCachedAudit(db *sql.DB, fwID int) (*auditResult, bool) {
	if db == nil {
		return nil, false
	}
	var blob string
	if err := db.QueryRow("SELECT results_json FROM audit_cache WHERE fw_id = ?", fwID).Scan(&blob); err != nil {
		return nil, false
	}
	var res auditResult
	if err := json.Unmarshal([]byte(blob), &res); err != nil {
		return nil, false
	}
	return &res, true
}

// storeAudit upserts the cached result for a firewall.
func storeAudit(db *sql.DB, fwID int, res *auditResult) {
	if db == nil {
		return
	}
	blob, err := json.Marshal(res)
	if err != nil {
		return
	}
	_, _ = db.Exec(`INSERT INTO audit_cache (fw_id, backup_filename, computed_at, results_json)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(fw_id) DO UPDATE SET
			backup_filename = excluded.backup_filename,
			computed_at = excluded.computed_at,
			results_json = excluded.results_json`,
		fwID, res.BackupFilename, res.ComputedAt.Format(time.RFC3339), string(blob))
}

// auditResultFor returns the audit result for a firewall, computing and
// caching it when the cache is missing or refers to an older backup.
func (s *Server) auditResultFor(db *sql.DB, fwID int) (*auditResult, bool) {
	filename, ok := s.latestConfigFilename(fwID)
	if !ok {
		return nil, false
	}
	if cached, hit := getCachedAudit(db, fwID); hit && cached.BackupFilename == filename {
		return cached, true
	}
	plain, filename, ok := s.latestConfig(fwID)
	if !ok {
		return nil, false
	}
	res := computeAudit(fwID, filename, plain, loadCustomRules(db))
	storeAudit(db, fwID, res)
	return res, true
}

// WarmAuditCache pre-computes the audit for a firewall (called after a
// successful backup so the audit page is instant). Safe to run concurrently;
// errors only cost the pre-warming.
func (s *Server) WarmAuditCache(fwID int) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("audit cache warm panicked", "fw_id", fwID, "panic", r)
		}
	}()
	db, err := s.insightsDB()
	if err != nil || db == nil {
		return
	}
	// Force recompute: a fresh backup just landed.
	plain, filename, ok := s.latestConfig(fwID)
	if !ok {
		return
	}
	res := computeAudit(fwID, filename, plain, loadCustomRules(db))
	storeAudit(db, fwID, res)
	s.logger.Debug("audit cache warmed", "fw_id", fwID, "backup", filename, "findings", len(res.Findings))
}

// auditRowJSON is the /audit/results/{fwID} response shape consumed by the
// audit page.
type auditRowJSON struct {
	FwID       int    `json:"fw_id"`
	HasConfig  bool   `json:"has_config"`
	Model      string `json:"model,omitempty"`
	Version    string `json:"version,omitempty"`
	Backup     string `json:"backup_filename,omitempty"`
	ComputedAt string `json:"computed_at,omitempty"`

	Findings []models.AuditFinding `json:"findings,omitempty"`
	Exempted []models.AuditFinding `json:"exempted,omitempty"`

	UpgradePath []string `json:"upgrade_path,omitempty"`

	PciScore   int `json:"pci_score"`
	CisScore   int `json:"cis_score"`
	HipaaScore int `json:"hipaa_score"`

	TicketID     string `json:"ticket_id,omitempty"`
	TicketDetail string `json:"ticket_detail,omitempty"`
}

// splitExemptions partitions raw findings into active and exempted using the
// stable finding key (legacy rows fall back to exact text matching).
func splitExemptions(findings []models.AuditFinding, exemptions []exemption, fwID int) (active, exempted []models.AuditFinding) {
	for _, f := range findings {
		isExempt := false
		for _, ex := range exemptions {
			if ex.FwID != fwID {
				continue
			}
			if (ex.FindingKey != "" && ex.FindingKey == f.Key) ||
				(ex.FindingKey == "" && ex.FindingText == f.Text) {
				isExempt = true
				break
			}
		}
		if isExempt {
			exempted = append(exempted, f)
		} else {
			active = append(active, f)
		}
	}
	return active, exempted
}

// handleAuditResults serves the per-firewall audit result as JSON, computing
// lazily on cache miss.
func (s *Server) handleAuditResults(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid firewall id", http.StatusBadRequest)
		return
	}
	db, dbErr := s.insightsDB()
	if dbErr != nil {
		s.logger.Error("insights db unavailable", "err", dbErr)
	}

	if r.URL.Query().Get("recompute") == "1" && db != nil {
		_, _ = db.Exec("DELETE FROM audit_cache WHERE fw_id = ?", fwID)
	}

	lang := langFromRequest(r)
	out := auditRowJSON{FwID: fwID}
	res, ok := s.auditResultFor(db, fwID)
	if ok {
		out.HasConfig = true
		out.Model = res.Model
		out.Version = res.Version
		out.Backup = res.BackupFilename
		out.ComputedAt = res.ComputedAt.Format("2006-01-02 15:04:05")
		out.UpgradePath = res.UpgradePath
		if lang == "de" && len(res.UpgradePathDE) > 0 {
			out.UpgradePath = res.UpgradePathDE
		}
		out.PciScore, out.CisScore, out.HipaaScore = res.PciScore, res.CisScore, res.HipaaScore
		active, exempted := splitExemptions(res.Findings, loadExemptions(db), fwID)
		out.Findings = localizeFindings(active, lang)
		out.Exempted = localizeFindings(exempted, lang)

		if db != nil {
			_ = db.QueryRow("SELECT ticket_id, details FROM change_tickets WHERE backup_filename = ?",
				res.BackupFilename).Scan(&out.TicketID, &out.TicketDetail)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
