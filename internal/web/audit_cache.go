package web

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// auditResult is the cached per-firewall audit computation: everything derived
// from one backup file. Exemptions are applied at read time, so toggling an
// exemption never triggers a recompute; custom rule changes invalidate the
// entry via RulesFingerprint.
type auditResult struct {
	BackupFilename string    `json:"backup_filename"`
	ComputedAt     time.Time `json:"computed_at"`
	// RulesFingerprint identifies the custom-rule set the result was computed
	// with; a mismatch forces a recompute (also closes the race where an
	// in-flight compute stores results made with an outdated rule set after
	// the rule-change cache bust).
	RulesFingerprint string `json:"rules_fingerprint,omitempty"`

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

// rulesFingerprint hashes the custom-rule set so cached results can detect
// rule changes.
func rulesFingerprint(rules []customRule) string {
	h := sha256.New()
	for _, r := range rules {
		_, _ = fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00", r.ID, r.Name, r.Pattern, r.Severity, r.Remediation)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// computeAudit runs the full audit for one decrypted configuration.
func computeAudit(fwID int, filename, plain string, customRules []customRule) *auditResult {
	res := &auditResult{
		BackupFilename:   filename,
		ComputedAt:       time.Now(),
		RulesFingerprint: rulesFingerprint(customRules),
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
// caching it when the cache is missing, refers to an older backup, or was
// computed with a different custom-rule set.
func (s *Server) auditResultFor(db *sql.DB, fwID int) (*auditResult, bool) {
	filename, ok := s.latestConfigFilename(fwID)
	if !ok {
		return nil, false
	}
	rules := loadCustomRules(db)
	if cached, hit := getCachedAudit(db, fwID); hit &&
		cached.BackupFilename == filename && cached.RulesFingerprint == rulesFingerprint(rules) {
		return cached, true
	}
	plain, ok := s.readConfig(fwID, filename)
	if !ok {
		return nil, false
	}
	res := computeAudit(fwID, filename, plain, rules)
	storeAudit(db, fwID, res)
	return res, true
}

// WarmAuditCache pre-computes the audit for a firewall (called after a
// successful backup so the audit page is instant). Concurrency is bounded by
// warmSem so a fleet-wide backup burst cannot pile up dozens of full-config
// parses; errors only cost the pre-warming.
func (s *Server) WarmAuditCache(fwID int) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("audit cache warm panicked", "fw_id", fwID, "panic", r)
		}
	}()
	s.warmSem <- struct{}{}
	defer func() { <-s.warmSem }()

	db, err := s.insightsDB()
	if err != nil || db == nil {
		return
	}
	// Force recompute: a fresh backup just landed.
	filename, ok := s.latestConfigFilename(fwID)
	if !ok {
		return
	}
	plain, ok := s.readConfig(fwID, filename)
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
// stable finding key. Keys with the "check:" prefix (from the legacy-text
// backfill) exempt every instance of that check; rows without a key fall back
// to exact text matching.
func splitExemptions(findings []models.AuditFinding, exemptions []exemption, fwID int) (active, exempted []models.AuditFinding) {
	byKey := map[string]bool{}
	byCheck := map[string]bool{}
	byText := map[string]bool{}
	for _, ex := range exemptions {
		if ex.FwID != fwID {
			continue
		}
		switch {
		case strings.HasPrefix(ex.FindingKey, "check:"):
			byCheck[strings.TrimPrefix(ex.FindingKey, "check:")] = true
		case ex.FindingKey != "":
			byKey[ex.FindingKey] = true
		case ex.FindingText != "":
			byText[ex.FindingText] = true
		}
	}
	for _, f := range findings {
		if byKey[f.Key] || (f.CheckID != "" && byCheck[f.CheckID]) || byText[f.Text] {
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
		out.ComputedAt = res.ComputedAt.Format(insightsTimeLayout)
		out.UpgradePath = res.UpgradePath
		if lang == "de" && len(res.UpgradePathDE) > 0 {
			out.UpgradePath = res.UpgradePathDE
		}
		active, exempted := splitExemptions(res.Findings, loadExemptionsFor(db, fwID), fwID)
		// Scores reflect the ACTIVE findings: exempting a finding restores the
		// compliance score (the cached scores are pre-exemption).
		out.PciScore, out.CisScore, out.HipaaScore = calculateComplianceScores(active)
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
