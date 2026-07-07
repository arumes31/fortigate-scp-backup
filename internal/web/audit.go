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
)

// auditFinding is a single compliance observation parsed from a config.
type auditFinding struct {
	Severity string // critical | warning | info
	Text     string
}

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
		plain, ok := s.latestConfig(ref.ID)
		row := auditRow{FwID: ref.ID, FQDN: ref.FQDN, HasConfig: ok}
		if ok {
			row.Model, row.Version = parseFortiOSVersion(plain)
			row.Findings = auditFindings(plain)
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

// latestConfig returns the decrypted newest .conf for a firewall, or ok=false
// when the firewall has no readable backup.
func (s *Server) latestConfig(fwID int) (string, bool) {
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
	if latest == "" {
		return "", false
	}
	raw, err := os.ReadFile(filepath.Join(fwDir, latest))
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

// parseFortiOSVersion extracts the model and firmware version from a config's
// "#config-version" header (empty strings when not present).
func parseFortiOSVersion(cfg string) (model, version string) {
	if m := reConfigVersion.FindStringSubmatch(cfg); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// auditFindings derives management-exposure findings from a config: telnet /
// plaintext-HTTP management, ping exposure, and how many interfaces expose any
// management service.
func auditFindings(cfg string) []auditFinding {
	var out []auditFinding
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
		out = append(out, auditFinding{"critical", "Telnet-Management aktiviert (allowaccess telnet)"})
	}
	if strings.Contains(strings.ToLower(cfg), "set admin-telnet enable") {
		out = append(out, auditFinding{"critical", "Admin-Telnet global aktiviert"})
	}
	if httpMgmt {
		out = append(out, auditFinding{"warning", "Klartext-HTTP-Management aktiviert (allowaccess http)"})
	}
	if pingMgmt {
		out = append(out, auditFinding{"info", "Ping auf Management-Interfaces erlaubt"})
	}
	if exposedMgmt > 0 {
		out = append(out, auditFinding{"info", fmt.Sprintf("%d Interface(s) mit Management-Zugriff exponiert", exposedMgmt)})
	}
	if len(out) == 0 {
		out = append(out, auditFinding{"info", "Keine offensichtlichen Management-Findings"})
	}
	return out
}
