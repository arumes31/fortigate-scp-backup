package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// This file fetches LIVE FortiOS CVE data so the audit engine never depends
// on a hand-maintained table (see cveFallbackDefs in audit_checks.go, which
// exists only as an offline safety net, not the source of truth). Two public,
// keyless-or-free sources are combined:
//
//   - NVD API 2.0, queried by CPE, gives structured affected/fixed version
//     ranges per FortiOS train.
//   - CISA's Known Exploited Vulnerabilities (KEV) catalog gives a trustworthy
//     "actively exploited" signal that a CVSS score alone can understate
//     (Fortinet and NVD have scored the same FortiOS CVE differently before).
//
// Fortinet's own PSIRT advisories are the most complete source but expose no
// JSON/CSAF feed (HTML only), so scraping them is deliberately left out of
// this v1 rather than built on fragile markup assumptions.

const (
	nvdCVEEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdCPEMatch    = "cpe:2.3:o:fortinet:fortios"
	kevFeedURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	nvdPageSize    = 200
	nvdMaxPages    = 10 // hard cap: 2000 CVEs is far more than FortiOS will ever have
	cveUserAgent   = "fortigate-scp-backup-audit/1.0 (+https://github.com/arumes31/fortigate-scp-backup)"
)

var cveHTTPClient = &http.Client{Timeout: 20 * time.Second}

type nvdCvssMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // CVSSv2 entries carry it at this level instead
}

type nvdCpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdVuln struct {
	CVE struct {
		ID           string `json:"id"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
			CvssMetricV30 []nvdCvssMetric `json:"cvssMetricV30"`
			CvssMetricV2  []nvdCvssMetric `json:"cvssMetricV2"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CpeMatch []nvdCpeMatch `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

type nvdResponse struct {
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

// fetchNVDFortiOSCVEs queries NVD's CPE search for every CVE affecting
// FortiOS, paginating until exhausted (capped at nvdMaxPages pages). apiKey is
// optional: NVD allows 5 req/30s without one, 50 req/30s with one.
func fetchNVDFortiOSCVEs(ctx context.Context, apiKey string) ([]cveDef, error) {
	var defs []cveDef
	startIndex := 0
	for page := 0; page < nvdMaxPages; page++ {
		reqURL := fmt.Sprintf("%s?virtualMatchString=%s&resultsPerPage=%d&startIndex=%d",
			nvdCVEEndpoint, nvdCPEMatch, nvdPageSize, startIndex)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", cveUserAgent)
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}
		resp, err := cveHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("nvd request failed: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nvd returned status %d", resp.StatusCode)
		}
		if readErr != nil {
			return nil, fmt.Errorf("nvd response read failed: %w", readErr)
		}
		var parsed nvdResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("nvd response parse failed: %w", err)
		}
		for _, v := range parsed.Vulnerabilities {
			if def, ok := nvdEntryToDef(v); ok {
				defs = append(defs, def)
			}
		}
		startIndex += nvdPageSize
		if startIndex >= parsed.TotalResults || len(parsed.Vulnerabilities) == 0 {
			break
		}
		if apiKey == "" {
			// Keyless rate limit is 5 requests/30s; stay well under it.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(6 * time.Second):
			}
		}
	}
	return defs, nil
}

// nvdEntryToDef converts one NVD vulnerability entry into the same cveDef
// shape the audit engine already matches against. Entries with no parseable
// FortiOS version range are dropped rather than guessed at.
func nvdEntryToDef(v nvdVuln) (cveDef, bool) {
	def := cveDef{id: v.CVE.ID}
	for _, d := range v.CVE.Descriptions {
		if d.Lang == "en" {
			def.summaryEN = truncateCVESummary(d.Value)
			break
		}
	}
	def.severity = nvdSeverity(v.CVE.Metrics.CvssMetricV31, v.CVE.Metrics.CvssMetricV30, v.CVE.Metrics.CvssMetricV2)
	for _, cfg := range v.CVE.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				if !m.Vulnerable || !strings.Contains(m.Criteria, "fortinet:fortios") {
					continue
				}
				if r, ok := nvdCpeRange(m); ok {
					def.ranges = append(def.ranges, r)
				}
			}
		}
	}
	if len(def.ranges) == 0 || def.summaryEN == "" {
		return cveDef{}, false
	}
	def.remediation = nvdRemediation(def.ranges)
	return def, true
}

func nvdSeverity(sets ...[]nvdCvssMetric) string {
	for _, set := range sets {
		if len(set) == 0 {
			continue
		}
		sev := strings.ToUpper(set[0].CvssData.BaseSeverity)
		if sev == "" {
			sev = strings.ToUpper(set[0].BaseSeverity)
		}
		switch sev {
		case "CRITICAL", "HIGH":
			return "critical"
		case "MEDIUM":
			return "warning"
		case "LOW":
			return "info"
		}
	}
	return "warning"
}

// nvdCpeRange converts one cpeMatch's version bounds into the fixedPatch
// representation getCVEs already understands. End-only ranges derive their
// train from the fixed-version bound; start-only ranges have no fixed version
// and therefore mark that train as neverFixed. Exact-version matches without
// range fields are skipped rather than approximated.
func nvdCpeRange(m nvdCpeMatch) (cveRange, bool) {
	startStr := m.VersionStartIncluding
	if startStr == "" {
		startStr = m.VersionStartExcluding
	}
	endStr := m.VersionEndExcluding
	endIncluding := false
	if endStr == "" {
		endStr = m.VersionEndIncluding
		endIncluding = true
	}
	if startStr == "" && endStr == "" {
		return cveRange{}, false
	}
	trainVersion := startStr
	if trainVersion == "" {
		trainVersion = endStr
	}
	major, minor, _, ok := splitVersion(trainVersion)
	if !ok {
		return cveRange{}, false
	}
	if endStr == "" {
		return cveRange{major: major, minor: minor, fixedPatch: neverFixed}, true
	}
	endMajor, endMinor, endPatch, ok2 := splitVersion(endStr)
	if !ok2 || endMajor != major || endMinor != minor {
		return cveRange{}, false
	}
	fixedPatch := endPatch
	if endIncluding {
		fixedPatch++
	}
	return cveRange{major: major, minor: minor, fixedPatch: fixedPatch}, true
}

func truncateCVESummary(s string) string {
	s = strings.TrimSpace(s)
	const max = 240
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func nvdRemediation(ranges []cveRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r.fixedPatch == neverFixed {
			parts = append(parts, fmt.Sprintf("%d.%d.x has no fix — migrate to a supported train", r.major, r.minor))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d.%d.x: upgrade to >= %d.%d.%d", r.major, r.minor, r.major, r.minor, r.fixedPatch))
	}
	return "See Fortinet PSIRT (fortiguard.com/psirt) for the full advisory and any interim mitigation. " + strings.Join(parts, "; ") + "."
}

type kevFeed struct {
	Vulnerabilities []struct {
		CveID         string `json:"cveID"`
		VendorProject string `json:"vendorProject"`
	} `json:"vulnerabilities"`
}

// fetchFortinetKEV returns the set of Fortinet CVE IDs on CISA's Known
// Exploited Vulnerabilities catalog — the "is this actually being exploited"
// signal NVD's CVSS score alone doesn't reliably capture.
func fetchFortinetKEV(ctx context.Context) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevFeedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cveUserAgent)
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cisa kev request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cisa kev returned status %d", resp.StatusCode)
	}
	var feed kevFeed
	if err := json.NewDecoder(io.LimitReader(resp.Body, 20<<20)).Decode(&feed); err != nil {
		return nil, fmt.Errorf("cisa kev parse failed: %w", err)
	}
	out := make(map[string]bool)
	for _, v := range feed.Vulnerabilities {
		if strings.Contains(strings.ToLower(v.VendorProject), "fortinet") {
			out[v.CveID] = true
		}
	}
	return out, nil
}

// fetchLiveCVEDefs combines NVD (structured version ranges) with CISA KEV
// (actively-exploited ground truth) into the cveDef shape the audit engine
// matches against. A KEV hit always forces severity to "critical": Fortinet's
// own CVSS score and NVD's can disagree (e.g. CVE-2025-25249: 8.1 vs 9.8), and
// a known-exploited vulnerability should never be under-flagged.
func fetchLiveCVEDefs(ctx context.Context, nvdAPIKey string) ([]cveDef, error) {
	defs, err := fetchNVDFortiOSCVEs(ctx, nvdAPIKey)
	if err != nil {
		return nil, err
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("nvd returned zero FortiOS CVEs (unexpected)")
	}
	// KEV is an enrichment, not the primary data: degrade gracefully rather
	// than discarding a successful NVD fetch just because CISA is unreachable.
	kev, _ := fetchFortinetKEV(ctx)
	for i := range defs {
		if kev[defs[i].id] {
			defs[i].severity = "critical"
			if !strings.Contains(defs[i].summaryEN, "actively exploited") {
				defs[i].summaryEN += " (actively exploited — CISA KEV listed)"
			}
		}
	}
	return defs, nil
}
