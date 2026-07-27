package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// This file is the storage/orchestration layer for CVE data: the cve_cache /
// cve_meta tables, converting between cveDef and its JSON-storable form, and
// refreshing the cache from the live sources in cve_source.go. See
// cveFallbackDefs (audit_checks.go) for the offline-only safety net this
// backs onto when a live fetch has never succeeded.

// cveRangeJSON is cveRange's storage form: cveRange's fields are unexported
// (internal to the matching logic), so this small mirror is what actually
// gets marshaled into the ranges_json column.
type cveRangeJSON struct {
	Major      int `json:"major"`
	Minor      int `json:"minor"`
	FixedPatch int `json:"fixed_patch"`
}

func encodeRanges(ranges []cveRange) string {
	out := make([]cveRangeJSON, len(ranges))
	for i, r := range ranges {
		out[i] = cveRangeJSON{Major: r.major, Minor: r.minor, FixedPatch: r.fixedPatch}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func decodeRanges(blob string) []cveRange {
	var raw []cveRangeJSON
	if err := json.Unmarshal([]byte(blob), &raw); err != nil {
		return nil
	}
	out := make([]cveRange, len(raw))
	for i, r := range raw {
		out[i] = cveRange{major: r.Major, minor: r.Minor, fixedPatch: r.FixedPatch}
	}
	return out
}

// seedCVECacheIfEmpty populates cve_cache with the offline fallback defs on
// first run, so getCVEs has something to match against before the first live
// refresh (scheduled or manual) ever succeeds. No-op once anything exists.
func seedCVECacheIfEmpty(db *sql.DB) {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM cve_cache").Scan(&count); err != nil || count > 0 {
		return
	}
	for _, def := range cveFallbackDefs {
		_, _ = db.Exec(`INSERT OR IGNORE INTO cve_cache (id, summary_en, severity, ranges_json, remediation, source)
			VALUES (?, ?, ?, ?, ?, 'fallback-seed')`,
			def.id, def.summaryEN, def.severity, encodeRanges(def.ranges), def.remediation)
	}
}

// loadCVEDefs returns the best available CVE dataset: live (NVD+KEV) rows
// when a refresh has ever succeeded, otherwise the offline fallback seed.
func loadCVEDefs(db *sql.DB) []cveDef {
	if db == nil {
		return cveFallbackDefs
	}
	if defs := queryCVEDefs(db, "SELECT id, summary_en, severity, ranges_json, remediation FROM cve_cache WHERE source = 'live'"); len(defs) > 0 {
		return defs
	}
	if defs := queryCVEDefs(db, "SELECT id, summary_en, severity, ranges_json, remediation FROM cve_cache WHERE source = 'fallback-seed'"); len(defs) > 0 {
		return defs
	}
	return cveFallbackDefs
}

func queryCVEDefs(db *sql.DB, query string) []cveDef {
	rows, err := db.Query(query)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []cveDef
	for rows.Next() {
		var def cveDef
		var rangesBlob string
		if scanErr := rows.Scan(&def.id, &def.summaryEN, &def.severity, &rangesBlob, &def.remediation); scanErr != nil {
			continue
		}
		def.ranges = decodeRanges(rangesBlob)
		out = append(out, def)
	}
	return out
}

// cveFingerprint hashes the loaded CVE dataset so a cached audit result can
// detect that CVE data changed (a live refresh landed, or the fallback seed
// changed on upgrade) and recompute — mirroring rulesFingerprint for custom
// rules.
func cveFingerprint(defs []cveDef) string {
	h := sha256.New()
	for _, d := range defs {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", d.id, d.severity, d.remediation)
		for _, r := range d.ranges {
			_, _ = fmt.Fprintf(h, "%d.%d.%d\x00", r.major, r.minor, r.fixedPatch)
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// cveRefreshStatus is the audit page's CVE-database status line.
type cveRefreshStatus struct {
	LastSuccessAt time.Time // zero when a live refresh has never succeeded
	LastAttemptAt time.Time // zero when a refresh has never been attempted
	LastError     string    // error of the last attempt, cleared on success
	Live          bool      // whether cve_cache currently holds live (not just seed) rows
}

func getCVERefreshStatus(db *sql.DB) cveRefreshStatus {
	var st cveRefreshStatus
	if db == nil {
		return st
	}
	var successAt, attemptAt, errMsg sql.NullString
	_ = db.QueryRow("SELECT last_success_at, last_attempt_at, last_error FROM cve_meta WHERE id = 1").
		Scan(&successAt, &attemptAt, &errMsg)
	if successAt.Valid {
		if t, e := time.Parse(insightsTimeLayout, successAt.String); e == nil {
			st.LastSuccessAt = t
		}
	}
	if attemptAt.Valid {
		if t, e := time.Parse(insightsTimeLayout, attemptAt.String); e == nil {
			st.LastAttemptAt = t
		}
	}
	st.LastError = errMsg.String
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM cve_cache WHERE source = 'live'").Scan(&count)
	st.Live = count > 0
	return st
}

// refreshCVECache fetches live CVE data and replaces the cached "live" rows.
// On failure it records the error in cve_meta but leaves any existing live
// rows untouched, so a transient outage doesn't revert callers to the
// (potentially much staler) offline fallback.
func refreshCVECache(ctx context.Context, db *sql.DB, nvdAPIKey string) error {
	now := time.Now().Format(insightsTimeLayout)
	defs, err := fetchLiveCVEDefs(ctx, nvdAPIKey)
	if err != nil {
		_, _ = db.Exec(`INSERT INTO cve_meta (id, last_attempt_at, last_error) VALUES (1, ?, ?)
			ON CONFLICT(id) DO UPDATE SET last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error`,
			now, err.Error())
		return err
	}

	tx, txErr := db.Begin()
	if txErr != nil {
		return txErr
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM cve_cache WHERE source = 'live'"); err != nil {
		return err
	}
	for _, def := range defs {
		if _, err := tx.Exec(`INSERT INTO cve_cache (id, summary_en, severity, ranges_json, remediation, source)
			VALUES (?, ?, ?, ?, ?, 'live')`,
			def.id, def.summaryEN, def.severity, encodeRanges(def.ranges), def.remediation); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO cve_meta (id, last_success_at, last_attempt_at, last_error) VALUES (1, ?, ?, '')
		ON CONFLICT(id) DO UPDATE SET last_success_at = excluded.last_success_at, last_attempt_at = excluded.last_attempt_at, last_error = ''`,
		now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// refreshCVECacheJob is the scheduled background refresh: best-effort and
// never fatal. Cached per-firewall audit results pick up the change lazily
// (via CVEFingerprint) the next time each one is actually viewed, so this
// does not force a recompute burst across the whole fleet.
func (s *Server) refreshCVECacheJob() {
	db, err := s.insightsDB()
	if err != nil || db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := refreshCVECache(ctx, db, s.cfg.NVDAPIKey); err != nil {
		s.logger.Warn("scheduled CVE refresh failed", "err", err)
		return
	}
	s.logger.Info("CVE database refreshed", "source", "nvd+cisa-kev")
}

// handleAuditCVERefresh triggers an immediate CVE-cache refresh. Unlike the
// scheduled job this always runs when called, even if CVEAutoUpdate is
// disabled — an explicit operator click is a deliberate override of that
// setting, not something it should silently swallow.
func (s *Server) handleAuditCVERefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	db, err := s.insightsDB()
	if err != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if refreshErr := refreshCVECache(ctx, db, s.cfg.NVDAPIKey); refreshErr != nil {
		s.logger.Warn("manual CVE refresh failed", "err", refreshErr)
	}
	// Findings recompute lazily via CVEFingerprint too, but clearing the cache
	// here matches the existing custom-rule-change convention and gives
	// immediate, consistent results for whichever firewall is opened next.
	_, _ = db.Exec("DELETE FROM audit_cache")
	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}
