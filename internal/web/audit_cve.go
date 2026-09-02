package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// This file is the storage/orchestration layer for CVE data: the cve_cache /
// cve_meta tables, converting between cveDef and its JSON-storable form, and
// refreshing the cache from the live sources in cve_source.go. See
// cveFallbackDefs (audit_checks.go) for the offline-only safety net this
// backs onto when a live fetch has never succeeded.

// cveDefsSchema versions the cve_cache storage shape (most importantly
// ranges_json / cveRangeJSON). Bump on any incompatible change: stored rows
// in an older shape would otherwise decode to zero values and CVE matching
// would silently stop finding anything — permanently on offline installs,
// whose fallback-seed rows are only ever written when the table is empty.
const cveDefsSchema = 1

const cveRefreshTimeout = 2 * time.Minute

// ensureCVEDefsSchema wipes every stored CVE row (live and seed) when the
// storage shape changed, so seedCVECacheIfEmpty re-seeds the fallback set in
// the current shape and the next scheduled/manual refresh restores the live
// rows. Matching keeps working off the fresh seed in the meantime, and the
// changed dataset flips cveFingerprint, which recomputes cached audits.
func ensureCVEDefsSchema(db *sql.DB) {
	var stored int
	_ = db.QueryRow("SELECT COALESCE(defs_schema, 0) FROM cve_meta WHERE id = 1").Scan(&stored)
	if stored == cveDefsSchema {
		return
	}
	_, _ = db.Exec("DELETE FROM cve_cache")
	_, _ = db.Exec(`INSERT INTO cve_meta (id, defs_schema) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET defs_schema = excluded.defs_schema`, cveDefsSchema)
}

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

// loadCVEDefs combines live (NVD+KEV) rows with the offline fallback seed,
// preferring live definitions when the same CVE exists in both datasets.
func loadCVEDefs(db *sql.DB) []cveDef {
	if db == nil {
		return cveFallbackDefs
	}
	liveDefs := queryCVEDefs(db, "SELECT id, summary_en, severity, ranges_json, remediation FROM cve_cache WHERE source = 'live' ORDER BY id")
	byID := make(map[string]cveDef, len(cveFallbackDefs)+len(liveDefs))
	// A live refresh promotes overlapping seed rows because cve_cache is keyed
	// by ID. Keep the compiled seed as the canonical fallback so a later refresh
	// that omits that ID cannot remove its offline definition.
	for _, def := range cveFallbackDefs {
		byID[def.id] = def
	}
	for _, def := range liveDefs {
		byID[def.id] = def
	}
	defs := make([]cveDef, 0, len(byID))
	for _, def := range byID {
		defs = append(defs, def)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].id < defs[j].id })
	return defs
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
	return refreshCVECacheWithFetcher(ctx, db, nvdAPIKey, fetchLiveCVEDefs)
}

func refreshCVECacheWithFetcher(
	ctx context.Context,
	db *sql.DB,
	nvdAPIKey string,
	fetch func(context.Context, string) ([]cveDef, error),
) (retErr error) {
	now := time.Now().Format(insightsTimeLayout)
	defer func() {
		if retErr == nil {
			return
		}
		if metaErr := recordCVERefreshFailure(db, now, retErr); metaErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("record CVE refresh failure: %w", metaErr))
		}
	}()

	defs, err := fetch(ctx, nvdAPIKey)
	if err != nil {
		return err
	}

	tx, txErr := db.BeginTx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("begin CVE refresh transaction: %w", txErr)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM cve_cache WHERE source = 'live'"); err != nil {
		return fmt.Errorf("delete cached live CVEs: %w", err)
	}
	for _, def := range defs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cve_cache (id, summary_en, severity, ranges_json, remediation, source)
			VALUES (?, ?, ?, ?, ?, 'live')
			ON CONFLICT(id) DO UPDATE SET
				summary_en = excluded.summary_en,
				severity = excluded.severity,
				ranges_json = excluded.ranges_json,
				remediation = excluded.remediation,
				source = excluded.source`,
			def.id, def.summaryEN, def.severity, encodeRanges(def.ranges), def.remediation); err != nil {
			return fmt.Errorf("store live CVE %s: %w", def.id, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cve_meta (id, last_success_at, last_attempt_at, last_error) VALUES (1, ?, ?, '')
		ON CONFLICT(id) DO UPDATE SET last_success_at = excluded.last_success_at, last_attempt_at = excluded.last_attempt_at, last_error = ''`,
		now, now); err != nil {
		return fmt.Errorf("record CVE refresh success: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit CVE refresh: %w", err)
	}
	return nil
}

func recordCVERefreshFailure(db *sql.DB, attemptedAt string, refreshErr error) error {
	_, err := db.Exec(`INSERT INTO cve_meta (id, last_attempt_at, last_error) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error`,
		attemptedAt, refreshErr.Error())
	return err
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
	if !s.beginCVERefresh() {
		return
	}
	defer s.endCVERefresh()
	ctx, cancel := context.WithTimeout(s.cveRefreshContext(), cveRefreshTimeout)
	defer cancel()
	if err := s.runCVERefresh(ctx, db); err != nil {
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
	if s.beginCVERefresh() {
		go func() {
			defer s.endCVERefresh()
			ctx, cancel := context.WithTimeout(s.cveRefreshContext(), cveRefreshTimeout)
			defer cancel()
			if refreshErr := s.runCVERefresh(ctx, db); refreshErr != nil {
				s.logger.Warn("manual CVE refresh failed", "err", refreshErr)
				return
			}
			// Findings recompute lazily via CVEFingerprint too, but clearing the
			// cache gives immediate results for the next firewall that is opened.
			if _, clearErr := db.ExecContext(ctx, "DELETE FROM audit_cache"); clearErr != nil {
				s.logger.Warn("clear audit cache after CVE refresh", "err", clearErr)
			}
		}()
	}
	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

func (s *Server) runCVERefresh(ctx context.Context, db *sql.DB) error {
	refresh := s.cveRefresh
	if refresh == nil {
		refresh = refreshCVECache
	}
	return refresh(ctx, db, s.cfg.NVDAPIKey)
}

func (s *Server) beginCVERefresh() bool {
	s.cveRefreshMu.Lock()
	defer s.cveRefreshMu.Unlock()
	if s.cveRefreshActive || s.cveRefreshStopping {
		return false
	}
	s.cveRefreshActive = true
	s.cveRefreshWG.Add(1)
	return true
}

func (s *Server) endCVERefresh() {
	s.cveRefreshMu.Lock()
	s.cveRefreshActive = false
	s.cveRefreshMu.Unlock()
	s.cveRefreshWG.Done()
}

func (s *Server) cveRefreshContext() context.Context {
	if s.cveRefreshCtx != nil {
		return s.cveRefreshCtx
	}
	return context.Background()
}
