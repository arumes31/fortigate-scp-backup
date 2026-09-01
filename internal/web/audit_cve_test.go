package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openCVETestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cve.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, query := range []string{
		`CREATE TABLE cve_cache (id TEXT PRIMARY KEY, summary_en TEXT NOT NULL, severity TEXT NOT NULL,
			ranges_json TEXT NOT NULL, remediation TEXT NOT NULL, source TEXT NOT NULL)`,
		`CREATE TABLE cve_meta (id INTEGER PRIMARY KEY CHECK (id = 1), last_success_at TEXT,
			last_attempt_at TEXT, last_error TEXT)`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestLoadCVEDefsUsesDeterministicIDOrder(t *testing.T) {
	db := openCVETestDB(t)
	for _, id := range []string{"CVE-2099-0002", "CVE-2099-0001"} {
		if _, err := db.Exec(`INSERT INTO cve_cache
			(id, summary_en, severity, ranges_json, remediation, source)
			VALUES (?, 'summary', 'warning', ?, 'upgrade', 'live')`, id, encodeRanges(nil)); err != nil {
			t.Fatal(err)
		}
	}

	defs := loadCVEDefs(db)
	for index := 1; index < len(defs); index++ {
		if defs[index-1].id >= defs[index].id {
			t.Fatalf("CVE order = %+v, want ascending stable IDs", defs)
		}
	}
}

func TestLoadCVEDefsRetainsFallbackAcrossLiveRefreshes(t *testing.T) {
	db := openCVETestDB(t)
	seedCVECacheIfEmpty(db)
	fallback := cveFallbackDefs[0]
	live := fallback
	live.summaryEN = "live definition"
	if err := refreshCVECacheWithFetcher(t.Context(), db, "", func(context.Context, string) ([]cveDef, error) {
		return []cveDef{live}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := findCVEDef(t, loadCVEDefs(db), fallback.id); got.summaryEN != live.summaryEN {
		t.Fatalf("loaded summary = %q, want live summary %q", got.summaryEN, live.summaryEN)
	}

	if err := refreshCVECacheWithFetcher(t.Context(), db, "", func(context.Context, string) ([]cveDef, error) {
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := findCVEDef(t, loadCVEDefs(db), fallback.id); got.summaryEN != fallback.summaryEN {
		t.Fatalf("loaded summary = %q, want restored fallback summary %q", got.summaryEN, fallback.summaryEN)
	}
}

func findCVEDef(t *testing.T, defs []cveDef, id string) cveDef {
	t.Helper()
	for _, def := range defs {
		if def.id == id {
			return def
		}
	}
	t.Fatalf("CVE %q not found in %+v", id, defs)
	return cveDef{}
}

func TestRefreshCVECachePromotesExistingFallbackIDToLive(t *testing.T) {
	db := openCVETestDB(t)
	if _, err := db.Exec(`INSERT INTO cve_cache
		(id, summary_en, severity, ranges_json, remediation, source)
		VALUES ('CVE-2099-0001', 'old', 'warning', ?, 'old remediation', 'fallback-seed')`, encodeRanges(nil)); err != nil {
		t.Fatal(err)
	}
	fetch := func(context.Context, string) ([]cveDef, error) {
		return []cveDef{{
			id: "CVE-2099-0001", summaryEN: "new", severity: "critical",
			remediation: "new remediation", ranges: []cveRange{{major: 7, minor: 4, fixedPatch: 3}},
		}}, nil
	}

	if err := refreshCVECacheWithFetcher(t.Context(), db, "", fetch); err != nil {
		t.Fatal(err)
	}
	var summary, severity, remediation, source string
	if err := db.QueryRow(`SELECT summary_en, severity, remediation, source FROM cve_cache WHERE id = 'CVE-2099-0001'`).
		Scan(&summary, &severity, &remediation, &source); err != nil {
		t.Fatal(err)
	}
	if summary != "new" || severity != "critical" || remediation != "new remediation" || source != "live" {
		t.Fatalf("stored row = %q/%q/%q/%q", summary, severity, remediation, source)
	}
}

func TestRefreshCVECacheRecordsStorageFailure(t *testing.T) {
	db := openCVETestDB(t)
	if _, err := db.Exec(`INSERT INTO cve_cache
		(id, summary_en, severity, ranges_json, remediation, source)
		VALUES ('CVE-OLD', 'old', 'warning', ?, 'old remediation', 'live')`, encodeRanges(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_live_delete BEFORE DELETE ON cve_cache
		WHEN OLD.source = 'live' BEGIN SELECT RAISE(FAIL, 'forced live delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	fetch := func(context.Context, string) ([]cveDef, error) {
		return []cveDef{{id: "CVE-NEW", summaryEN: "new", severity: "warning", remediation: "upgrade"}}, nil
	}

	err := refreshCVECacheWithFetcher(t.Context(), db, "", fetch)
	if err == nil || !strings.Contains(err.Error(), "forced live delete failure") {
		t.Fatalf("refresh error = %v", err)
	}
	status := getCVERefreshStatus(db)
	if status.LastAttemptAt.IsZero() || !strings.Contains(status.LastError, "forced live delete failure") {
		t.Fatalf("refresh status = %+v", status)
	}
}

func TestHandleAuditCVERefreshRunsInBackgroundWithScheduledTimeout(t *testing.T) {
	srv := testServer(t)
	srv.cfg.DataDir = t.TempDir()
	t.Cleanup(func() {
		srv.Shutdown()
		if srv.insights != nil {
			_ = srv.insights.Close()
		}
	})
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	srv.cveRefresh = func(ctx context.Context, _ *sql.DB, _ string) error {
		started <- ctx
		<-release
		close(done)
		return errors.New("store failed")
	}
	recorder := httptest.NewRecorder()

	srv.handleAuditCVERefresh(recorder, httptest.NewRequest(http.MethodPost, "/audit/cve_refresh", nil))

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	var refreshCtx context.Context
	select {
	case refreshCtx = <-started:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not start")
	}
	deadline, ok := refreshCtx.Deadline()
	if !ok {
		t.Fatal("background refresh has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining < cveRefreshTimeout-time.Second || remaining > cveRefreshTimeout+time.Second {
		t.Fatalf("refresh deadline remaining = %v, want about %v", remaining, cveRefreshTimeout)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not finish")
	}
	srv.cveRefreshWG.Wait()
}
