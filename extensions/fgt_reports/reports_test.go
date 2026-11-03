package fgt_reports

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

type sourceFixture struct {
	mu      sync.Mutex
	sources []reportmodel.Source
	err     error
}

func (f *sourceFixture) list(context.Context) ([]reportmodel.Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reportmodel.Source(nil), f.sources...), f.err
}
func (f *sourceFixture) set(sources ...reportmodel.Source) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sources = sources
}
func (f *sourceFixture) read(_ context.Context, fw, id int) (reportmodel.Source, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sources {
		if s.FirewallID == fw && s.BackupID == id {
			return s, []byte("configuration"), nil
		}
	}
	return reportmodel.Source{}, nil, sql.ErrNoRows
}

func source(id int) reportmodel.Source {
	return reportmodel.Source{FirewallID: 7, Firewall: "test-firewall", BackupID: id,
		BackupAt: time.Date(2026, 11, 3, 10, 0, id, 0, time.UTC), Checksum: fmt.Sprintf("hash-%d", id)}
}

func testExtension(t *testing.T, f *sourceFixture) *Extension {
	t.Helper()
	cipher, err := crypto.New(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cipher.RequireEncrypted()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := initDB(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	e := New(&config.Config{ExtFgtReports: true, ReportsLanguage: "en"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.db, e.cipher, e.ctx = db, cipher, context.Background()
	e.listSources, e.readSource = f.list, f.read
	e.wake = make(chan struct{}, 1)
	e.analyze = func(context.Context, []byte) (reportmodel.Assessment, error) {
		return reportmodel.Assessment{Complete: true, Firmware: "7.4.7"}, nil
	}
	e.render = func(_ context.Context, s reportmodel.Source, _ reportmodel.Assessment, kind, lang string) ([]byte, error) {
		return []byte(fmt.Sprintf("%%PDF-1.7\nbackup-%d:%s:%s", s.BackupID, kind, lang)), nil
	}
	e.pageBase = func(_ *http.Request, title, active string) webui.BaseData {
		return webui.BaseData{Title: title, Active: active, Lang: "en", Shell: webui.ShellText("en")}
	}
	e.canRead = func(r *http.Request) bool { return r.Header.Get("X-Test-Role") == "operator" }
	return e
}

func claim(t *testing.T, e *Extension) target {
	t.Helper()
	if err := e.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, err := nextTarget(context.Background(), e.db, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func assertPublished(t *testing.T, e *Extension, id int) {
	t.Helper()
	var count, backupID int
	if err := e.db.QueryRow("SELECT COUNT(*),backup_id FROM report_latest").Scan(&count, &backupID); err != nil {
		t.Fatal(err)
	}
	if count != 1 || backupID != id {
		t.Fatalf("published count=%d backup=%d want one backup %d", count, backupID, id)
	}
	for _, column := range []string{"assessment", "forwarding", "technical", "traffic"} {
		var value []byte
		if err := e.db.QueryRow("SELECT " + column + " FROM report_latest WHERE firewall_id=7").Scan(&value); err != nil {
			t.Fatal(err)
		}
		if !crypto.HasHeader(value) {
			t.Fatalf("%s stored unencrypted", column)
		}
		plain, err := e.cipher.Decrypt(value)
		if err != nil {
			t.Fatal(err)
		}
		if column != "assessment" && !strings.Contains(string(plain), fmt.Sprintf("backup-%d:%s", id, column)) {
			t.Fatalf("mixed snapshot: %s", plain)
		}
	}
}

func TestAtomicLatestReplacementRetainsPreviousOnFailure(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	assertPublished(t, e, 1)
	f.set(source(2))
	original := e.render
	e.render = func(ctx context.Context, s reportmodel.Source, a reportmodel.Assessment, kind, lang string) ([]byte, error) {
		if kind == "technical" {
			return nil, errors.New("sensitive renderer diagnostic")
		}
		return original(ctx, s, a, kind, lang)
	}
	e.generate(claim(t, e))
	assertPublished(t, e, 1)
	var status, message string
	if err := e.db.QueryRow("SELECT status,error FROM report_targets WHERE firewall_id=7").Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || message != "rendering" {
		t.Fatalf("status=%q error=%q", status, message)
	}
	e.render = original
	if err := forceRetry(e.ctx, e.db, 7); err != nil {
		t.Fatal(err)
	}
	e.generate(claim(t, e))
	assertPublished(t, e, 2)
	data, err := e.loadData(e.ctx, 7)
	if err != nil || data.Source.BackupID != 2 {
		t.Fatalf("assessment source: %+v %v", data.Source, err)
	}
}

func TestNewerSourceSupersedesInFlightGeneration(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	old := claim(t, e)
	original := e.render
	e.render = func(ctx context.Context, s reportmodel.Source, a reportmodel.Assessment, kind, lang string) ([]byte, error) {
		f.set(source(2))
		return original(ctx, s, a, kind, lang)
	}
	e.generate(old)
	var count int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM report_latest").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("superseded snapshot was published")
	}
	e.render = original
	e.generate(claim(t, e))
	assertPublished(t, e, 2)
	if ok, err := publish(e.ctx, e.db, old, time.Now(), encryptedSet{}); err != nil || ok {
		t.Fatalf("late publication ok=%v err=%v", ok, err)
	}
	assertPublished(t, e, 2)
}

func TestChecksumChangeCannotBeFailedOrPublishedByOldWork(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	old := claim(t, e)
	replacement := source(1)
	replacement.Checksum = "replacement-checksum"
	f.set(replacement)
	newTarget := claim(t, e)
	if err := failTarget(e.ctx, e.db, old, "analysis", time.Now()); err != nil {
		t.Fatal(err)
	}
	var status, checksum string
	if err := e.db.QueryRow("SELECT status,checksum FROM report_targets WHERE firewall_id=7").Scan(&status, &checksum); err != nil {
		t.Fatal(err)
	}
	if status != "running" || checksum != replacement.Checksum {
		t.Fatalf("old failure affected new work: %s %s", status, checksum)
	}
	if ok, err := publish(e.ctx, e.db, old, time.Now(), encryptedSet{}); err != nil || ok {
		t.Fatalf("old checksum publication ok=%v err=%v", ok, err)
	}
	e.generate(newTarget)
	assertPublished(t, e, 1)
}

func TestActualAnalysisAndThreePDFsPublishTogether(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.analyze = nil
	e.render = nil
	e.readSource = func(context.Context, int, int) (reportmodel.Source, []byte, error) {
		return source(1), []byte(`#config-version=FGT60F-7.4.7-FW-build2731
config system global
 set hostname "synthetic-firewall"
end
config firewall address
 edit "Country-A"
  set type geography
  set country "AT"
 next
end
config firewall vip
 edit "Portal"
  set extip 203.0.113.20
  set mappedip "10.10.20.15"
  set extintf "wan1"
  set portforward enable
  set extport 8443
  set mappedport 443
 next
end
config firewall policy
 edit 900
  set srcintf "wan1"
  set dstintf "dmz"
  set srcaddr "Country-A"
  set dstaddr "all"
  set service "HTTPS"
  set schedule "always"
  set action deny
  set match-vip enable
 next
 edit 20
  set srcintf "wan1"
  set dstintf "dmz"
  set srcaddr "all"
  set dstaddr "Portal"
  set service "HTTPS"
  set schedule "always"
  set action accept
  set logtraffic all
 next
end
`), nil
	}
	e.generate(claim(t, e))
	data, err := e.loadData(e.ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Assessment.Exposures) != 1 || data.Assessment.Exposures[0].GeoStatus != "Applicable" {
		t.Fatalf("unexpected assessment: %+v", data.Assessment)
	}
	for _, kind := range []string{"forwarding", "technical", "traffic"} {
		var encrypted []byte
		if err := e.db.QueryRow("SELECT " + kind + " FROM report_latest WHERE firewall_id=7").Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		pdf, err := e.cipher.Decrypt(encrypted)
		if err != nil || len(pdf) < 1000 || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
			t.Fatalf("invalid %s PDF: bytes=%d err=%v", kind, len(pdf), err)
		}
	}
}

func TestReconciliationRecoveryDedupAndRemoval(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	claimed := claim(t, e)
	if claimed.Attempts != 1 {
		t.Fatal("claim not persisted")
	}
	if err := initDB(e.ctx, e.db); err != nil {
		t.Fatal(err)
	}
	e.generate(claim(t, e))
	assertPublished(t, e, 1)
	if err := e.refresh(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := nextTarget(e.ctx, e.db, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("duplicate work: %v", err)
	}
	// Content can be unchanged: a new successful backup still gets fresh provenance.
	newSource := source(2)
	newSource.Checksum = source(1).Checksum
	f.set(newSource)
	e.generate(claim(t, e))
	assertPublished(t, e, 2)
	// Repeated old notifications cannot roll back a target or published set.
	if err := reconcile(e.ctx, e.db, []reportmodel.Source{source(1)}, e.generation()); err != nil {
		t.Fatal(err)
	}
	if _, err := nextTarget(e.ctx, e.db, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("older source queued")
	}
	f.set(newSource)
	e.cfg.ReportsLanguage = "de"
	e.generate(claim(t, e))
	assertPublished(t, e, 2)
	// Removal is cascaded; no historical PDF or assessment rows remain.
	f.set()
	if err := e.refresh(e.ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"report_targets", "report_latest"} {
		var count int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
}

func TestCatalogFailureNeverPrunesExistingReports(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	f.mu.Lock()
	f.err = errors.New("database unavailable")
	f.sources = nil
	f.mu.Unlock()
	if err := e.refresh(e.ctx); err == nil {
		t.Fatal("catalog failure ignored")
	}
	assertPublished(t, e, 1)
}

func TestWorkerPanicIsContainedAndPreviousReportSurvives(t *testing.T) {
	for _, stage := range []string{"analysis", "rendering"} {
		t.Run(stage, func(t *testing.T) {
			f := &sourceFixture{}
			f.set(source(1))
			e := testExtension(t, f)
			e.generate(claim(t, e))
			f.set(source(2))
			if stage == "analysis" {
				e.analyze = func(context.Context, []byte) (reportmodel.Assessment, error) { panic("untrusted secret") }
			} else {
				e.render = func(context.Context, reportmodel.Source, reportmodel.Assessment, string, string) ([]byte, error) {
					panic("untrusted secret")
				}
			}
			e.generate(claim(t, e))
			assertPublished(t, e, 1)
			var status, message string
			if err := e.db.QueryRow("SELECT status,error FROM report_targets WHERE firewall_id=7").Scan(&status, &message); err != nil {
				t.Fatal(err)
			}
			if status != "failed" || message != stage {
				t.Fatalf("status=%s stage=%s", status, message)
			}
		})
	}
}

func TestRetryBudgetDoesNotResetOnReconciliation(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.analyze = func(context.Context, []byte) (reportmodel.Assessment, error) {
		return reportmodel.Assessment{}, errors.New("bad config")
	}
	for i := 1; i <= 3; i++ {
		if err := e.refresh(e.ctx); err != nil {
			t.Fatal(err)
		}
		target, err := nextTarget(e.ctx, e.db, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		e.generate(target)
	}
	if err := e.refresh(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := nextTarget(e.ctx, e.db, time.Now().Add(time.Hour)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("retry budget ignored: %v", err)
	}
}

func reportRouter(e *Extension) http.Handler {
	r := chi.NewRouter()
	r.Use(e.authorized)
	r.Get("/reports/{firewallID}/data", e.data)
	r.Get("/reports/{firewallID}/{kind}.pdf", e.download)
	r.Post("/reports/{firewallID}/regenerate", e.regenerate)
	return r
}

func TestReportReadAuthorizationAndDeletedFirewall(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	router := reportRouter(e)
	for _, path := range []string{"/reports/7/data", "/reports/7/technical.pdf", "/reports/7/forwarding.pdf", "/reports/7/traffic.pdf"} {
		for _, role := range []string{"", "viewer", "operator"} {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("X-Test-Role", role)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			want := http.StatusForbidden
			if role == "operator" {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("%s role %q=%d want %d", path, role, w.Code, want)
			}
			if role == "operator" && w.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("sensitive cache header missing")
			}
		}
	}
	f.set() // Before the background worker has pruned its private store.
	r := httptest.NewRequest(http.MethodGet, "/reports/7/technical.pdf", nil)
	r.Header.Set("X-Test-Role", "operator")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("deleted firewall downloadable: %d", w.Code)
	}
}

func TestTemplatesEscapeConfigurationAndRenderBothLocales(t *testing.T) {
	for _, lang := range []string{"en", "de"} {
		page, err := webui.ParsePage(assets, "templates/detail.html", map[string]any{"R": reportText})
		if err != nil {
			t.Fatal(err)
		}
		view := detailData{Base: webui.BaseData{Lang: lang}, Report: reportData{Source: source(1), Assessment: reportmodel.Assessment{
			Exposures: []reportmodel.Exposure{{Name: `<script>alert("x")</script>`, Trace: []reportmodel.PolicyTrace{{ID: "900", Sequence: 1}}}},
		}}}
		var output bytes.Buffer
		if err := page.Render(&output, view); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), `<script>alert`) {
			t.Fatal("config name rendered as markup")
		}
		if !strings.Contains(output.String(), "&lt;script&gt;") {
			t.Fatal("escaped name not present")
		}
		page, err = webui.ParsePage(assets, "templates/index.html", map[string]any{"R": reportText})
		if err != nil {
			t.Fatal(err)
		}
		if err := page.Render(io.Discard, indexData{Base: webui.BaseData{Lang: lang}, Rows: []reportRow{{FirewallID: 7, Ready: true, Status: "failed", Error: "rendering", Stale: true}}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMountBackfillsAndCommittedBackupTriggersReplacement(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	base := testExtension(t, f)
	e := New(base.cfg, base.logger)
	e.analyze, e.render = base.analyze, base.render
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observer func(models.Backup)
	router := chi.NewRouter()
	var err error
	router.Route("/reports", func(r chi.Router) {
		err = e.Mount(r, extension.Deps{
			Context: ctx, DataDir: t.TempDir(), Cipher: base.cipher, PageBase: base.pageBase,
			LoginRequired: func(h http.Handler) http.Handler { return h }, CanReadReports: base.canRead,
			ListReportSources: f.list, ReadReportSource: f.read, SubscribeBackup: func(fn func(models.Backup)) { observer = fn },
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		select {
		case <-e.done:
		case <-time.After(5 * time.Second):
			t.Error("report worker did not stop")
		}
	}()
	waitBackup := func(id int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var got int
			err := e.db.QueryRow("SELECT backup_id FROM report_latest WHERE firewall_id=7").Scan(&got)
			if err == nil && got == id {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("backup %d never published", id)
	}
	waitBackup(1)
	f.set(source(2))
	observer(models.Backup{ID: 2, FwID: 7, Timestamp: source(2).BackupAt, Checksum: source(2).Checksum})
	waitBackup(2)
	assertPublished(t, e, 2)
	paths := []string{"/reports/", "/reports/catalog", "/reports/calendar", "/reports/7", "/reports/7/profile", "/reports/7/profile.json", "/reports/static/reports.css"}
	for _, kind := range []string{"forwarding", "technical", "traffic"} {
		for _, format := range []string{"pdf", "html", "csv", "json", "xml"} {
			paths = append(paths, "/reports/7/"+kind+"."+format)
		}
	}
	for _, path := range paths {
		for _, role := range []string{"viewer", "operator"} {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("X-Test-Role", role)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			want := http.StatusForbidden
			if role == "operator" {
				want = http.StatusOK
			}
			if response.Code != want {
				t.Fatalf("mounted %s role %q status=%d want=%d", path, role, response.Code, want)
			}
			if path == "/reports/7/profile.json" && role == "operator" && !strings.Contains(response.Body.String(), profileFormat) {
				t.Fatal("dynamic report export shadowed the profile export route")
			}
		}
	}
	for _, operation := range []string{"profile", "profile/import", "profile/copy", "profile/reset", "regenerate"} {
		request := httptest.NewRequest(http.MethodPost, "/reports/7/"+operation, nil)
		request.Header.Set("X-Test-Role", "viewer")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("viewer reached report mutation %s: %d", operation, response.Code)
		}
	}
	for _, format := range []string{"pdf", "html", "csv", "json", "xml"} {
		request := httptest.NewRequest(http.MethodGet, "/reports/7/customer."+format, nil)
		request.Header.Set("X-Test-Role", "operator")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired customer report still served as %s: %d", format, response.Code)
		}
	}
}
