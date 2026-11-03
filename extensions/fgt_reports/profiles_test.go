package fgt_reports

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

func TestProfileReplacementIsAtomicAndEncrypted(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	original, err := e.getProfile(e.ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	edited := original.Profile
	edited.Name, edited.Customer, edited.Language = "Customer-specific review", "Private customer marker", "de"
	if err := e.saveProfile(e.ctx, source(1), edited, reportmodel.ProfileHash(original.Profile), false); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err := e.db.QueryRow("SELECT document FROM report_profiles WHERE firewall_id=7").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(edited.Customer)) || bytes.Contains(encrypted, []byte(edited.Name)) {
		t.Fatal("profile text was stored without encryption")
	}
	before, err := e.loadData(e.ctx, 7)
	if err != nil || before.Profile.Name == edited.Name {
		t.Fatalf("profile edit replaced the published snapshot before successful rendering: %v", err)
	}
	e.generate(claim(t, e))
	after, err := e.loadData(e.ctx, 7)
	if err != nil || after.Profile.Name != edited.Name || after.Language != "de" {
		t.Fatalf("published profile missing: %#v %v", after.Profile, err)
	}
	assertPublished(t, e, 1)
	if err := e.saveProfile(e.ctx, source(1), original.Profile, reportmodel.ProfileHash(original.Profile), false); !errors.Is(err, errProfileConflict) {
		t.Fatalf("stale editor silently overwrote the newer profile: %v", err)
	}
}

func TestProfileEditDuringRenderingSupersedesOldGeneration(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	f.set(source(2))
	target := claim(t, e)
	changed := false
	e.renderProfile = func(_ context.Context, _ reportmodel.Source, _ reportmodel.Assessment, _ string, p reportmodel.Profile) ([]byte, error) {
		if !changed {
			changed = true
			p.Name = "Edited while rendering"
			if err := e.saveProfile(e.ctx, source(2), p, "", false); err != nil {
				t.Fatal(err)
			}
		}
		return []byte("%PDF-1.7\nprofile-test"), nil
	}
	e.generate(target)
	assertPublished(t, e, 1)
	e.renderProfile = nil
	e.generate(claim(t, e))
	assertPublished(t, e, 2)
	data, err := e.loadData(e.ctx, 7)
	if err != nil || data.Profile.Name != "Edited while rendering" {
		t.Fatalf("stale profile won publication: %v", err)
	}
}

func TestTelemetryFailurePreservesPreviousCompleteSet(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	f.set(source(2))
	e.collectTelemetry = func(context.Context, reportmodel.Source, reportmodel.Assessment, reportmodel.Profile, time.Time) reportmodel.Telemetry {
		return reportmodel.Telemetry{Status: "error", Reason: "remote diagnostics must not enter job errors"}
	}
	e.generate(claim(t, e))
	assertPublished(t, e, 1)
	var stage string
	if err := e.db.QueryRow("SELECT error FROM report_targets WHERE firewall_id=7").Scan(&stage); err != nil || stage != "telemetry" {
		t.Fatalf("safe telemetry failure stage missing: %q %v", stage, err)
	}
}

func TestSchedulesPinOccurrenceAndProfileRevision(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	p := reportmodel.DefaultProfile("en")
	p.Schedule = reportmodel.Schedule{Frequency: "daily", Timezone: "UTC", Hour: 3, MonthDay: 1}
	if err := e.saveProfile(e.ctx, source(1), p, "", false); err != nil {
		t.Fatal(err)
	}
	e.generate(claim(t, e))
	now := time.Date(2026, 11, 3, 3, 1, 0, 0, time.UTC)
	due := now.Add(-time.Minute)
	if _, err := e.db.Exec("UPDATE report_profiles SET next_due_ns=? WHERE firewall_id=7", due.UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := e.enqueueScheduled(e.ctx, now); err != nil {
		t.Fatal(err)
	}
	job, err := nextTarget(e.ctx, e.db, now)
	if err != nil {
		t.Fatal("due report was not queued", err)
	}
	e.generate(job)
	if err := e.enqueueScheduled(e.ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := nextTarget(e.ctx, e.db, now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("same schedule occurrence was queued twice")
	}
	oldGeneration := profileGeneration(p)
	p.Name = "New profile revision"
	if err := e.saveProfile(e.ctx, source(1), p, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec("UPDATE report_profiles SET next_due_ns=? WHERE firewall_id=7", due.UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := e.enqueueOccurrence(e.ctx, 7, due, now.Add(24*time.Hour), now, oldGeneration); err != nil {
		t.Fatal(err)
	}
	var actual int64
	if err := e.db.QueryRow("SELECT next_due_ns FROM report_profiles WHERE firewall_id=7").Scan(&actual); err != nil || actual != due.UnixNano() {
		t.Fatal("old schedule snapshot overwrote the edited profile occurrence", err)
	}
}

func TestCalendarUsesWallClockAndClampsShortMonths(t *testing.T) {
	for _, tc := range []struct {
		name        string
		schedule    reportmodel.Schedule
		after, want string
	}{
		{"daily", reportmodel.Schedule{Frequency: "daily", Timezone: "UTC", Hour: 3, MonthDay: 1}, "2026-11-03T03:00:00Z", "2026-11-04T03:00:00Z"},
		{"monthly", reportmodel.Schedule{Frequency: "monthly", Timezone: "UTC", Hour: 3, MonthDay: 31}, "2026-01-31T04:00:00Z", "2026-02-28T03:00:00Z"},
		{"DST", reportmodel.Schedule{Frequency: "daily", Timezone: "Europe/Vienna", Hour: 9, MonthDay: 1}, "2026-03-28T09:00:00Z", "2026-03-29T07:00:00Z"},
		{"weekly", reportmodel.Schedule{Frequency: "weekly", Timezone: "UTC", Hour: 10, Weekday: 1, MonthDay: 1}, "2026-11-03T10:00:00Z", "2026-11-09T10:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after, _ := time.Parse(time.RFC3339, tc.after)
			got, err := nextScheduledRun(tc.schedule, after)
			if err != nil || got.Format(time.RFC3339) != tc.want {
				t.Fatalf("next=%s error=%v want=%s", got, err, tc.want)
			}
		})
	}
}

func profileTestRouter(t *testing.T, e *Extension) http.Handler {
	t.Helper()
	var err error
	e.profilePage, err = webui.ParsePage(assets, "templates/profile.html", template.FuncMap{"R": reportText})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(e.authorized)
	r.Get("/reports/{firewallID}/profile.json", e.exportProfile)
	r.Get("/reports/{firewallID}/profile", e.profile)
	r.Post("/reports/{firewallID}/profile", e.updateProfile)
	r.Post("/reports/{firewallID}/profile/import", e.importProfile)
	r.Get("/reports/{firewallID}/{kind}.json", e.exportJSON)
	return r
}

func TestProfileImportAuthorizationAndCapturedExport(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	router := profileTestRouter(t, e)
	p := reportmodel.DefaultProfile("en")
	p.Name = "Imported definition"
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("profile_file", "profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(part).Encode(profileDocument{Format: profileFormat, Profile: p}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"viewer", "operator"} {
		request := httptest.NewRequest(http.MethodPost, "/reports/7/profile/import", bytes.NewReader(body.Bytes()))
		request.Header.Set("Content-Type", writer.FormDataContentType())
		request.Header.Set("X-Test-Role", role)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		want := http.StatusForbidden
		if role == "operator" {
			want = http.StatusSeeOther
		}
		if response.Code != want {
			t.Fatalf("role=%s status=%d body=%s", role, response.Code, response.Body.String())
		}
	}
	e.generate(claim(t, e))
	for _, path := range []string{"/reports/7/profile.json", "/reports/7/technical.json"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("X-Test-Role", "operator")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) || response.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("export %s failed: %d %s", path, response.Code, response.Body.String())
		}
	}
	// Form errors preserve the draft while retaining the saved revision guard.
	form := url.Values{"name": {"Draft name kept"}, "accent": {"invalid"}, "language": {"en"}, "orientation": {"portrait"}, "frequency": {"on_backup"}, "timezone": {"UTC"}, "hour": {"3"}, "minute": {"0"}, "weekday": {"1"}, "month_day": {"1"}}
	request := httptest.NewRequest(http.MethodPost, "/reports/7/profile", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Test-Role", "operator")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Draft name kept") || !strings.Contains(response.Body.String(), reportmodel.ProfileHash(p)) {
		t.Fatalf("invalid edit lost its draft/revision: %d", response.Code)
	}
}

func TestStoreMigrationRemovesCustomerAndPreservesSupportedReports(t *testing.T) {
	for _, withTraffic := range []bool{false, true} {
		name := "before traffic reports"
		if withTraffic {
			name = "with traffic reports"
		}
		t.Run(name, func(t *testing.T) {
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			db.SetMaxOpenConns(1)
			legacy := strings.Replace(reportSchema, " technical BLOB NOT NULL,", " technical BLOB NOT NULL,\n customer BLOB NOT NULL,", 1)
			if !withTraffic {
				legacy = strings.Replace(legacy, ",\n traffic BLOB NOT NULL DEFAULT X''", "", 1)
			}
			if _, err := db.Exec(legacy); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO report_targets(firewall_id,backup_id,backup_ns,checksum,generation,status)
 VALUES(7,1,1,'digest','2:en','ready')`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO report_latest(firewall_id,backup_id,backup_ns,generated_ns,generation,checksum,limited,assessment,forwarding,technical,customer)
 VALUES(7,1,1,2,'2:en','digest',0,?,?,?,?)`, []byte("old assessment"), []byte("old forwarding"), []byte("old technical"), []byte("old customer")); err != nil {
				t.Fatal(err)
			}
			wantTraffic := ""
			if withTraffic {
				wantTraffic = "old traffic"
				if _, err := db.Exec("UPDATE report_latest SET traffic=?", []byte(wantTraffic)); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := initDB(context.Background(), db); err != nil {
					t.Fatal("migration must succeed and be idempotent", err)
				}
			}
			var assessment, traffic, forwarding, technical []byte
			if err := db.QueryRow("SELECT assessment,traffic,forwarding,technical FROM report_latest WHERE firewall_id=7").Scan(&assessment, &traffic, &forwarding, &technical); err != nil {
				t.Fatal(err)
			}
			if string(assessment) != "old assessment" || string(traffic) != wantTraffic || string(forwarding) != "old forwarding" || string(technical) != "old technical" {
				t.Fatal("migration removed or rewrote a supported report")
			}
			var retiredColumns int
			if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('report_latest') WHERE name='customer'").Scan(&retiredColumns); err != nil || retiredColumns != 0 {
				t.Fatalf("retired report column retained: %d %v", retiredColumns, err)
			}
			var secureDelete int
			if err := db.QueryRow("PRAGMA secure_delete").Scan(&secureDelete); err != nil || secureDelete != 1 {
				t.Fatalf("retired reports must be removed with secure_delete enabled: %d %v", secureDelete, err)
			}
		})
	}
}

func TestReportVersionUpgradeRegeneratesExistingBackup(t *testing.T) {
	f := &sourceFixture{}
	f.set(source(1))
	e := testExtension(t, f)
	e.generate(claim(t, e))
	legacyGeneration := "2:" + reportmodel.ProfileHash(reportmodel.DefaultProfile("en"))
	if _, err := e.db.Exec("UPDATE report_targets SET generation=?", legacyGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec("UPDATE report_latest SET generation=?", legacyGeneration); err != nil {
		t.Fatal(err)
	}
	job := claim(t, e)
	if job.BackupID != 1 || job.Generation == legacyGeneration {
		t.Fatal("version upgrade did not queue the existing latest backup")
	}
	assertPublished(t, e, 1)
	e.generate(job)
	assertPublished(t, e, 1)
	var generation string
	if err := e.db.QueryRow("SELECT generation FROM report_latest WHERE firewall_id=7").Scan(&generation); err != nil || generation != job.Generation {
		t.Fatalf("upgraded set did not replace the old generation: %q %v", generation, err)
	}
	if _, err := nextTarget(e.ctx, e.db, time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unchanged source was queued again after regeneration: %v", err)
	}
}

func TestSerializationBudgetRejectsAmplificationBeforeMarshal(t *testing.T) {
	large := strings.Repeat("x", 16<<10)
	traces := make([]reportmodel.PolicyTrace, 1024)
	for i := range traces {
		traces[i].Action = large
	}
	data := reportData{Assessment: reportmodel.Assessment{Exposures: []reportmodel.Exposure{{Trace: traces}}}}
	if !errors.Is(checkReportDataBudget(context.Background(), data), errReportDataLimit) {
		t.Fatal("repeated shared strings could allocate an oversized JSON buffer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(checkReportDataBudget(ctx, reportData{}), context.Canceled) {
		t.Fatal("serialization preflight ignored cancellation")
	}
}
