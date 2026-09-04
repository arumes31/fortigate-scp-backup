package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestConfigDiffReportsAddedRemovedAndUnchangedLines(t *testing.T) {
	t.Parallel()
	rows, err := configSideBySideDiff([]string{"one", "remove", "three"}, []string{"one", "add", "three"})
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]string, 0, len(rows))
	for _, row := range rows {
		kinds = append(kinds, row.Kind)
	}
	if strings.Join(kinds, ",") != "unchanged,removed,added,unchanged" {
		t.Fatalf("diff kinds = %v", kinds)
	}
}

func TestHandleBackupCompareScopesIDsEscapesOutputAndLogsMetadata(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	srv.cfg.BackupDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(srv.cfg.BackupDir, "7"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"left.conf":  "config system test\nset value old\nend\n",
		"right.conf": "config system test\nset value <script>alert(1)</script>\nend\n",
	} {
		if err := os.WriteFile(filepath.Join(srv.cfg.BackupDir, "7", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var activity []string
	srv.store = fakeStore{
		firewalls: []models.Firewall{{ID: 7, FQDN: "edge.example.test"}}, activity: &activity,
		backups: []models.Backup{
			{ID: 1, FwID: 7, Filename: "7/left.conf", Timestamp: time.Now()},
			{ID: 2, FwID: 7, Filename: "7/right.conf", Timestamp: time.Now()},
			{ID: 99, FwID: 8, Filename: "8/foreign.conf", Timestamp: time.Now()},
		},
	}
	router := chi.NewRouter()
	router.Get("/backups/{fwID}/compare", srv.handleBackupCompare)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/backups/7/compare?backup=1&backup=2", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("compare status = %d body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert") {
		t.Fatalf("diff output was not escaped: %s", body)
	}
	if len(activity) != 1 || !strings.Contains(activity[0], "fw_id=7 backup_ids=1,2") || strings.Contains(activity[0], "left.conf") {
		t.Fatalf("comparison activity = %#v", activity)
	}

	foreign := httptest.NewRecorder()
	router.ServeHTTP(foreign, httptest.NewRequest(http.MethodGet, "/backups/7/compare?backup=1&backup=99", nil))
	if foreign.Code != http.StatusBadRequest {
		t.Fatalf("foreign backup status = %d, want 400", foreign.Code)
	}
}

func TestHandleBackupCompareRejectsInvalidSelection(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	router := chi.NewRouter()
	router.Get("/backups/{fwID}/compare", srv.handleBackupCompare)
	for _, target := range []string{
		"/backups/7/compare?backup=1",
		"/backups/7/compare?backup=1&backup=1",
		"/backups/7/compare?backup=1&backup=two",
		"/backups/7/compare?backup=1&backup=2&backup=3",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s status = %d", target, response.Code)
		}
	}
}

func TestConfigDiffEnforcesLineAndWorkLimits(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	srv.cfg.BackupDir = t.TempDir()
	lines := strings.Repeat("set value synthetic\n", configDiffMaxLines+20)
	path := filepath.Join(srv.cfg.BackupDir, "bounded.conf")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	got, truncated, err := srv.readComparisonBackup(models.Backup{Filename: "bounded.conf"})
	if err != nil || !truncated || len(got) != configDiffMaxLines {
		t.Fatalf("bounded comparison read = %d lines truncated=%t err=%v", len(got), truncated, err)
	}
	if _, err := configSideBySideDiff(make([]string, configDiffMaxLines+1), make([]string, configDiffMaxLines)); err == nil {
		t.Fatal("comparison accepted work above the configured limit")
	}
}
