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

func TestHandleListBackupsRendersFirewallChecksumAndIDOnlyComparison(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	srv.store = fakeStore{
		firewalls: []models.Firewall{{ID: 7, FQDN: "edge.example.test"}},
		backups: []models.Backup{
			{ID: 11, FwID: 7, Timestamp: time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC), Filename: "edge/backup-11.conf", SizeBytes: 42, Checksum: strings.Repeat("a", 64)},
			{ID: 12, FwID: 7, Timestamp: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), Filename: "edge/backup-12.conf"},
		},
	}
	router := chi.NewRouter()
	router.Get("/backups/{fwID}", srv.handleListBackups)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/backups/7", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("backup page status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{
		"edge.example.test", "#7", strings.Repeat("a", 64), "Not recorded",
		`action="/backups/7/compare"`, `name="backup" value="11"`, `name="backup" value="12"`,
		`data-copy-target="backup-checksum-11"`, `data-backup-compare disabled`, `/download/edge/backup-11.conf`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("backup page missing %q", want)
		}
	}
	if strings.Contains(body, `name="filename"`) || strings.Contains(body, `name="path"`) {
		t.Fatal("backup comparison accepts a free filename or path")
	}
}

func TestHandleListBackupsRejectsUnknownFirewall(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	router := chi.NewRouter()
	router.Get("/backups/{fwID}", srv.handleListBackups)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/backups/999", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown firewall status = %d, want 404", response.Code)
	}
}

func TestHandleDownloadKeepsPathBoundaryAndActivityLogging(t *testing.T) {
	srv := testServer(t)
	t.Cleanup(srv.hub.shutdown)
	backupDir := t.TempDir()
	srv.cfg.BackupDir = backupDir
	if err := os.WriteFile(filepath.Join(backupDir, "safe.conf"), []byte("config system test\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var activity []string
	srv.store = fakeStore{activity: &activity}
	router := chi.NewRouter()
	router.Get("/download/*", srv.handleDownload)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/download/safe.conf", nil))
	if response.Code != http.StatusOK || response.Body.String() != "config system test\nend\n" {
		t.Fatalf("download response = %d/%q", response.Code, response.Body.String())
	}
	if len(activity) != 1 || !strings.Contains(activity[0], "Downloaded configuration file: safe.conf") {
		t.Fatalf("download activity = %#v", activity)
	}

	blocked := httptest.NewRecorder()
	router.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/download/%2e%2e/outside.conf", nil))
	if blocked.Code != http.StatusNotFound {
		t.Fatalf("traversal download status = %d, want 404", blocked.Code)
	}
}
