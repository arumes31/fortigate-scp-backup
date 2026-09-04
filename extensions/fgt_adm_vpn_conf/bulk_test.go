package fgtadmvpnconf

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestBulkGenerateReportsPartialFailureWithSafeDeterministicFilenames(t *testing.T) {
	e, ids := newBulkTestExtension(t, 2)
	var activity string
	e.logActivity = func(_, action, details string) { activity = action + " " + details }
	e.buildConfigZipFn = func(config *VpnConfig) (*bytes.Buffer, error) {
		if config.ID == ids[1] {
			return nil, errors.New("synthetic generation failure")
		}
		return bytes.NewBufferString("synthetic bundle"), nil
	}

	rr := postBulkRequest(t, e.bulkGenerate, "/bulk/generate", ids)
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk generate status = %d, body = %q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-FortiSafe-Bulk-Succeeded"); got != "1" {
		t.Errorf("succeeded header = %q, want 1", got)
	}
	if got := rr.Header().Get("X-FortiSafe-Bulk-Failed-IDs"); got != fmt.Sprint(ids[1]) {
		t.Errorf("failed IDs header = %q, want %d", got, ids[1])
	}
	if got := rr.Header().Get("Content-Disposition"); got != `attachment; filename="fgt_adm_configs_2_selected.zip"` {
		t.Errorf("Content-Disposition = %q", got)
	}

	reader, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if err != nil {
		t.Fatalf("read bulk ZIP: %v", err)
	}
	var names []string
	var results string
	for _, file := range reader.File {
		names = append(names, file.Name)
		if file.Name == "_results.csv" {
			entry, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(entry)
			_ = entry.Close()
			if err != nil {
				t.Fatal(err)
			}
			results = string(payload)
		}
	}
	sort.Strings(names)
	wantBundle := fmt.Sprintf("%03d-edge-1.example.test.zip", ids[0])
	wantNames := []string{"_results.csv", wantBundle}
	sort.Strings(wantNames)
	if fmt.Sprint(names) != fmt.Sprint(wantNames) {
		t.Errorf("ZIP entries = %v", names)
	}
	if !strings.Contains(results, fmt.Sprintf("%d,edge-2.example.test,failed", ids[1])) {
		t.Errorf("result report does not identify failed entry: %q", results)
	}
	if !strings.Contains(activity, "count: 2") || !strings.Contains(activity, fmt.Sprintf("IDs: %d,%d", ids[0], ids[1])) {
		t.Errorf("activity does not identify bounded operation: %q", activity)
	}
	for _, forbidden := range []string{"SENTINEL-PSK", "synthetic bundle"} {
		if strings.Contains(activity, forbidden) {
			t.Errorf("activity exposed generated content or credential: %q", activity)
		}
	}
}

func TestBulkExportReturnsOnlySelectedRowsViaPOST(t *testing.T) {
	e, ids := newBulkTestExtension(t, 3)
	rr := postBulkRequest(t, e.bulkExport, "/bulk/export", []int64{ids[2], ids[0]})
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk export status = %d, body = %q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Disposition"); got != `attachment; filename="vpn_configs_2_selected.csv"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "edge-1.example.test") || !strings.Contains(body, "edge-3.example.test") {
		t.Errorf("selected rows missing from CSV: %q", body)
	}
	if strings.Contains(body, "edge-2.example.test") {
		t.Errorf("unselected row leaked into CSV: %q", body)
	}
}

func TestBulkRejectsZeroDuplicateUnknownAndOverLimitIDs(t *testing.T) {
	e, ids := newBulkTestExtension(t, 2)
	tests := []struct {
		name string
		ids  []int64
	}{
		{name: "zero"},
		{name: "duplicate", ids: []int64{ids[0], ids[0]}},
		{name: "unknown", ids: []int64{ids[0], 999999}},
		{name: "over limit", ids: func() []int64 {
			values := make([]int64, 101)
			for index := range values {
				values[index] = int64(index + 1)
			}
			return values
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := postBulkRequest(t, e.bulkGenerate, "/bulk/generate", tt.ids)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %q, want 400", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestBulkNamesArePathSafeAndResultCellsNeutralizeFormulas(t *testing.T) {
	filename := bulkConfigFilename(&VpnConfig{ID: 7, Firewallname: `../../..\\=dangerous customer`})
	if strings.ContainsAny(filename, `/\\`) || !strings.HasPrefix(filename, "007-") || !strings.HasSuffix(filename, ".zip") {
		t.Fatalf("unsafe bulk filename %q", filename)
	}
	for _, input := range []string{"=1+1", "+SUM(A1:A2)", "-2+3", "@cmd", "  =trimmed"} {
		if got := safeCSVDisplay(input); !strings.HasPrefix(got, "'") {
			t.Errorf("safeCSVDisplay(%q) = %q, want apostrophe prefix", input, got)
		}
	}
	if got := safeCSVDisplay("edge.example.test"); got != "edge.example.test" {
		t.Errorf("ordinary cell changed to %q", got)
	}
}

func newBulkTestExtension(t *testing.T, count int) (*Extension, []int64) {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "bulk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, count)
	for index := 1; index <= count; index++ {
		result, err := db.Exec(`INSERT INTO vpn_config
			(kundenname, standort, remoteip_full, firewallname, cid, ipsec_psk_ro, ipsec_psk_hci)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("customer-%d", index), "site", fmt.Sprintf("10.105.1.%d", index),
			fmt.Sprintf("edge-%d.example.test", index), fmt.Sprint(100+index),
			"SENTINEL-PSK-RO", "SENTINEL-PSK-HCI")
		if err != nil {
			t.Fatal(err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return &Extension{db: db, logger: slog.New(slog.DiscardHandler)}, ids
}

func postBulkRequest(t *testing.T, handler http.HandlerFunc, path string, ids []int64) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, id := range ids {
		if err := writer.WriteField("id", fmt.Sprint(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Post(path, handler)
	router.ServeHTTP(rr, req)
	return rr
}
