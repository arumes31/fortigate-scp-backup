package fgtadmvpnconf

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestCompanyIdentifierAddEditAndHookwise(t *testing.T) {
	e, _ := newBulkTestExtension(t, 0)
	values := url.Values{
		"kundenname": {"customer"}, "standort": {"site"}, "firewallname": {"edge.example.test"},
		"connectwise_company_name": {"  Acme-Europe  "}, "graylog_enabled": {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/add", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.add(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("add = %d: %s", rr.Code, rr.Body.String())
	}
	rows, err := e.allConfigs()
	if err != nil || len(rows) != 1 {
		t.Fatalf("configs = %v, err = %v", rows, err)
	}
	entry := rows[0]
	if entry.CompanyName != "Acme-Europe" || !entry.GraylogEnabled {
		t.Fatalf("new company/Graylog = %q/%t", entry.CompanyName, entry.GraylogEnabled)
	}
	postEditForm(t, e, entry.ID, map[string]string{
		"kundenname": "customer", "standort": "site", "firewallname": entry.Firewallname,
		"remoteip_full": entry.RemoteipFull, "connectwise_company_name": "  Acme & Partners  ",
	}, http.StatusSeeOther)
	entry, err = e.getConfig(entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if entry.CompanyName != "Acme & Partners" || entry.GraylogEnabled {
		t.Fatalf("edited company/Graylog = %q/%t", entry.CompanyName, entry.GraylogEnabled)
	}
	var received map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e.cfg = &config.Config{HookwiseURL: server.URL, HookwiseToken: "synthetic-token"}
	if !e.sendHookwiseEvent(entry, "offline") || received["company"] != "Acme & Partners" || received["status"] != "DOWN" {
		t.Fatalf("Hookwise payload = %v", received)
	}
	if _, ok := received["cid"]; ok {
		t.Fatal("legacy CID appeared in Hookwise payload")
	}
}

func TestCompanyIdentifierRequiredAndNoLegacyFormFallback(t *testing.T) {
	e, _ := newBulkTestExtension(t, 0)
	values := url.Values{"kundenname": {"customer"}, "standort": {"site"}, "graylog_enabled": {"on"}}
	// An obsolete CID cannot satisfy the required company field.
	values.Set("cid", "101")
	req := httptest.NewRequest(http.MethodPost, "/add", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.add(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "connectwise company name is required") {
		t.Fatalf("add without company = %d: %s", rr.Code, rr.Body.String())
	}
	rows, err := e.allConfigs()
	if err != nil || len(rows) != 0 {
		t.Fatalf("invalid add wrote configs=%v err=%v", rows, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("missing company must not send a Hookwise event")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e.cfg = &config.Config{HookwiseURL: server.URL, HookwiseToken: "synthetic-token"}
	for _, company := range []string{"", "  "} {
		entry := &VpnConfig{CompanyName: company, GraylogEnabled: false}
		if !e.sendHookwiseEvent(entry, "offline") {
			t.Fatal("intentionally skipped event should succeed")
		}
		view := browserSafeEditFormData(entry)
		if view.CompanyName != "" || view.GraylogEnabled {
			t.Fatalf("disabled edit state changed: %+v", view)
		}
	}
}

func TestValidateCompanyIdentifier(t *testing.T) {
	for _, value := range []string{"101", "Acme-Europe", "Müller & Söhne", strings.Repeat("a", 100)} {
		if err := validateCompanyIdentifier(value); err != nil {
			t.Errorf("valid identifier %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "  ", "Acme\nOther", "Acme\x00", strings.Repeat("a", 101), string([]byte{0xff})} {
		if err := validateCompanyIdentifier(value); err == nil {
			t.Errorf("accepted invalid identifier %q", value)
		}
	}
}

func TestCompanyIdentifierCSVRequiresNewHeader(t *testing.T) {
	for _, header := range []string{"Connectwise Company Name", "CID"} {
		t.Run(header, func(t *testing.T) {
			e, _ := newBulkTestExtension(t, 0)
			e.cfg = &config.Config{CSVMaxBytes: 1 << 20}
			var exported bytes.Buffer
			if err := writeConfigsCSV(&exported, []*VpnConfig{{
				Kundenname: "customer", Standort: "site", Firewallname: "edge.example.test",
				RemoteipFull: "10.105.1.8", CompanyName: "Acme-Europe", GraylogEnabled: true,
			}}); err != nil {
				t.Fatal(err)
			}
			records, err := csv.NewReader(&exported).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if records[0][13] != "Connectwise Company Name" {
				t.Fatalf("export company header = %q", records[0][13])
			}
			records[0][13] = header
			var csvBody bytes.Buffer
			csvWriter := csv.NewWriter(&csvBody)
			if err := csvWriter.WriteAll(records); err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			form := multipart.NewWriter(&body)
			file, err := form.CreateFormFile("file", "companies.csv")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(file, &csvBody); err != nil {
				t.Fatal(err)
			}
			if err := form.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/import", &body)
			req.Header.Set("Content-Type", form.FormDataContentType())
			rr := httptest.NewRecorder()
			e.importCSV(rr, req)
			rows, err := e.allConfigs()
			if header == "CID" {
				if err != nil || len(rows) != 0 || !strings.Contains(rr.Body.String(), "connectwise company name") {
					t.Fatalf("legacy CSV was accepted: rows=%v err=%v response=%s", rows, err, rr.Body.String())
				}
				return
			}
			if err != nil || len(rows) != 1 || rows[0].CompanyName != "Acme-Europe" || !rows[0].GraylogEnabled {
				t.Fatalf("import failed: rows=%v err=%v response=%s", rows, err, rr.Body.String())
			}
		})
	}
}

func TestCompanyMigrationPreservesMappingsAndMonitoring(t *testing.T) {
	e, ids := newBulkTestExtension(t, 2)
	if _, err := e.db.Exec("ALTER TABLE vpn_config RENAME COLUMN connectwise_company_name TO cid"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec("UPDATE vpn_config SET cid = 'Acme-Europe', graylog_enabled = 0 WHERE id = ?", ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec("UPDATE vpn_config SET cid = '000000' WHERE id = ?", ids[1]); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.runMigrations(); err != nil {
			t.Fatal(err)
		}
	}
	if columnExists(e.db, "cid") {
		t.Fatal("legacy CID column remains after migration")
	}
	first, err := e.getConfig(ids[0])
	if err != nil || first.CompanyName != "Acme-Europe" || first.GraylogEnabled {
		t.Fatalf("saved mapping/monitoring changed: entry=%+v err=%v", first, err)
	}
	second, err := e.getConfig(ids[1])
	if err != nil || second.CompanyName != "" || !second.GraylogEnabled {
		t.Fatalf("disabled marker migration changed monitoring: entry=%+v err=%v", second, err)
	}
	postEditForm(t, e, first.ID, map[string]string{
		"kundenname": first.Kundenname, "standort": first.Standort, "firewallname": first.Firewallname,
		"remoteip_full": first.RemoteipFull, "connectwise_company_name": " ",
	}, http.StatusBadRequest)
	first, err = e.getConfig(ids[0])
	if err != nil || first.CompanyName != "Acme-Europe" {
		t.Fatalf("invalid edit replaced company: entry=%+v err=%v", first, err)
	}
}
