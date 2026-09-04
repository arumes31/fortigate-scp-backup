package fgtadmvpnconf

import (
	"bytes"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

// TestIndexTemplateRenders parses the embedded templates and renders the index
// with one row, guarding the delete-confirmation modal markup against template
// syntax/field mistakes (the extension templates are not exercised elsewhere).
func TestIndexTemplateRenders(t *testing.T) {
	e := &Extension{}
	if err := e.parseTemplates(); err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	data := indexData{
		Base: webui.BaseData{
			Title: "FGT ADM VPN Config", Username: "reviewer", Lang: "en", Active: "admvpn", ReturnTo: "/fgt-adm-vpn-conf/",
			Shell:      webui.ShellText("en"),
			Navigation: webui.Navigation(webui.NavigationOptions{Lang: "en", Active: "admvpn", AdmVPN: true}),
		},
		Configs: []configRow{
			{VpnConfig: &VpnConfig{ID: 1, Firewallname: "acme-hq", Radiusmgt: "YES"}},
			{VpnConfig: &VpnConfig{ID: 2, Firewallname: "acme-ok", DnsNameFull: "fgt-acme-ok.adm.example",
				RemoteipFull: "10.105.1.2", LastDnsStatus: "ok", LastDnsResolved: "10.105.1.2"}},
			{VpnConfig: &VpnConfig{ID: 3, Firewallname: "acme-bad", DnsNameFull: "fgt-acme-bad.adm.example",
				RemoteipFull: "10.105.1.3", LastDnsStatus: "mismatch", LastDnsResolved: "10.105.1.99"}},
		},
		AvailableIPsCount:      5,
		AvailableIPsPercentage: "50.00",
	}
	var buf bytes.Buffer
	if err := e.page.Render(&buf, data); err != nil {
		t.Fatalf("execute index: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`class="app-rail"`, `data-live-status`, `data-time-controls`, `aria-current="page"`} {
		if !strings.Contains(out, want) {
			t.Errorf("shared shell missing %q", want)
		}
	}
	for _, unwanted := range []string{`class="topbar"`, `class="sysfooter"`, `FORTISAFE_SYS`} {
		if strings.Contains(out, unwanted) {
			t.Errorf("standalone shell remains: %q", unwanted)
		}
	}
	for _, want := range []string{"open-remove-modal", "removeConfirmInput", "removal_commands",
		// DNS record check icons: green tick for a matching record, red cross
		// (with resolved-vs-expected tooltip) for a wrong-IP record.
		"dns-ok", "dns-fail", "expected 10.105.1.3",
		// Client-side table search input + its filter hook.
		"vpnSearch", "vpnTable"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered index missing %q", want)
		}
	}
}

func TestMountRequiresSharedPageContext(t *testing.T) {
	e := New(&config.Config{}, slog.New(slog.DiscardHandler))
	if err := e.Mount(chi.NewRouter(), extension.Deps{}); err == nil || !strings.Contains(err.Error(), "page context") {
		t.Fatalf("Mount error = %v, want missing shared page context", err)
	}
}

func TestIndexUsesHostPageContext(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/fgt-adm-vpn-conf/?view=all", nil)
	contextCalled := false
	e := &Extension{
		cfg: &config.Config{}, db: db, logger: slog.New(slog.DiscardHandler),
		pageBase: func(gotRequest *http.Request, title, active string) webui.BaseData {
			contextCalled = true
			if gotRequest != request || title != "FGT ADM VPN Config" || active != "admvpn" {
				t.Errorf("PageBase arguments = (%p, %q, %q)", gotRequest, title, active)
			}
			return webui.BaseData{
				Title: title, Username: "host-user", Lang: "de", Active: active, ReturnTo: gotRequest.URL.RequestURI(),
				Shell:      webui.ShellText("de"),
				Navigation: webui.Navigation(webui.NavigationOptions{Lang: "de", Active: active, AdmVPN: true}),
			}
		},
	}
	if err := e.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	e.index(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("index status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	if !contextCalled {
		t.Fatal("index did not request the host page context")
	}
	for _, want := range []string{`<html lang="de">`, "host-user", `aria-current="page"`} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("index missing host context %q", want)
		}
	}
}

func TestGetRandomPassword(t *testing.T) {
	pw := getRandomPassword(34, 4, 4, 2, 2)
	if len(pw) != 34 {
		t.Fatalf("length = %d, want 34", len(pw))
	}
	var upper, lower, digit, special int
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		case r == '!' || r == '#':
			special++
		}
	}
	if upper < 4 || lower < 4 || digit < 2 || special < 2 {
		t.Fatalf("composition too weak: U=%d L=%d D=%d S=%d", upper, lower, digit, special)
	}
}

func TestSplitHostnames(t *testing.T) {
	got := splitHostnames(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(splitHostnames("")) != 0 {
		t.Fatal("empty should yield no hostnames")
	}
}

func TestEscapeGraylogValue(t *testing.T) {
	if got := escapeGraylogValue(`a"b\c`); got != `a\"b\\c` {
		t.Fatalf("got %q", got)
	}
}

func TestContainsStr(t *testing.T) {
	if !containsStr([]string{"a", "error", "b"}, "error") {
		t.Fatal("should find error")
	}
	if containsStr([]string{"a"}, "z") {
		t.Fatal("should not find z")
	}
}

func TestBuildRemovalCommands(t *testing.T) {
	base := VpnConfig{
		Kundenname:   "acme",
		Standort:     "hq",
		Ike2Username: "vpn-adm-acme-hq",
		RemoteipFull: "10.105.1.5",
		DnsNameFull:  "fgt-acme-hq.adm.eworx.at",
	}

	// RADIUS enabled: the RO + HCI/RADIUS objects must all be present.
	yes := base
	yes.Radiusmgt = "YES"
	out := buildRemovalCommands(&yes)
	for _, want := range []string{
		`delete "VPN_EX-ADMRO"`,
		`delete "VPN_EX-ADMHCI"`,
		`delete "RAD-EXADM-1stlvl_1"`,
		`delete "sg-ADM_FGT_Auth_2nd-Level"`,
		`delete "LB-EXADM"`,
		`delete "vpn-adm-acme-hq"`,
		`delete "VPN_ADM_acme-hq_1st"`,
		"config firewall policy",
		"RZP / HCI firewall",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("radius=YES output missing %q", want)
		}
	}
	// phase2 must be deleted before phase1 (dependency order).
	if strings.Index(out, `delete "VPN_EX-ADMRO-1st"`) > strings.Index(out, `delete "VPN_EX-ADMRO"`) {
		t.Error("phase2 must be listed before phase1")
	}

	// RADIUS disabled: no HCI/RADIUS objects, but the RO tunnel + local user stay.
	no := base
	no.Radiusmgt = "NO"
	out = buildRemovalCommands(&no)
	for _, absent := range []string{
		`delete "VPN_EX-ADMHCI"`,
		`delete "RAD-EXADM-1stlvl_1"`,
		"RZP / HCI firewall",
		"config firewall policy",
	} {
		if strings.Contains(out, absent) {
			t.Errorf("radius=NO output should not contain %q", absent)
		}
	}
	for _, want := range []string{`delete "VPN_EX-ADMRO"`, `delete "vpn-adm-acme-hq"`, `delete "LB-EXADM"`} {
		if !strings.Contains(out, want) {
			t.Errorf("radius=NO output missing %q", want)
		}
	}
}

// TestListGraylogIssuesFiltersByAge verifies the dashboard card only lists
// devices that have been unhealthy for at least graylogIssueMinAge (24h),
// matching the alert threshold, and excludes recent/healthy/streak-unknown rows.
func TestListGraylogIssuesFiltersByAge(t *testing.T) {
	dataDir := t.TempDir()
	db, err := openDB(filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	old := formatDBTime(now.Add(-25 * time.Hour))
	recent := formatDBTime(now.Add(-1 * time.Hour))

	cases := []struct {
		fw, status, since string
		enabled           int
		wantListed        bool
	}{
		{"old-offline", "offline", old, 1, true},           // unhealthy > 24h
		{"old-error", "error", old, 1, true},               // any unhealthy state counts
		{"recent-offline", "offline", recent, 1, false},    // unhealthy < 24h
		{"online", "online", "", 1, false},                 // healthy
		{"unhealthy-no-streak", "offline", "", 1, false},   // streak start unknown
		{"disabled-old-offline", "offline", old, 0, false}, // graylog disabled
	}
	for i, c := range cases {
		var since any
		if c.since != "" {
			since = c.since
		}
		if _, err := db.Exec(
			`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname, cid,
			 graylog_enabled, last_graylog_status, graylog_unhealthy_since)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"cust", "site", fmt.Sprintf("10.105.1.%d", i+1), c.fw, "123",
			c.enabled, c.status, since); err != nil {
			t.Fatalf("insert %s: %v", c.fw, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	issues, err := ListGraylogIssues(dataDir)
	if err != nil {
		t.Fatalf("ListGraylogIssues: %v", err)
	}
	got := map[string]bool{}
	for _, is := range issues {
		got[is.Firewall] = true
	}
	for _, c := range cases {
		if got[c.fw] != c.wantListed {
			t.Errorf("device %q listed=%v, want %v", c.fw, got[c.fw], c.wantListed)
		}
	}
}

// TestEditSubmit_MultipartFormData reproduces the edit modal's real request: the
// browser JS submits via fetch() with a FormData body, which Content-Type's as
// multipart/form-data rather than the urlencoded shape a plain HTML form post
// would use. editSubmit must actually pick up the posted fields from that body
// (previously it called ParseForm, which leaves PostForm empty for multipart
// requests, so every field read back as "" and the update always failed with
// "Kundenname and Standort are required" no matter what was typed).
func TestEditSubmit_MultipartFormData(t *testing.T) {
	dataDir := t.TempDir()
	db, err := openDB(filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname, cid)
		VALUES ('old-kunde', 'old-ort', '10.105.1.110', 'FGT40F_OLD-KUNDE-OLD-ORT', '11111')`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	e := &Extension{db: db, logger: slog.New(slog.DiscardHandler), logActivity: func(string, string, string) {}}

	fields := map[string]string{
		"kundenname":    "panhoelzl",
		"standort":      "ried",
		"firewallname":  "FGT40F_PANHOELZL-RIED",
		"cid":           "25580",
		"remoteip_full": "10.105.1.110",
		"wan_interface": "wan",
		"lan_interface": "loopback",
		"ipsec_psk_ro":  "psauto",
		"ipsec_psk_hci": "psauto",
		"radiusmgt":     "YES",
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/edit/%d", id), &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()

	router := chi.NewRouter()
	router.Post("/edit/{id}", e.editSubmit)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("editSubmit status = %d, body = %q, want %d", rr.Code, rr.Body.String(), http.StatusSeeOther)
	}

	updated, err := e.getConfig(id)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if updated.Kundenname != "panhoelzl" || updated.Standort != "ried" {
		t.Fatalf("update did not apply: kundenname=%q standort=%q", updated.Kundenname, updated.Standort)
	}
}

func TestEditFormDoesNotExposeStoredPSKs(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "edit-form.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	const roSecret = "SENTINEL-RO-SECRET-7f28"
	const hciSecret = "SENTINEL-HCI-SECRET-91ac"
	result, err := db.Exec(`INSERT INTO vpn_config
		(kundenname, standort, remoteip_full, firewallname, cid, ipsec_psk_ro, ipsec_psk_hci)
		VALUES ('customer', 'site', '10.105.1.120', 'edge.example.test', '101', ?, ?)`, roSecret, hciSecret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	e := &Extension{db: db, logger: slog.New(slog.DiscardHandler)}
	if err := e.parseTemplates(); err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/edit/%d", id), nil)
	rr := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/edit/{id}", e.editForm)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("editForm status = %d, body = %q", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, secret := range []string{roSecret, hciSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("edit form exposed stored PSK %q", secret)
		}
	}
	for _, want := range []string{
		`type="password" name="ipsec_psk_ro"`,
		`type="password" name="ipsec_psk_hci"`,
		`autocomplete="new-password"`,
		`Leave blank to keep the current secret`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form missing %q", want)
		}
	}
}

func TestEditSubmitBlankPSKsPreservesStoredSecretsAndLogsOnlyChangedFieldNames(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "edit-secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	const roSecret = "SENTINEL-RO-SECRET-1f5d"
	const hciSecret = "SENTINEL-HCI-SECRET-8c22"
	const replacement = "REPLACEMENT-RO-SECRET-e301"
	result, err := db.Exec(`INSERT INTO vpn_config
		(kundenname, standort, remoteip_full, firewallname, cid, ipsec_psk_ro, ipsec_psk_hci,
		 wan_interface, lan_interface, radiusmgt)
		VALUES ('customer', 'site', '10.105.1.121', 'edge.example.test', '101', ?, ?, 'wan1', 'loopback', 'YES')`, roSecret, hciSecret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	var activity []string
	e := &Extension{
		db: db, logger: slog.New(slog.DiscardHandler),
		logActivity: func(_, action, details string) { activity = append(activity, action+" "+details) },
	}
	baseFields := map[string]string{
		"kundenname": "customer", "standort": "site", "firewallname": "edge.example.test",
		"cid": "101", "remoteip_full": "10.105.1.121", "wan_interface": "wan1",
		"lan_interface": "loopback", "radiusmgt": "YES", "ipsec_psk_ro": "", "ipsec_psk_hci": "",
	}
	postEditForm(t, e, id, baseFields, http.StatusSeeOther)
	stored, err := e.getConfig(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IpsecPskRo != roSecret || stored.IpsecPskHci != hciSecret {
		t.Fatalf("blank PSKs changed stored values: ro=%q hci=%q", stored.IpsecPskRo, stored.IpsecPskHci)
	}

	activity = nil
	replaceFields := make(map[string]string, len(baseFields))
	for key, value := range baseFields {
		replaceFields[key] = value
	}
	replaceFields["ipsec_psk_ro"] = replacement
	postEditForm(t, e, id, replaceFields, http.StatusSeeOther)
	stored, err = e.getConfig(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IpsecPskRo != replacement || stored.IpsecPskHci != hciSecret {
		t.Fatalf("single PSK replacement was not isolated: ro=%q hci=%q", stored.IpsecPskRo, stored.IpsecPskHci)
	}
	if len(activity) != 1 {
		t.Fatalf("activity entries = %d, want 1", len(activity))
	}
	if !strings.Contains(activity[0], fmt.Sprintf("ID: %d", id)) || !strings.Contains(activity[0], "ipsec_psk_ro") {
		t.Errorf("activity does not identify entry and changed field: %q", activity[0])
	}
	if strings.Contains(activity[0], "ipsec_psk_hci") {
		t.Errorf("activity lists unchanged secret field: %q", activity[0])
	}
	for _, secret := range []string{roSecret, hciSecret, replacement} {
		if strings.Contains(activity[0], secret) {
			t.Errorf("activity exposed secret %q: %q", secret, activity[0])
		}
	}
}

func TestEditSubmitMalformedMultipartFailsClosed(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "edit-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	const secret = "SENTINEL-UNCHANGED-SECRET-40aa"
	result, err := db.Exec(`INSERT INTO vpn_config
		(kundenname, standort, remoteip_full, firewallname, cid, ipsec_psk_ro)
		VALUES ('customer', 'site', '10.105.1.122', 'edge.example.test', '101', ?)`, secret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	logged := false
	e := &Extension{
		db: db, logger: slog.New(slog.DiscardHandler),
		logActivity: func(_, _, _ string) { logged = true },
	}
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/edit/%d", id), strings.NewReader("not-a-valid-multipart-body"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=missing")
	rr := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Post("/edit/{id}", e.editSubmit)
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed edit status = %d, body = %q, want 400", rr.Code, rr.Body.String())
	}
	stored, err := e.getConfig(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IpsecPskRo != secret || stored.Kundenname != "customer" {
		t.Fatalf("malformed edit mutated row: %#v", stored)
	}
	if logged {
		t.Fatal("malformed edit created an activity record")
	}
	if strings.Contains(rr.Body.String(), secret) {
		t.Fatal("malformed edit response exposed stored secret")
	}
}

func TestEditSubmitRejectsAmbiguousOrOversizedPSKFields(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "edit-invalid-secret.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	const storedSecret = "SENTINEL-STORED-SECRET-115a"
	result, err := db.Exec(`INSERT INTO vpn_config
		(kundenname, standort, remoteip_full, firewallname, cid, ipsec_psk_ro)
		VALUES ('customer', 'site', '10.105.1.123', 'edge.example.test', '101', ?)`, storedSecret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	activityCount := 0
	e := &Extension{
		db: db, logger: slog.New(slog.DiscardHandler),
		logActivity: func(_, _, _ string) { activityCount++ },
	}
	baseFields := map[string]string{
		"kundenname": "customer", "standort": "site", "firewallname": "edge.example.test",
		"cid": "101", "remoteip_full": "10.105.1.123", "wan_interface": "wan1",
		"lan_interface": "loopback", "radiusmgt": "YES", "ipsec_psk_hci": "",
	}

	t.Run("oversized", func(t *testing.T) {
		fields := make(map[string]string, len(baseFields)+1)
		for key, value := range baseFields {
			fields[key] = value
		}
		fields["ipsec_psk_ro"] = strings.Repeat("x", 101)
		postEditForm(t, e, id, fields, http.StatusBadRequest)
	})

	t.Run("duplicate", func(t *testing.T) {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for key, value := range baseFields {
			if err := mw.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
		if err := mw.WriteField("ipsec_psk_ro", "first-value"); err != nil {
			t.Fatal(err)
		}
		if err := mw.WriteField("ipsec_psk_ro", "second-value"); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/edit/%d", id), &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		router := chi.NewRouter()
		router.Post("/edit/{id}", e.editSubmit)
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("duplicate PSK status = %d, body = %q", rr.Code, rr.Body.String())
		}
	})

	stored, err := e.getConfig(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IpsecPskRo != storedSecret {
		t.Fatalf("invalid PSK submission changed stored value to %q", stored.IpsecPskRo)
	}
	if activityCount != 0 {
		t.Fatalf("invalid PSK submissions logged %d successful edits", activityCount)
	}
}

func TestAddActivityIdentifiesEntryAndFieldsWithoutSecrets(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "add-activity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	const roSecret = "SENTINEL-ADD-RO-SECRET-5e18"
	const hciSecret = "SENTINEL-ADD-HCI-SECRET-2ca4"
	var activity string
	e := &Extension{
		db: db, logger: slog.New(slog.DiscardHandler),
		logActivity: func(_, action, details string) { activity = action + " " + details },
	}
	values := url.Values{
		"kundenname": {"customer"}, "standort": {"site"}, "firewallname": {"edge.example.test"},
		"cid": {"101"}, "wan_interface": {"wan1"}, "lan_interface": {"loopback"},
		"ipsec_psk_ro": {roSecret}, "ipsec_psk_hci": {hciSecret}, "radiusmgt": {"YES"},
	}
	req := httptest.NewRequest(http.MethodPost, "/add", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.add(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("add status = %d, body = %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(activity, "ID:") || !strings.Contains(activity, "ipsec_psk_ro") || !strings.Contains(activity, "ipsec_psk_hci") {
		t.Errorf("activity does not identify entry and field names: %q", activity)
	}
	for _, secret := range []string{roSecret, hciSecret} {
		if strings.Contains(activity, secret) {
			t.Errorf("activity exposed secret %q: %q", secret, activity)
		}
	}
}

func postEditForm(t *testing.T, e *Extension, id int64, fields map[string]string, wantStatus int) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := mw.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/edit/%d", id), &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Post("/edit/{id}", e.editSubmit)
	router.ServeHTTP(rr, req)
	if rr.Code != wantStatus {
		t.Fatalf("editSubmit status = %d, body = %q, want %d", rr.Code, rr.Body.String(), wantStatus)
	}
}

// TestMigrations verifies a legacy database (missing the newer columns) is
// migrated in place and the cid backfill runs (#91).
func TestMigrations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Old-shape table: no cid / graylog_enabled / cluster_hostnames /
	// last_graylog_status / last_graylog_check.
	_, err = db.Exec(`CREATE TABLE vpn_config (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kundenname VARCHAR(100), standort VARCHAR(100),
		remoteip_full VARCHAR(100) UNIQUE, firewallname VARCHAR(100) UNIQUE)`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname)
		VALUES ('acme','hq','10.105.1.1','acme-hq')`); err != nil {
		t.Fatal(err)
	}

	e := &Extension{db: db, logger: slog.New(slog.DiscardHandler), logActivity: func(string, string, string) {}}
	if err := e.ensureMigrations(); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Newer columns must now be selectable.
	for _, col := range []string{"cid", "graylog_enabled", "cluster_hostnames", "last_graylog_status", "last_graylog_check", "graylog_unhealthy_since", "last_dns_status", "last_dns_check", "last_dns_resolved"} {
		if !columnExists(db, col) {
			t.Errorf("column %q missing after migration", col)
		}
	}
	// cid must be backfilled from firewallname.
	var cid string
	if err := db.QueryRow(`SELECT cid FROM vpn_config WHERE firewallname='acme-hq'`).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(cid) == "" {
		t.Fatal("cid should have been backfilled")
	}
}
