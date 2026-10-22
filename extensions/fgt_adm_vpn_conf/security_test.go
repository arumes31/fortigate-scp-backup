package fgtadmvpnconf

import (
	"bytes"
	"encoding/csv"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

func validTestConfig() *VpnConfig {
	return &VpnConfig{
		Kundenname: "customer", Standort: "site", Firewallname: "edge.example.test",
		WanInterface: "wan1", LanInterface: "loopback",
		IpsecPskRo: "psauto", IpsecPskHci: "Abc!#123xyz",
		RemoteipFull: "10.105.1.7", RemoteipFull1st: "10.150.11.7",
		ClusterHostnames: "fgt-a, fgt-b",
	}
}

func TestValidateVpnConfigFieldsRejectsCLIInjection(t *testing.T) {
	if err := validateVpnConfigFields(validTestConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	mutations := map[string]func(*VpnConfig){
		"newline in name":       func(c *VpnConfig) { c.Kundenname = "acme\nconfig system admin" },
		"space in site":         func(c *VpnConfig) { c.Standort = "hq site" },
		"quote in firewall":     func(c *VpnConfig) { c.Firewallname = `edge"` },
		"semicolon in cluster":  func(c *VpnConfig) { c.ClusterHostnames = "fgt-a;10.0.0.1;active" },
		"newline in interface":  func(c *VpnConfig) { c.WanInterface = "wan1\nend" },
		"empty interface":       func(c *VpnConfig) { c.LanInterface = "" },
		"newline in psk":        func(c *VpnConfig) { c.IpsecPskRo = "secret\nconfig system admin" },
		"space in psk":          func(c *VpnConfig) { c.IpsecPskHci = "secret value" },
		"quote in psk":          func(c *VpnConfig) { c.IpsecPskHci = `secret"` },
		"backslash in psk":      func(c *VpnConfig) { c.IpsecPskHci = `secret\` },
		"non-ip remote":         func(c *VpnConfig) { c.RemoteipFull = "10.105.1.7 255.0.0.0" },
		"non-ip 1st remote":     func(c *VpnConfig) { c.RemoteipFull1st = "x\nend" },
		"overlong name":         func(c *VpnConfig) { c.Kundenname = strings.Repeat("a", 64) },
		"overlong psk":          func(c *VpnConfig) { c.IpsecPskRo = strings.Repeat("a", 101) },
		"non-ascii psk":         func(c *VpnConfig) { c.IpsecPskRo = "geheimö" },
		"control char in names": func(c *VpnConfig) { c.Firewallname = "edge\x00" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := validTestConfig()
			mutate(c)
			if err := validateVpnConfigFields(c); err == nil {
				t.Fatal("unsafe value accepted")
			}
		})
	}
}

func TestAddRejectsInjectedCLICommands(t *testing.T) {
	e, _ := newBulkTestExtension(t, 0)
	values := url.Values{
		"kundenname": {"customer"}, "standort": {"site"}, "firewallname": {"edge.example.test"},
		"connectwise_company_name": {"Acme"},
		"wan_interface":            {"wan1\nconfig system admin\nedit backdoor"},
	}
	req := httptest.NewRequest(http.MethodPost, "/add", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.add(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("add with injected interface = %d, want 400", rr.Code)
	}
	rows, err := e.allConfigs()
	if err != nil || len(rows) != 0 {
		t.Fatalf("injected entry stored: rows=%v err=%v", rows, err)
	}
}

func TestBuildConfigZipRefusesUnsafeLegacyRows(t *testing.T) {
	e := &Extension{}
	c := validTestConfig()
	c.IpsecPskRo = "x\nconfig system admin"
	if _, err := e.buildConfigZip(c); err == nil {
		t.Fatal("generator rendered a row with an injected PSK")
	}
	if _, err := e.buildConfigZip(validTestConfig()); err != nil {
		t.Fatalf("generator rejected a valid row: %v", err)
	}
}

func TestGraylogDSVTokenAndAllowlist(t *testing.T) {
	e, _ := newBulkTestExtension(t, 1)
	e.cfg = &config.Config{}
	get := func(remote, target, bearer string) int {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = remote
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		e.graylogDSV(rr, req)
		return rr.Code
	}
	if code := get("203.0.113.1:1", "/graylog_dsv", ""); code != http.StatusOK {
		t.Fatalf("unconfigured feed status = %d, want legacy 200", code)
	}

	e.cfg.AdmVpnDSVToken = "dsv-feed-token-123"
	if code := get("203.0.113.1:1", "/graylog_dsv", ""); code != http.StatusForbidden {
		t.Fatalf("feed without token = %d, want 403", code)
	}
	if code := get("203.0.113.1:1", "/graylog_dsv?token=wrong", ""); code != http.StatusForbidden {
		t.Fatalf("feed with wrong token = %d, want 403", code)
	}
	if code := get("203.0.113.1:1", "/graylog_dsv?token=dsv-feed-token-123", ""); code != http.StatusOK {
		t.Fatalf("feed with query token = %d, want 200", code)
	}
	if code := get("203.0.113.1:1", "/graylog_dsv", "dsv-feed-token-123"); code != http.StatusOK {
		t.Fatalf("feed with bearer token = %d, want 200", code)
	}

	e.cfg.AdmVpnDSVAllowedCIDRs = "192.0.2.0/24"
	if code := get("203.0.113.1:1", "/graylog_dsv", "dsv-feed-token-123"); code != http.StatusForbidden {
		t.Fatalf("feed from outside allowlist = %d, want 403", code)
	}
	if code := get("192.0.2.10:1", "/graylog_dsv", "dsv-feed-token-123"); code != http.StatusOK {
		t.Fatalf("feed from allowlisted peer = %d, want 200", code)
	}
}

func TestPSKsAreEncryptedAtRest(t *testing.T) {
	e, ids := newBulkTestExtension(t, 1)
	cipher, err := crypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e.cipher = cipher
	if err := e.encryptLegacySecrets(); err != nil {
		t.Fatal(err)
	}
	var rawRo, rawHci string
	if err := e.db.QueryRow("SELECT ipsec_psk_ro, ipsec_psk_hci FROM vpn_config WHERE id = ?", ids[0]).Scan(&rawRo, &rawHci); err != nil {
		t.Fatal(err)
	}
	if !crypto.IsEncryptedString(rawRo) || !crypto.IsEncryptedString(rawHci) || strings.Contains(rawRo+rawHci, "SENTINEL") {
		t.Fatalf("legacy PSKs not encrypted: %q %q", rawRo, rawHci)
	}
	stored, err := e.getConfig(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if stored.IpsecPskRo != "SENTINEL-PSK-RO" || stored.IpsecPskHci != "SENTINEL-PSK-HCI" {
		t.Fatalf("decrypted PSKs = %q %q", stored.IpsecPskRo, stored.IpsecPskHci)
	}

	c := validTestConfig()
	c.CompanyName = "Acme"
	c.IpsecPskRo = "NEW-SECRET-RO"
	if err := e.insertConfig(c); err != nil {
		t.Fatal(err)
	}
	if err := e.db.QueryRow("SELECT ipsec_psk_ro FROM vpn_config WHERE id = ?", c.ID).Scan(&rawRo); err != nil {
		t.Fatal(err)
	}
	if !crypto.IsEncryptedString(rawRo) {
		t.Fatalf("new PSK stored in plaintext: %q", rawRo)
	}
}

func TestCSVExportOmitsPSKsAndNeutralizesFormulas(t *testing.T) {
	c := validTestConfig()
	c.IpsecPskRo = "SECRET-RO"
	c.IpsecPskHci = "psauto"
	c.CompanyName = "=HYPERLINK(\"http://example.invalid\")"
	var plain bytes.Buffer
	if err := writeConfigsCSV(&plain, []*VpnConfig{c}, false); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&plain).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	row := records[1]
	if row[8] != "" || row[9] != "psauto" {
		t.Fatalf("default export PSK cells = %q %q, want blank and psauto", row[8], row[9])
	}
	if !strings.HasPrefix(row[13], "'=") {
		t.Fatalf("formula cell not neutralized: %q", row[13])
	}
	if csvUnescapeCell(row[13]) != c.CompanyName {
		t.Fatalf("neutralized cell does not round-trip: %q", csvUnescapeCell(row[13]))
	}

	var full bytes.Buffer
	if err := writeConfigsCSV(&full, []*VpnConfig{c}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full.String(), "SECRET-RO") {
		t.Fatal("explicit secret export omitted the PSK")
	}
}

func TestImportOfSecretFreeExportKeepsStoredPSKs(t *testing.T) {
	e, _ := newBulkTestExtension(t, 0)
	e.cfg = &config.Config{CSVMaxBytes: 1 << 20}
	c := validTestConfig()
	c.CompanyName = "Acme"
	c.IpsecPskRo = "STORED-RO-SECRET"
	c.IpsecPskHci = "STORED-HCI-SECRET"
	if err := e.insertConfig(c); err != nil {
		t.Fatal(err)
	}
	var exported bytes.Buffer
	if err := writeConfigsCSV(&exported, []*VpnConfig{c}, false); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("file", "backup.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(exported.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/import", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	rr := httptest.NewRecorder()
	e.importCSV(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("import = %d: %s", rr.Code, rr.Body.String())
	}
	stored, err := e.getConfig(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IpsecPskRo != "STORED-RO-SECRET" || stored.IpsecPskHci != "STORED-HCI-SECRET" {
		t.Fatalf("re-import changed PSKs: %q %q", stored.IpsecPskRo, stored.IpsecPskHci)
	}
}
