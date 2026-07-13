package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/backup"
	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/scheduler"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
)

// ---- fakes ----

type fakeStore struct{}

func (fakeStore) Ping(context.Context) error         { return nil }
func (fakeStore) LogActivity(string, string, string) {}
func (fakeStore) GetUserForLogin(_ context.Context, u string) (*models.User, error) {
	if u == "admin" {
		return &models.User{Username: "admin", Password: "changeme", FirstLogin: 0}, nil
	}
	return nil, nil
}
func (fakeStore) UpsertRadiusUser(context.Context, string) error { return nil }
func (fakeStore) AuthenticateLocal(_ context.Context, u, p string) (*models.User, bool, error) {
	if u == "admin" && p == "changeme" {
		return &models.User{Username: "admin", FirstLogin: 0}, true, nil
	}
	return nil, false, nil
}
func (fakeStore) GetFirstLogin(context.Context, string) (int, bool, error) { return 0, true, nil }
func (fakeStore) ChangePassword(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (fakeStore) ListFirewalls(context.Context) ([]models.Firewall, error)  { return nil, nil }
func (fakeStore) AddFirewall(context.Context, models.Firewall) (int, error) { return 1, nil }
func (fakeStore) DeleteFirewall(context.Context, int) (string, error)       { return "", nil }
func (fakeStore) ListBackups(context.Context, int) ([]models.Backup, error) { return nil, nil }
func (fakeStore) ListErrors(context.Context) ([]models.Firewall, error)     { return nil, nil }
func (fakeStore) CountActivityLogs(context.Context) (int, error)            { return 0, nil }
func (fakeStore) DashboardStats(context.Context) (models.DashboardStats, error) {
	return models.DashboardStats{}, nil
}
func (fakeStore) ListFirewallRefs(context.Context) ([]models.FirewallRef, error) { return nil, nil }
func (fakeStore) ListActivityLogs(context.Context, int, int) ([]models.ActivityLog, error) {
	return nil, nil
}
func (fakeStore) GetAuditFindings(context.Context, int) ([]models.AuditFinding, error) {
	return nil, nil
}
func (fakeStore) SaveAuditFindings(context.Context, int, []models.AuditFinding) error { return nil }

type fakeAuth struct{ totp bool }

func (fakeAuth) VerifyRadius(string, string) bool { return false }
func (a fakeAuth) VerifyTOTP(string, string) bool { return a.totp }

func testServer(t *testing.T) *Server {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Load(logger)
	cfg.LoginMaxAttempts = 3
	cipher, _ := crypto.New(nil)
	srv, err := New(cfg, fakeStore{}, scheduler.New(logger, time.UTC),
		backup.New(nil, mailer.New(cfg, logger), cfg, cipher, logger),
		session.New(nil, false, false), fakeAuth{}, cipher, logger)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestUnauthenticatedRedirect(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("want redirect to /login, got %q", loc)
	}
}

func TestHealthz(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing CSP")
	}
}

func TestStaticFontServed(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/static/fonts/jetbrains-mono-400.woff2", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("self-hosted font not served: got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "font/woff2" {
		t.Errorf("Content-Type = %q, want font/woff2", ct)
	}
	if b := rr.Body.Bytes(); len(b) < 4 || string(b[:4]) != "wOF2" {
		t.Error("served font is not a valid woff2 (bad magic bytes)")
	}
}

func TestLoginSuccess(t *testing.T) {
	srv := testServer(t)
	form := url.Values{"username": {"admin"}, "password": {"changeme"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("want 302 on success, got %d", rr.Code)
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("expected a session cookie")
	}
}

func TestLoginRateLimit(t *testing.T) {
	srv := testServer(t)
	post := func() int {
		form := url.Values{"username": {"admin"}, "password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.9:1234"
		rr := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rr, req)
		return rr.Code
	}
	// 3 failures reach the limit; the 4th is blocked (still 200 with an error page).
	for i := 0; i < 3; i++ {
		post()
	}
	if !srv.limiter.allowed("10.0.0.9|admin") {
		// good: blocked
	} else {
		t.Fatal("expected key to be blocked after max failures")
	}
}

func TestBuildSearchPattern(t *testing.T) {
	re, err := buildSearchPattern("set *name*")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("SET port-NAME value") {
		t.Fatal("wildcard should match")
	}
	if re.MatchString("nomatch") {
		t.Fatal("should not match unrelated text")
	}
	// A regex metacharacter is treated literally.
	re2, err := buildSearchPattern("a.b")
	if err != nil {
		t.Fatal(err)
	}
	if re2.MatchString("axb") {
		t.Fatal("'.' must be literal, not any-char")
	}
}

func FuzzBuildSearchPattern(f *testing.F) {
	f.Add("set *name*")
	f.Add("a.b[c]")
	f.Add("***")
	f.Fuzz(func(t *testing.T, q string) {
		if _, err := buildSearchPattern(q); err != nil {
			t.Fatalf("pattern should always compile, query=%q err=%v", q, err)
		}
	})
}

func TestFmtBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 512: "512 B", 1024: "1.0 KB", 1048576: "1.0 MB"}
	for in, want := range cases {
		if got := fmtBytes(in); got != want {
			t.Errorf("fmtBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFmtTimeZero(t *testing.T) {
	if got := fmtTime(time.Time{}); got != "—" {
		t.Fatalf("zero time should render as em dash, got %q", got)
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		trustProxy bool
		want       string
	}{
		{"no trust ignores xff", "203.0.113.5:443", "1.2.3.4", false, "203.0.113.5"},
		{"no trust no port", "203.0.113.5", "", false, "203.0.113.5"},
		{"trust single xff", "10.0.0.1:80", "198.51.100.7", true, "198.51.100.7"},
		// Client prepends a spoofed hop; the trusted proxy appends the real peer
		// on the right, so the rightmost entry is the address to trust.
		{"trust picks rightmost", "10.0.0.1:80", "1.2.3.4, 198.51.100.7", true, "198.51.100.7"},
		{"trust trims spaces", "10.0.0.1:80", "1.2.3.4,  198.51.100.7  ", true, "198.51.100.7"},
		{"trust empty xff falls back", "203.0.113.5:443", "", true, "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r, tc.trustProxy); got != tc.want {
				t.Fatalf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseFortiOSVersion(t *testing.T) {
	cfg := "#config-version=FGT60F-7.2.5-FW-build1517-230608:opmode=0:vdom=0\nconfig system global\nend\n"
	if model, ver := parseFortiOSVersion(cfg); model != "FGT60F" || ver != "7.2.5" {
		t.Fatalf("got model=%q ver=%q, want FGT60F/7.2.5", model, ver)
	}
	if m, v := parseFortiOSVersion("no version header"); m != "" || v != "" {
		t.Fatalf("expected empty, got %q %q", m, v)
	}
}

// structuralFindings is a test helper running the block-scanner checks the way
// computeAudit does.
func structuralFindings(cfg string) []auditFinding {
	doc := parseCfg(cfg)
	return runStructuralChecks(doc, parseConfigData(doc).Routes)
}

// findingIDs collects the CheckIDs of a finding list.
func findingIDs(fs []auditFinding) map[string]auditFinding {
	out := make(map[string]auditFinding, len(fs))
	for _, f := range fs {
		out[f.CheckID] = f
	}
	return out
}

func TestAuditFindings(t *testing.T) {
	cfg := `config system interface
edit "wan1"
set allowaccess ping https ssh telnet
next
edit "mgmt"
set allowaccess https http
next
end`
	ids := findingIDs(structuralFindings(cfg))
	if f, ok := ids["intf-telnet"]; !ok || f.Severity != "critical" {
		t.Error("telnet allowaccess should raise a critical intf-telnet finding")
	}
	if f, ok := ids["intf-http"]; !ok || f.Severity != "warning" {
		t.Error("plaintext http allowaccess should raise an intf-http warning")
	}
	// Line context must point at the allowaccess statement of wan1 (line 3).
	if f := ids["intf-telnet"]; f.Line != 3 || !strings.Contains(f.Context, "set allowaccess ping https ssh telnet") {
		t.Errorf("intf-telnet should anchor at line 3 with context, got line=%d ctx=%q", f.Line, f.Context)
	}

	// Test 2FA, trusted hosts and default admin account
	adminCfg := `config system admin
edit "admin"
set accprofile "super_admin"
next
edit "user2"
set accprofile "super_admin"
set trusthost1 10.0.0.0 255.255.255.0
set two-factor email
next
end`
	ids = findingIDs(structuralFindings(adminCfg))
	if f, ok := ids["admin-no-2fa"]; !ok || f.Severity != "critical" || f.Key != "admin-no-2fa:admin" {
		t.Errorf("admin without 2FA should raise critical keyed finding, got %+v", ids["admin-no-2fa"])
	}
	if _, ok := ids["admin-default-account"]; !ok {
		t.Error("admin default account should raise a warning finding")
	}
	if f, ok := ids["admin-no-trusthost"]; !ok || f.Key != "admin-no-trusthost:admin" {
		t.Error("admin without trusted hosts should raise a keyed warning finding")
	}

	// Test weak crypto (3des/des, md5, dhgrp, ssl min version, password policy)
	cryptoCfg := `config system global
set ssl-min-proto-version tls1-0
end
config vpn ipsec phase1-interface
edit "vpn1"
set proposal 3des-md5 des-sha1 aes128-sha256
set dhgrp 1 2 14
next
end
config system password-policy
set status disable
end`
	ids = findingIDs(structuralFindings(cryptoCfg))
	for _, want := range []string{"vpn-weak-cipher", "vpn-weak-hash", "vpn-weak-dhgrp", "global-weak-tls", "pwpolicy-disabled"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("crypto config should raise %s", want)
		}
	}

	// A config with hardened settings raises none of the critical checks.
	hardened := `config system global
set admin-sport 9443
set pre-login-banner enable
end
config system password-policy
set status enable
end
config log syslogd setting
set status enable
end`
	ids = findingIDs(structuralFindings(hardened))
	for _, bad := range []string{"intf-telnet", "global-weak-tls", "pwpolicy-disabled", "log-no-remote", "global-admin-sport-default"} {
		if _, ok := ids[bad]; ok {
			t.Errorf("hardened config should not raise %s", bad)
		}
	}
}

func TestCheckGlobalHardening(t *testing.T) {
	cfg := `config system global
set admin-telnet enable
set admin-ssh-v1 enable
set strong-crypto disable
set ssl-static-key-ciphers enable
set admin-https-redirect disable
set admintimeout 480
set admin-maintainer enable
set rest-api-key-url-query enable
end`
	ids := findingIDs(structuralFindings(cfg))
	for _, want := range []string{"global-admin-telnet", "global-ssh-v1", "global-strong-crypto",
		"global-static-keys", "global-http-redirect", "global-admintimeout",
		"global-maintainer", "global-rest-api-query", "global-admin-sport-default"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("expected finding %s", want)
		}
	}
}

func TestCheckWANManagement(t *testing.T) {
	cfg := `config system interface
edit "wan1"
set role wan
set allowaccess ping https ssh
next
edit "lan"
set allowaccess https ssh
next
end`
	ids := findingIDs(structuralFindings(cfg))
	f, ok := ids["intf-wan-mgmt"]
	if !ok || f.Severity != "critical" || f.Key != "intf-wan-mgmt:wan1" {
		t.Fatalf("management on WAN interface should raise critical keyed finding, got %+v", f)
	}
	if _, ok := ids["intf-ping-wan"]; !ok {
		t.Error("ping on WAN interface should raise an info finding")
	}
}

func TestCheckSSLVPNAndSNMP(t *testing.T) {
	cfg := `config vpn ssl settings
set servercert "cert"
set port 443
set source-interface "wan1"
end
config system snmp community
edit 1
set name "public"
next
end`
	ids := findingIDs(structuralFindings(cfg))
	if _, ok := ids["sslvpn-default-port"]; !ok {
		t.Error("SSL-VPN on default port should raise a warning")
	}
	if _, ok := ids["sslvpn-no-source-address"]; !ok {
		t.Error("SSL-VPN without source-address should raise an info finding")
	}
	if f, ok := ids["snmp-default-community"]; !ok || f.Severity != "critical" {
		t.Error("default SNMP community should raise a critical finding")
	}
	if _, ok := ids["snmp-v1v2c"]; !ok {
		t.Error("SNMP v1/v2c usage should raise an info finding")
	}
}

func TestCheckPolicies(t *testing.T) {
	cfg := `config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan1"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set action accept
set logtraffic disable
next
end`
	ids := findingIDs(structuralFindings(cfg))
	if f, ok := ids["policy-any-any"]; !ok || f.Severity != "critical" || f.Key != "policy-any-any:1" {
		t.Fatalf("any/any/ALL accept policy should raise critical keyed finding, got %+v", f)
	}
	if _, ok := ids["policy-no-log"]; !ok {
		t.Error("accept policy without logging should raise an info finding")
	}
}

func TestGetUpgradePath(t *testing.T) {
	// 7.6.7 is the newest patch of the recommended train: never a downgrade.
	steps, stepsDE := getUpgradePath("7.6.7")
	joined := strings.Join(steps, " | ")
	if strings.Contains(joined, "7.6.0") {
		t.Fatalf("7.6.7 must not suggest 7.6.0, got %v", steps)
	}
	if !strings.Contains(joined, "Up to date") {
		t.Fatalf("7.6.7 should report up to date, got %v", steps)
	}
	if !strings.Contains(strings.Join(stepsDE, " | "), "Aktuell") {
		t.Fatalf("German path should report Aktuell, got %v", stepsDE)
	}

	// 7.6.5 patches up within its own train.
	steps, _ = getUpgradePath("7.6.5")
	if !strings.Contains(steps[0], "7.6.7") {
		t.Fatalf("7.6.5 should first patch to 7.6.7, got %v", steps)
	}

	// 7.0.12 walks the trains upward, never downward.
	steps, stepsDE = getUpgradePath("7.0.12")
	joined = strings.Join(steps, " | ")
	for _, want := range []string{"7.0.17", "7.2.13", "7.4.12", "7.6.7"} {
		if !strings.Contains(joined, want) {
			t.Errorf("7.0.12 path missing %s: %v", want, steps)
		}
	}
	if len(stepsDE) != len(steps) {
		t.Errorf("en/de paths differ in length: %d vs %d", len(steps), len(stepsDE))
	}

	// Unknown versions degrade gracefully.
	if steps, _ = getUpgradePath("bogus"); len(steps) != 1 {
		t.Fatalf("unexpected path for bogus version: %v", steps)
	}
}

func TestFindingLocalization(t *testing.T) {
	fs := []auditFinding{
		{Text: "english", TextDE: "deutsch"},
		{Text: "custom only"},
	}
	de := localizeFindings(fs, "de")
	if de[0].Text != "deutsch" || de[0].TextDE != "" {
		t.Fatalf("de localization wrong: %+v", de[0])
	}
	if de[1].Text != "custom only" {
		t.Fatal("missing translation must fall back to English")
	}
	en := localizeFindings(fs, "en")
	if en[0].Text != "english" || en[0].TextDE != "" {
		t.Fatalf("en localization wrong: %+v", en[0])
	}
	// Source slice untouched.
	if fs[0].TextDE != "deutsch" {
		t.Fatal("localizeFindings must not mutate the cached findings")
	}
}

func TestTr(t *testing.T) {
	if got := tr("de", "audit.warnings"); got != "Warnungen" {
		t.Errorf("tr(de) = %q", got)
	}
	if got := tr("en", "audit.warnings"); got != "Warnings" {
		t.Errorf("tr(en) = %q", got)
	}
	if got := tr("fr", "audit.warnings"); got != "Warnings" {
		t.Errorf("unknown lang must fall back to en, got %q", got)
	}
	if got := tr("en", "no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key must return the key, got %q", got)
	}
}

func TestGetCVEs(t *testing.T) {
	ids := func(version string) map[string]bool {
		out := map[string]bool{}
		for _, f := range getCVEs(version) {
			out[f.Key] = true
		}
		return out
	}
	if got := ids("7.0.11"); !got["cve:CVE-2023-27997"] || !got["cve:CVE-2024-21762"] || !got["cve:CVE-2024-55591"] {
		t.Errorf("7.0.11 should flag known SSL-VPN CVEs, got %v", got)
	}
	if got := ids("7.6.7"); len(got) != 0 {
		t.Errorf("7.6.7 should have no CVE findings, got %v", got)
	}
	if got := ids("6.4.10"); !got["cve:CVE-2022-42475"] || !got["eol-train"] {
		t.Errorf("6.4.10 should flag CVE-2022-42475 and EOL, got %v", got)
	}
}

func TestComplianceScores(t *testing.T) {
	pci, cis, hipaa := calculateComplianceScores(nil)
	if pci != 100 || cis != 100 || hipaa != 100 {
		t.Fatalf("no findings should score 100/100/100, got %d/%d/%d", pci, cis, hipaa)
	}
	findings := []auditFinding{{CheckID: "intf-telnet"}, {CheckID: "pwpolicy-disabled"}}
	pci, cis, hipaa = calculateComplianceScores(findings)
	if pci >= 100 || cis >= 100 || hipaa >= 100 {
		t.Fatalf("failing checks must lower every framework score, got %d/%d/%d", pci, cis, hipaa)
	}
}

func TestSplitExemptions(t *testing.T) {
	findings := []auditFinding{
		{FwID: 1, Key: "admin-no-2fa:admin", Text: "Administrator 'admin' ohne 2FA"},
		{FwID: 1, Key: "intf-telnet:wan1", Text: "Telnet auf wan1"},
	}
	exemptions := []exemption{
		{FwID: 1, FindingKey: "admin-no-2fa:admin"},           // key match
		{FwID: 2, FindingKey: "intf-telnet:wan1"},             // other firewall
		{FwID: 1, FindingKey: "", FindingText: "nicht dabei"}, // legacy, no match
	}
	active, exempted := splitExemptions(findings, exemptions, 1)
	if len(exempted) != 1 || exempted[0].Key != "admin-no-2fa:admin" {
		t.Fatalf("expected exactly the keyed exemption to match, got %+v", exempted)
	}
	if len(active) != 1 || active[0].Key != "intf-telnet:wan1" {
		t.Fatalf("expected one active finding, got %+v", active)
	}
}

func TestParseCfgBlocks(t *testing.T) {
	cfg := `config system admin
edit "admin"
set accprofile "super_admin"
next
end
config system global
set admintimeout 480
end`
	doc := parseCfg(cfg)
	g, ok := doc.block("config system global")
	if !ok {
		t.Fatal("global block not found")
	}
	val, idx, found := doc.settingDirect(g, "admintimeout")
	if !found || val != "480" || idx != 6 {
		t.Fatalf("admintimeout: val=%q idx=%d found=%t", val, idx, found)
	}
	admins := doc.blocksUnder("config system admin")
	if len(admins) != 1 || admins[0].Name != "admin" {
		t.Fatalf("expected one admin edit block, got %+v", admins)
	}
	// Context includes the matched line and the block ending.
	ctx, start := doc.context(idx, g)
	if start < 1 || !strings.Contains(ctx, "set admintimeout 480") || !strings.Contains(ctx, "end") {
		t.Fatalf("context wrong: start=%d ctx=%q", start, ctx)
	}
}

func TestSanitizeBundleName(t *testing.T) {
	cases := map[string]string{
		"fw-core-01.corp.local": "fw-core-01.corp.local.conf",
		"a b/c":                 "a_b_c.conf",
	}
	for in, want := range cases {
		if got := sanitizeBundleName(in, 1); got != want {
			t.Errorf("sanitizeBundleName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeBundleName("", 3); got != "fw-3.conf" {
		t.Errorf("empty fqdn = %q, want fw-3.conf", got)
	}
}

func TestBackupStorageStats(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "1")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sub, "a.conf"), make([]byte, 100), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "b.conf"), make([]byte, 300), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "ignore.txt"), make([]byte, 50), 0o644)

	total, week, largest, smallest := backupStorageStats(root)
	if total != 400 {
		t.Errorf("total = %d, want 400 (only .conf files)", total)
	}
	if week != 400 {
		t.Errorf("week = %d, want 400 (just written)", week)
	}
	if largest != 300 || smallest != 100 {
		t.Errorf("largest/smallest = %d/%d, want 300/100", largest, smallest)
	}
	if t2, _, _, _ := backupStorageStats(filepath.Join(root, "missing")); t2 != 0 {
		t.Errorf("missing dir total = %d, want 0", t2)
	}
}

func TestDashboardStatsJSON(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.handleDashboardStats(rr, httptest.NewRequest(http.MethodGet, "/dashboard/stats", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	for _, k := range []string{"total", "failed", "storageBytes", "nextBackup", "running"} {
		if _, ok := m[k]; !ok {
			t.Errorf("stats JSON missing key %q", k)
		}
	}
}

func TestAuditRenders(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.handleAudit(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Compliance") {
		t.Error("audit page did not render expected content")
	}
}

func TestRetryAllFailedRedirects(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.handleRetryAllFailed(rr, httptest.NewRequest(http.MethodPost, "/backup_now_all_failed", nil))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", loc)
	}
}

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter(2, time.Minute)
	if !l.allowed("k") {
		t.Fatal("fresh key allowed")
	}
	l.fail("k")
	if !l.allowed("k") {
		t.Fatal("one failure still allowed")
	}
	l.fail("k")
	if l.allowed("k") {
		t.Fatal("should block after reaching max")
	}
	l.reset("k")
	if !l.allowed("k") {
		t.Fatal("reset should clear the block")
	}
}

// TestLoginPageAnimation guards the login screen's animated backdrop: the
// radar background (grid + scan + 10 positioned pulse rings), the matrix
// "FGT → FortiSafe" logo script and the shared stylesheet must all render.
// The pulse rings are children 3-12 of the container (grid + scan occupy 1-2),
// so the position rules must target exactly that range — a regression here made
// the rings invisible once before.
func TestLoginPageAnimation(t *testing.T) {
	srv := testServer(t)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	html := rr.Body.String()
	for _, want := range []string{
		`<link rel="stylesheet" href="/static/app.css">`,
		`class="background-animation"`,
		`class="grid-overlay"`,
		`class="scan-effect"`,
		`@keyframes pulse-circle`,
		`@keyframes scan`,
		`matrixRain`,
		`id="logo-text"`,
		`id="loginShader"`,
		`class="shader-backdrop"`,
		`fsBeams`,
		`fsFlow`,
		`Math.random() < 0.1 ? fsFlow : fsBeams`,
		`prefers-reduced-motion`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("login page missing %q", want)
		}
	}
	if n := strings.Count(html, `<div class="pulse-circle">`); n != 10 {
		t.Errorf("pulse circles = %d, want 10", n)
	}
	// Every ring must have a position rule: children 3..12 of the container.
	for i := 3; i <= 12; i++ {
		sel := fmt.Sprintf(".pulse-circle:nth-child(%d)", i)
		if !strings.Contains(html, sel) {
			t.Errorf("missing position rule %s", sel)
		}
	}
	if strings.Contains(html, ".pulse-circle:nth-child(1) ") || strings.Contains(html, ".pulse-circle:nth-child(2) ") {
		t.Error("position rules target children 1-2 (grid/scan) — rings are children 3-12")
	}
	if strings.Contains(html, "src=\"http") || strings.Contains(html, "cdn.") {
		t.Error("login page must not reference external scripts (same-origin CSP)")
	}
}
