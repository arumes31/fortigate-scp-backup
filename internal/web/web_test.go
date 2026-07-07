package web

import (
	"context"
	"encoding/json"
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
		session.New(nil, false), fakeAuth{}, cipher, logger)
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

func TestAuditFindings(t *testing.T) {
	cfg := `config system interface
edit "wan1"
set allowaccess ping https ssh telnet
next
edit "mgmt"
set allowaccess https http
next
end`
	var crit, warn bool
	for _, f := range auditFindings(cfg) {
		switch f.Severity {
		case "critical":
			crit = true
		case "warning":
			warn = true
		}
	}
	if !crit {
		t.Error("telnet allowaccess should raise a critical finding")
	}
	if !warn {
		t.Error("plaintext http allowaccess should raise a warning")
	}
	clean := auditFindings("config system global\nend")
	if len(clean) != 1 || clean[0].Severity != "info" {
		t.Fatalf("clean config should yield one info finding, got %+v", clean)
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
