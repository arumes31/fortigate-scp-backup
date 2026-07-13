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

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/backup"
	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/scheduler"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
)

// fwStore is a fakeStore that knows one firewall.
type fwStore struct{ fakeStore }

func (fwStore) ListFirewallRefs(context.Context) ([]models.FirewallRef, error) {
	return []models.FirewallRef{{ID: 1, FQDN: "fw1.example.com"}}, nil
}

// sampleConfig is a small FortiGate config exercising most checks and the
// topology parser.
const sampleConfig = `#config-version=FGT60F-7.6.5-FW-build3651-251210:opmode=0:vdom=0:user=admin
config system global
    set admin-sport 9443
    set admintimeout 480
    set rest-api-key-url-query enable
    set admin-https-redirect disable
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess ping https ssh
        set role wan
    next
    edit "internal"
        set ip 192.168.1.99 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
    edit "vlan10"
        set ip 10.0.10.1 255.255.255.0
        set interface "internal"
        set vlanid 10
    next
    edit "fortilink"
        set ip 10.255.1.1 255.255.255.0
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config switch-controller managed-switch
    edit "S124EP0000000001"
        set name "sw-office"
        config ports
            edit "port1"
                set vlan "vlan10"
            next
            edit "port2"
            next
        end
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
end
config firewall policy
    edit 1
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
`

// testServerData builds a Server with isolated DataDir/BackupDir and one
// firewall (id 1) whose latest backup is sampleConfig.
func testServerData(t *testing.T) *Server {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Load(logger)
	cfg.DataDir = t.TempDir()
	cfg.BackupDir = t.TempDir()
	cipher, _ := crypto.New(nil)
	srv, err := New(cfg, fwStore{}, scheduler.New(logger, time.UTC),
		backup.New(nil, mailer.New(cfg, logger), cfg, cipher, logger),
		session.New(nil, false, false), fakeAuth{}, cipher, logger)
	if err != nil {
		t.Fatal(err)
	}
	// Close the lazily opened SQLite handle so Windows can delete the TempDir.
	t.Cleanup(func() {
		if srv.insights != nil {
			_ = srv.insights.Close()
		}
	})
	fwDir := filepath.Join(cfg.BackupDir, "1")
	if err := os.MkdirAll(fwDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "2026-07-08_00-00-00.conf"), []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv
}

// withURLParam injects a chi URL parameter so handlers can be called directly.
func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestComputeAudit(t *testing.T) {
	res := computeAudit(1, "x.conf", sampleConfig, nil)
	if res.Model != "FGT60F" || res.Version != "7.6.5" {
		t.Fatalf("model/version = %q/%q", res.Model, res.Version)
	}
	if len(res.Interfaces) != 4 || len(res.Switches) != 1 || len(res.Policies) != 1 || len(res.Routes) != 1 {
		t.Fatalf("topology parse: intf=%d sw=%d pol=%d rt=%d",
			len(res.Interfaces), len(res.Switches), len(res.Policies), len(res.Routes))
	}
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.CheckID] = true
		if f.FwID != 1 || f.BackupFilename != "x.conf" {
			t.Fatalf("finding not attributed: %+v", f)
		}
	}
	for _, want := range []string{"admin-no-2fa", "intf-wan-mgmt", "snmp-default-community",
		"policy-any-any", "global-admintimeout", "global-rest-api-query", "pwpolicy-disabled"} {
		if !ids[want] {
			t.Errorf("expected finding %s, got %v", want, ids)
		}
	}
	// Findings are sorted critical-first.
	if len(res.Findings) == 0 || res.Findings[0].Severity != "critical" {
		t.Error("findings should be sorted critical first")
	}
	// 7.6.5 upgrades within its train, never down.
	if !strings.Contains(strings.Join(res.UpgradePath, " "), "7.6.7") {
		t.Errorf("upgrade path should target 7.6.7, got %v", res.UpgradePath)
	}
	if res.PciScore == 100 || res.CisScore == 100 {
		t.Error("failing checks must reduce compliance scores")
	}
}

func TestAuditCacheRoundtrip(t *testing.T) {
	srv := testServerData(t)
	db, err := srv.insightsDB()
	if err != nil {
		t.Fatal(err)
	}

	if _, hit := getCachedAudit(db, 1); hit {
		t.Fatal("cache should start empty")
	}
	res, ok := srv.auditResultFor(db, 1)
	if !ok {
		t.Fatal("auditResultFor failed")
	}
	cached, hit := getCachedAudit(db, 1)
	if !hit || cached.BackupFilename != res.BackupFilename || len(cached.Findings) != len(res.Findings) {
		t.Fatalf("cache miss after compute: hit=%t", hit)
	}

	// A newer backup file invalidates the cached entry.
	fwDir := filepath.Join(srv.cfg.BackupDir, "1")
	newFile := filepath.Join(fwDir, "2026-07-08_01-00-00.conf")
	if err := os.WriteFile(newFile, []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(newFile, future, future)
	res2, ok := srv.auditResultFor(db, 1)
	if !ok || res2.BackupFilename == res.BackupFilename {
		t.Fatalf("expected recompute for newer backup, got %q", res2.BackupFilename)
	}
}

func TestWarmAuditCache(t *testing.T) {
	srv := testServerData(t)
	srv.WarmAuditCache(1)
	db, _ := srv.insightsDB()
	if _, hit := getCachedAudit(db, 1); !hit {
		t.Fatal("WarmAuditCache should populate the cache")
	}
	// Unknown firewall: no panic, no cache entry.
	srv.WarmAuditCache(99)
	if _, hit := getCachedAudit(db, 99); hit {
		t.Fatal("unexpected cache entry for unknown firewall")
	}
}

func TestAuditResultsEndpoint(t *testing.T) {
	srv := testServerData(t)

	rr := httptest.NewRecorder()
	srv.handleAuditResults(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/audit/results/1", nil), "fwID", "1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var out auditRowJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.HasConfig || out.Version != "7.6.5" || len(out.Findings) == 0 {
		t.Fatalf("unexpected payload: has=%t ver=%q findings=%d", out.HasConfig, out.Version, len(out.Findings))
	}
	var withCtx int
	for _, f := range out.Findings {
		if f.Context != "" && f.Line > 0 {
			withCtx++
		}
	}
	if withCtx == 0 {
		t.Error("findings should carry line context")
	}

	// Firewall without a backup reports has_config=false.
	rr = httptest.NewRecorder()
	srv.handleAuditResults(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/audit/results/7", nil), "fwID", "7"))
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.HasConfig {
		t.Fatalf("firewall 7 should have no config (err=%v)", err)
	}

	// Invalid id is a 400.
	rr = httptest.NewRecorder()
	srv.handleAuditResults(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/audit/results/x", nil), "fwID", "x"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestAuditExemptionFlow(t *testing.T) {
	srv := testServerData(t)

	// Compute once to know a real finding key.
	db, _ := srv.insightsDB()
	res, _ := srv.auditResultFor(db, 1)
	key := ""
	for _, f := range res.Findings {
		if f.CheckID == "admin-no-2fa" {
			key = f.Key
		}
	}
	if key == "" {
		t.Fatal("expected an admin-no-2fa finding")
	}

	form := url.Values{"fw_id": {"1"}, "finding_key": {key}, "finding_text": {"x"}, "reason": {"test"}}
	req := httptest.NewRequest(http.MethodPost, "/audit/exemption", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleAuditExemption(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	srv.handleAuditResults(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/audit/results/1", nil), "fwID", "1"))
	var out auditRowJSON
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	found := false
	for _, f := range out.Exempted {
		if f.Key == key {
			found = true
		}
	}
	if !found {
		t.Fatal("exempted finding missing from results")
	}
	for _, f := range out.Findings {
		if f.Key == key {
			t.Fatal("exempted finding still active")
		}
	}
}

func TestCustomRuleBustsCache(t *testing.T) {
	srv := testServerData(t)
	db, _ := srv.insightsDB()
	if _, ok := srv.auditResultFor(db, 1); !ok {
		t.Fatal("compute failed")
	}

	form := url.Values{"name": {"r1"}, "pattern": {"set admin-sport 9443"}, "severity": {"info"}, "remediation": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/audit/custom_rule", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleAuditCustomRule(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}
	if _, hit := getCachedAudit(db, 1); hit {
		t.Fatal("custom rule change must bust the audit cache")
	}

	// Recompute picks the custom rule up, anchored to the matching line.
	res, _ := srv.auditResultFor(db, 1)
	var hit bool
	for _, f := range res.Findings {
		if f.CheckID == "custom" && f.Line > 0 && strings.Contains(f.Context, "set admin-sport 9443") {
			hit = true
		}
	}
	if !hit {
		t.Fatal("custom rule finding with line context missing")
	}
}

func TestTopologyDataEndpoint(t *testing.T) {
	srv := testServerData(t)
	rr := httptest.NewRecorder()
	srv.handleTopologyData(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/data/1", nil), "fwID", "1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var out topologyJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.HasConfig || out.FQDN != "fw1.example.com" || len(out.Interfaces) != 4 || len(out.Switches) != 1 {
		t.Fatalf("unexpected topology payload: %+v", out)
	}
	if out.Switches[0].Name != "sw-office" || len(out.Switches[0].Ports) != 2 {
		t.Fatalf("switch parse wrong: %+v", out.Switches[0])
	}
}

func TestTopologyShareLifecycle(t *testing.T) {
	srv := testServerData(t)

	// Create.
	form := url.Values{"fw_id": {"1"}, "expiry_hours": {"24"}}
	req := httptest.NewRequest(http.MethodPost, "/topology/share", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleTopologyShareCreate(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: want 200, got %d", rr.Code)
	}
	var share topologyShare
	if err := json.Unmarshal(rr.Body.Bytes(), &share); err != nil || len(share.Token) != 48 {
		t.Fatalf("bad share response: %v %q", err, share.Token)
	}
	if share.ExpiresAt == "" {
		t.Fatal("24h share must carry an expiry")
	}

	// List.
	rr = httptest.NewRecorder()
	srv.handleTopologyShareList(rr, httptest.NewRequest(http.MethodGet, "/topology/shares?fw_id=1", nil))
	var shares []topologyShare
	if err := json.Unmarshal(rr.Body.Bytes(), &shares); err != nil || len(shares) != 1 {
		t.Fatalf("list: err=%v n=%d", err, len(shares))
	}

	// Public data endpoint works without auth (direct handler call).
	rr = httptest.NewRecorder()
	srv.handleTopologySharedData(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/shared/x/data", nil), "token", share.Token))
	if rr.Code != http.StatusOK {
		t.Fatalf("shared data: want 200, got %d", rr.Code)
	}
	var out topologyJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || !out.HasConfig {
		t.Fatalf("shared data payload wrong: %v", err)
	}

	// Public page renders.
	rr = httptest.NewRecorder()
	srv.handleTopologyShared(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/shared/x", nil), "token", share.Token))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), share.Token) {
		t.Fatalf("shared page: code=%d", rr.Code)
	}

	// Bad token 404s.
	rr = httptest.NewRecorder()
	srv.handleTopologySharedData(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/shared/x/data", nil), "token", "deadbeef"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("bad token: want 404, got %d", rr.Code)
	}

	// Revoke kills access.
	form = url.Values{"token": {share.Token}}
	req = httptest.NewRequest(http.MethodPost, "/topology/share/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.handleTopologyShareRevoke(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: want 204, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	srv.handleTopologySharedData(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/shared/x/data", nil), "token", share.Token))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("after revoke: want 404, got %d", rr.Code)
	}
}

// TestTopologyShareDeviceInclusion verifies the per-share device toggle: a share
// created without it exposes no devices on the public devices endpoint, one
// created with it is flagged include_devices and serves a device payload (empty
// here, since the extension DB is absent — the point is the gating, not content).
func TestTopologyShareDeviceInclusion(t *testing.T) {
	srv := testServerData(t)
	mk := func(withDevices string) topologyShare {
		form := url.Values{"fw_id": {"1"}, "expiry_hours": {"24"}, "include_devices": {withDevices}}
		req := httptest.NewRequest(http.MethodPost, "/topology/share", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.handleTopologyShareCreate(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("create(%s): want 200, got %d", withDevices, rr.Code)
		}
		var sh topologyShare
		if err := json.Unmarshal(rr.Body.Bytes(), &sh); err != nil {
			t.Fatalf("create(%s): %v", withDevices, err)
		}
		return sh
	}
	devicesResp := func(token string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		srv.handleTopologySharedDevices(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/shared/x/devices", nil), "token", token))
		return rr
	}

	// Off: flag false, endpoint returns an empty device set.
	off := mk("0")
	if off.IncludeDevices {
		t.Error("share created with include_devices=0 must not be flagged")
	}
	rr := devicesResp(off.Token)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"devices":[]`) {
		t.Fatalf("off devices: code=%d body=%s", rr.Code, rr.Body.String())
	}

	// On: flag true, endpoint serves a payload (200, valid JSON with a devices key).
	on := mk("1")
	if !on.IncludeDevices {
		t.Error("share created with include_devices=1 must be flagged")
	}
	rr = devicesResp(on.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("on devices: want 200, got %d", rr.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("on devices: invalid JSON: %v", err)
	}
	if _, hasDevices := payload["devices"]; !hasDevices {
		t.Errorf("on devices: payload missing 'devices' key: %v", payload)
	}

	// Bad token still 404s on the devices endpoint.
	if rr := devicesResp("deadbeef"); rr.Code != http.StatusNotFound {
		t.Fatalf("bad token devices: want 404, got %d", rr.Code)
	}
}

func TestExpiredShareRejected(t *testing.T) {
	srv := testServerData(t)
	db, _ := srv.insightsDB()
	_, err := db.Exec("INSERT INTO topology_shares (token, fw_id, created_at, expires_at) VALUES (?, 1, ?, ?)",
		"expiredtoken", time.Now().Add(-2*time.Hour).Format("2006-01-02 15:04:05"),
		time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := resolveShare(db, "expiredtoken"); ok {
		t.Fatal("expired token must not resolve")
	}
	// Expired token is cleaned up lazily.
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM topology_shares WHERE token = 'expiredtoken'").Scan(&n)
	if n != 0 {
		t.Fatal("expired token should be deleted on resolve")
	}
}

func TestTopologyPageRenders(t *testing.T) {
	srv := testServerData(t)
	rr := httptest.NewRecorder()
	srv.handleTopology(rr, httptest.NewRequest(http.MethodGet, "/topology", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "fw1.example.com") || !strings.Contains(body, "topology.js") {
		t.Error("topology page missing expected content")
	}
}

func TestSharedRoutesArePublic(t *testing.T) {
	srv := testServerData(t)
	// Unknown token on the public route: must NOT redirect to /login, must 404.
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/topology/shared/unknowntoken", nil))
	if rr.Code == http.StatusFound {
		t.Fatal("shared topology route must not require login")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown token: want 404, got %d", rr.Code)
	}
}

func TestAuditTicketEndpoint(t *testing.T) {
	srv := testServerData(t)
	form := url.Values{"backup_filename": {"2026-07-08_00-00-00.conf"}, "ticket_id": {"INC-1"}, "details": {"change"}}
	req := httptest.NewRequest(http.MethodPost, "/audit/ticket", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleAuditTicket(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rr.Code)
	}

	// The ticket shows up in the results payload.
	rr = httptest.NewRecorder()
	srv.handleAuditResults(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/audit/results/1", nil), "fwID", "1"))
	var out auditRowJSON
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.TicketID != "INC-1" || out.TicketDetail != "change" {
		t.Fatalf("ticket not linked: %q/%q", out.TicketID, out.TicketDetail)
	}

	// GET is rejected.
	rr = httptest.NewRecorder()
	srv.handleAuditTicket(rr, httptest.NewRequest(http.MethodGet, "/audit/ticket", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

func TestExemptionAndRuleDelete(t *testing.T) {
	srv := testServerData(t)
	db, _ := srv.insightsDB()
	if _, err := db.Exec("INSERT INTO exemptions (fw_id, finding_key, finding_text, reason, created_at) VALUES (1, 'k', 't', 'r', '2026-07-08 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO custom_rules (name, pattern, severity, remediation) VALUES ('r', 'p', 'info', 'x')"); err != nil {
		t.Fatal(err)
	}

	post := func(path string, form url.Values, h http.HandlerFunc) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h(rr, req)
		return rr.Code
	}

	if code := post("/audit/exemption", url.Values{"action": {"delete"}, "id": {"1"}}, srv.handleAuditExemption); code != http.StatusSeeOther {
		t.Fatalf("exemption delete: want 303, got %d", code)
	}
	if got := loadExemptions(db); len(got) != 0 {
		t.Fatalf("exemption not deleted: %+v", got)
	}
	if code := post("/audit/custom_rule", url.Values{"action": {"delete"}, "id": {"1"}}, srv.handleAuditCustomRule); code != http.StatusSeeOther {
		t.Fatalf("rule delete: want 303, got %d", code)
	}
	if got := loadCustomRules(db); len(got) != 0 {
		t.Fatalf("rule not deleted: %+v", got)
	}
}

func TestAuditShellRendersFirewalls(t *testing.T) {
	srv := testServerData(t)
	rr := httptest.NewRecorder()
	srv.handleAudit(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "fw1.example.com") || !strings.Contains(body, "/audit/results/") {
		t.Error("audit shell missing firewall row or async loader")
	}
	// The shell must not contain computed findings (they load async).
	if strings.Contains(body, "admin-no-2fa") {
		t.Error("audit shell should not embed computed findings")
	}
}

func TestCheckAutoInstallAndFabricAndSSLVPNBranches(t *testing.T) {
	cfg := `config system auto-install
    set auto-install-config enable
    set auto-install-image enable
end
config system csf
    set status enable
end
config vpn ssl settings
    set status disable
    set port 443
    set source-interface "wan1"
end`
	ids := findingIDs(structuralFindings(cfg))
	if _, ok := ids["auto-install-usb"]; !ok {
		t.Error("enabled auto-install should be flagged")
	}
	if _, ok := ids["fabric-csf"]; ok {
		t.Error("configured CSF must not raise fabric-csf")
	}
	if _, ok := ids["sslvpn-default-port"]; ok {
		t.Error("disabled SSL-VPN must not raise port findings")
	}

	// Weak TLS on an active SSL-VPN.
	weak := `config vpn ssl settings
    set port 8443
    set source-interface "wan1"
    set source-address "mgmt-net"
    set ssl-min-proto-ver tls1-1
end`
	ids = findingIDs(structuralFindings(weak))
	if f, ok := ids["sslvpn-weak-tls"]; !ok || f.Severity != "critical" {
		t.Error("weak SSL-VPN TLS should be critical")
	}
	if _, ok := ids["sslvpn-default-port"]; ok {
		t.Error("non-default port must not be flagged")
	}
	if _, ok := ids["sslvpn-no-source-address"]; ok {
		t.Error("restricted source-address must not be flagged")
	}
}

func TestSplitVersionEdgeCases(t *testing.T) {
	for _, bad := range []string{"", "7", "7.6", "a.b.c", "7.x.1"} {
		if _, _, _, ok := splitVersion(bad); ok {
			t.Errorf("splitVersion(%q) should fail", bad)
		}
	}
	if maj, min, pat, ok := splitVersion("7.6.5"); !ok || maj != 7 || min != 6 || pat != 5 {
		t.Errorf("splitVersion(7.6.5) = %d.%d.%d ok=%t", maj, min, pat, ok)
	}
}

func TestChangePWHiddenForRadiusUsers(t *testing.T) {
	srv := testServerData(t)

	// Local user: link visible.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req = req.WithContext(session.WithTestUser(req.Context(), session.Data{LoggedIn: true, Username: "admin"}))
	srv.handleAudit(rr, req)
	if !strings.Contains(rr.Body.String(), "/change_password") {
		t.Error("local user should see the Change_PW link")
	}

	// RADIUS user: link hidden.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/audit", nil)
	req = req.WithContext(session.WithTestUser(req.Context(), session.Data{LoggedIn: true, Username: "rad", IsRadiusUser: true}))
	srv.handleAudit(rr, req)
	if strings.Contains(rr.Body.String(), "/change_password") {
		t.Error("RADIUS user must not see the Change_PW link")
	}
}

func TestVDOMConfigsAreAudited(t *testing.T) {
	// Multi-VDOM configs nest the sections under "config global" /
	// "config vdom > edit <name>"; the checks must still fire (regression:
	// they used to silently no-op, reporting a false-clean audit).
	cfg := `#config-version=FGT100F-7.2.5-FW-build1517-230608:opmode=0:vdom=1:user=admin
config vdom
edit root
config system interface
    edit "wan1"
        set allowaccess ping https ssh telnet
        set role wan
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
next
end
config global
config system global
    set admintimeout 480
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
end`
	ids := findingIDs(structuralFindings(cfg))
	for _, want := range []string{"intf-telnet", "intf-wan-mgmt", "global-admintimeout", "admin-no-2fa", "policy-any-any"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("VDOM config should raise %s, got %v", want, keysOf(ids))
		}
	}
}

func keysOf(m map[string]auditFinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLegacyExemptionBackfill(t *testing.T) {
	srv := testServerData(t)
	db, err := srv.insightsDB()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate pre-upgrade rows: German texts, empty finding_key.
	legacy := []string{
		"Telnet-Management aktiviert (allowaccess telnet)",
		"Administrator 'daniel' hat keine Zwei-Faktor-Authentifizierung (2FA) aktiviert",
		"Shadow-Rule ID 12: wird durch ID 3 blockiert",
		"Kritische Sicherheitslücke CVE-2024-21762 (SSL-VPN Out-of-bounds Write RCE)",
		"völlig unbekannter Text",
	}
	for _, text := range legacy {
		if _, err := db.Exec("INSERT INTO exemptions (fw_id, finding_key, finding_text, reason, created_at) VALUES (1, '', ?, 'r', '2026-01-01 00:00:00')", text); err != nil {
			t.Fatal(err)
		}
	}
	srv.backfillExemptionKeys(db)

	got := map[string]string{}
	for _, ex := range loadExemptions(db) {
		got[ex.FindingText] = ex.FindingKey
	}
	want := map[string]string{
		legacy[0]: "check:intf-telnet",
		legacy[1]: "admin-no-2fa:daniel",
		legacy[2]: "shadow-rule:12-3",
		legacy[3]: "cve:CVE-2024-21762",
		legacy[4]: "", // unmapped rows stay visible but keyless
	}
	for text, key := range want {
		if got[text] != key {
			t.Errorf("backfill(%q) = %q, want %q", text, got[text], key)
		}
	}

	// A backfilled check:-key exempts every instance of that check.
	findings := []auditFinding{
		{FwID: 1, CheckID: "intf-telnet", Key: "intf-telnet:wan1", Text: "Telnet management enabled on interface 'wan1' (unencrypted)"},
		{FwID: 1, CheckID: "intf-telnet", Key: "intf-telnet:dmz", Text: "Telnet management enabled on interface 'dmz' (unencrypted)"},
		{FwID: 1, CheckID: "intf-http", Key: "intf-http:wan1", Text: "Plaintext HTTP management enabled on interface 'wan1'"},
	}
	active, exempted := splitExemptions(findings, loadExemptions(db), 1)
	if len(exempted) != 2 {
		t.Fatalf("check:intf-telnet should exempt both telnet findings, got %d", len(exempted))
	}
	if len(active) != 1 || active[0].CheckID != "intf-http" {
		t.Fatalf("http finding must stay active, got %+v", active)
	}
}

func TestExemptionRestoresComplianceScore(t *testing.T) {
	srv := testServerData(t)
	db, _ := srv.insightsDB()
	res, _ := srv.auditResultFor(db, 1)

	// Exempt every finding of the firewall: the served scores must recover to
	// 100 even though the cached (pre-exemption) scores are lower.
	for _, f := range res.Findings {
		if _, err := db.Exec("INSERT INTO exemptions (fw_id, finding_key, finding_text, reason, created_at) VALUES (1, ?, ?, 'r', '2026-01-01 00:00:00')", f.Key, f.Text); err != nil {
			t.Fatal(err)
		}
	}
	rr := httptest.NewRecorder()
	srv.handleAuditResults(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/audit/results/1", nil), "fwID", "1"))
	var out auditRowJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("all findings should be exempted, %d active", len(out.Findings))
	}
	if out.PciScore != 100 || out.CisScore != 100 || out.HipaaScore != 100 {
		t.Fatalf("exempting everything must restore scores to 100, got %d/%d/%d", out.PciScore, out.CisScore, out.HipaaScore)
	}
}

func TestCustomRuleFingerprintInvalidatesCache(t *testing.T) {
	srv := testServerData(t)
	db, _ := srv.insightsDB()
	if _, ok := srv.auditResultFor(db, 1); !ok {
		t.Fatal("compute failed")
	}
	// Insert a rule WITHOUT the handler's cache bust: the fingerprint alone
	// must force a recompute (this is the race fix — a stale entry stored
	// after the bust is detected too).
	if _, err := db.Exec("INSERT INTO custom_rules (name, pattern, severity, remediation) VALUES ('r1', 'set admin-sport 9443', 'info', 'x')"); err != nil {
		t.Fatal(err)
	}
	res, _ := srv.auditResultFor(db, 1)
	var hit bool
	for _, f := range res.Findings {
		if f.CheckID == "custom" {
			hit = true
		}
	}
	if !hit {
		t.Fatal("rule-set change must invalidate the cached audit via fingerprint")
	}
}

func TestSharedTopologyHidesPolicyDetails(t *testing.T) {
	srv := testServerData(t)
	form := url.Values{"fw_id": {"1"}, "expiry_hours": {"24"}}
	req := httptest.NewRequest(http.MethodPost, "/topology/share", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleTopologyShareCreate(rr, req)
	var share topologyShare
	_ = json.Unmarshal(rr.Body.Bytes(), &share)

	rr = httptest.NewRecorder()
	srv.handleTopologySharedData(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "token", share.Token))
	var out topologyJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) == 0 {
		t.Fatal("shared payload should keep policy counts")
	}
	for _, p := range out.Policies {
		if len(p.SrcAddr) != 0 || len(p.DstAddr) != 0 || len(p.Service) != 0 || p.Action != "" {
			t.Fatalf("shared payload must not leak rule details: %+v", p)
		}
	}
	for _, in := range out.Interfaces {
		if len(in.AllowAccess) != 0 {
			t.Fatalf("shared payload must not leak management access lists: %+v", in)
		}
	}
	// The authenticated endpoint still carries them.
	rr = httptest.NewRecorder()
	srv.handleTopologyData(rr, withURLParam(httptest.NewRequest(http.MethodGet, "/topology/data/1", nil), "fwID", "1"))
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Policies) == 0 || len(out.Policies[0].SrcAddr) == 0 {
		t.Fatal("authenticated payload should keep full policies")
	}
}

func TestSetLangRejectsExternalRedirects(t *testing.T) {
	srv := testServerData(t)
	for back, want := range map[string]string{
		"/audit":          "/audit",
		"//evil.example":  "/",
		"/\\evil.example": "/",
		"https://evil":    "/",
		"":                "/",
	} {
		form := url.Values{"lang": {"de"}, "back": {back}}
		req := httptest.NewRequest(http.MethodPost, "/lang", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.handleSetLang(rr, req)
		if loc := rr.Header().Get("Location"); loc != want {
			t.Errorf("back=%q redirected to %q, want %q", back, loc, want)
		}
	}
}

func TestGetCVEsNeverFixedTrains(t *testing.T) {
	keys := map[string]bool{}
	for _, f := range getCVEs("6.2.16") {
		keys[f.Key] = true
	}
	if !keys["cve:CVE-2024-21762"] {
		t.Error("6.2 has no fix for CVE-2024-21762 and must be flagged")
	}
	keys = map[string]bool{}
	for _, f := range getCVEs("6.0.17") {
		keys[f.Key] = true
	}
	if !keys["cve:CVE-2022-42475"] || !keys["cve:CVE-2024-21762"] {
		t.Errorf("6.0 must be flagged for never-fixed CVEs, got %v", keys)
	}
}

func TestComputeAuditExampleConf(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "example.conf"))
	if err != nil {
		t.Skip("example.conf not available")
	}
	res := computeAudit(1, "example.conf", string(raw), nil)
	if res.Model == "" || res.Version == "" {
		t.Fatalf("model/version not detected: %q %q", res.Model, res.Version)
	}
	if len(res.Interfaces) == 0 || len(res.Policies) == 0 {
		t.Fatalf("real config should parse interfaces/policies, got %d/%d", len(res.Interfaces), len(res.Policies))
	}
	// The example config enables rest-api-key-url-query: must be detected with
	// a valid line anchor.
	var hit bool
	for _, f := range res.Findings {
		if f.CheckID == "global-rest-api-query" {
			hit = true
			if f.Line <= 0 || !strings.Contains(f.Context, "rest-api-key-url-query") {
				t.Errorf("finding lacks context: %+v", f)
			}
		}
	}
	if !hit {
		t.Error("example.conf should trigger global-rest-api-query")
	}
	for _, step := range res.UpgradePath {
		if strings.Contains(step, "-> 7.6.0") {
			t.Errorf("upgrade path suggests a downgrade: %v", res.UpgradePath)
		}
	}
}
