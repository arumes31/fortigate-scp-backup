package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// radiusLogin posts RADIUS credentials and returns the response.
func radiusLogin(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {"radius-user"}, "password": {"radius-password"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.50:1234"
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

// TestRadiusGroupMapping covers the required-group gate and operator mapping.
func TestRadiusGroupMapping(t *testing.T) {
	tests := []struct {
		name      string
		required  string
		operator  string
		groups    []string
		wantLogin bool
		wantRole  string
	}{
		{name: "legacy unrestricted", wantLogin: true, wantRole: models.RoleOperator},
		{name: "required group missing", required: "fortisafe-users", groups: []string{"other"}},
		{name: "required group present", required: "fortisafe-users", groups: []string{"fortisafe-users"}, wantLogin: true, wantRole: models.RoleOperator},
		{name: "operator group member", operator: "fortisafe-ops", groups: []string{"fortisafe-ops"}, wantLogin: true, wantRole: models.RoleOperator},
		{name: "viewer outside operator group", operator: "fortisafe-ops", groups: []string{"fortisafe-users"}, wantLogin: true, wantRole: models.RoleViewer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := testServerWithAuth(t, fakeStore{}, fakeAuth{radius: true, groups: tt.groups})
			srv.cfg.RadiusEnabled = true
			srv.cfg.RadiusRequiredGroup = tt.required
			srv.cfg.RadiusOperatorGroup = tt.operator
			rr := radiusLogin(t, srv)
			if !tt.wantLogin {
				if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Invalid credentials") {
					t.Fatalf("login without required group = %d, want rejection", rr.Code)
				}
				return
			}
			if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/dashboard" {
				t.Fatalf("login = %d %q, want 302 /dashboard", rr.Code, rr.Header().Get("Location"))
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(cookieNamed(t, rr, "fortisafe"))
			if got := srv.sess.Current(req).Role; got != tt.wantRole {
				t.Fatalf("session role = %q, want %q", got, tt.wantRole)
			}
		})
	}
}

// TestViewerRoleIsReadOnly verifies the server-side viewer restrictions.
func TestViewerRoleIsReadOnly(t *testing.T) {
	srv := testServer(t)
	srv.cfg.BackupDir = t.TempDir()
	login := httptest.NewRequest(http.MethodPost, "/login", nil)
	login.RemoteAddr = "192.0.2.41:1234"
	loginResponse := httptest.NewRecorder()
	if err := srv.sess.Login(loginResponse, login, "viewer", true, models.RoleViewer); err != nil {
		t.Fatal(err)
	}
	cookie := cookieNamed(t, loginResponse, "fortisafe")

	tests := []struct {
		method    string
		path      string
		forbidden bool
	}{
		{http.MethodPost, "/delete/7", true},
		{http.MethodPost, "/ssh_host_key/accept/7", true},
		{http.MethodPost, "/topology/share", true},
		{http.MethodPost, "/fgt-adm-vpn-conf/add", true},
		{http.MethodGet, "/download_bundle", true},
		{http.MethodGet, "/download/7/file.conf", true},
		{http.MethodGet, "/backups/7/compare", true},
		{http.MethodGet, "/fgt-adm-vpn-conf/export", true},
		{http.MethodGet, "/dashboard", false},
		{http.MethodPost, "/search", false},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.RemoteAddr = login.RemoteAddr
			request.AddCookie(cookie)
			request.Header.Set("X-CSRF-Token", srv.sess.Current(request).CSRFToken)
			response := httptest.NewRecorder()
			srv.Routes().ServeHTTP(response, request)
			if got := response.Code == http.StatusForbidden; got != test.forbidden {
				t.Fatalf("%s %s status = %d, forbidden want %t", test.method, test.path, response.Code, test.forbidden)
			}
		})
	}
}

// TestLogoutRevokesOutstandingSessions checks server-side session revocation.
func TestLogoutRevokesOutstandingSessions(t *testing.T) {
	srv := testServerWithAuth(t, fakeStore{epochs: map[string]int64{}}, fakeAuth{})
	login := httptest.NewRequest(http.MethodPost, "/login", nil)
	login.RemoteAddr = "192.0.2.42:1234"
	loginResponse := httptest.NewRecorder()
	if err := srv.sess.Login(loginResponse, login, "admin", false, models.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	stolen := cookieNamed(t, loginResponse, "fortisafe")
	get := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/errors", nil)
		request.RemoteAddr = login.RemoteAddr
		request.AddCookie(stolen)
		response := httptest.NewRecorder()
		srv.Routes().ServeHTTP(response, request)
		return response
	}
	if response := get(); response.Code != http.StatusOK {
		t.Fatalf("session before logout status = %d, want 200", response.Code)
	}

	logout := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logout.RemoteAddr = login.RemoteAddr
	logout.AddCookie(stolen)
	logout.Header.Set("X-CSRF-Token", srv.sess.Current(logout).CSRFToken)
	srv.Routes().ServeHTTP(httptest.NewRecorder(), logout)

	if response := get(); response.Code != http.StatusFound || response.Header().Get("Location") != "/login" {
		t.Fatalf("replayed cookie after logout = %d %q, want redirect to /login", response.Code, response.Header().Get("Location"))
	}
}

// TestFirstLoginConfinesSessionToPasswordChange covers every protected route.
func TestFirstLoginConfinesSessionToPasswordChange(t *testing.T) {
	user := &models.User{ID: 9, Username: "admin", FirstLogin: 1, Role: models.RoleAdmin}
	srv := testServerWithAuth(t, fakeStore{loginUser: user, loginPass: "bootstrap-password"}, fakeAuth{})
	form := url.Values{"username": {"admin"}, "password": {"bootstrap-password"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.43:1234"
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Header().Get("Location") != "/change_password" {
		t.Fatalf("first login redirect = %q, want /change_password", rr.Header().Get("Location"))
	}
	cookie := cookieNamed(t, rr, "fortisafe")
	for _, path := range []string{"/dashboard", "/download_bundle", "/errors"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = req.RemoteAddr
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		srv.Routes().ServeHTTP(response, request)
		if response.Code != http.StatusFound || response.Header().Get("Location") != "/change_password" {
			t.Fatalf("%s before password change = %d %q, want redirect to /change_password", path, response.Code, response.Header().Get("Location"))
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/change_password", nil)
	request.RemoteAddr = req.RemoteAddr
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	srv.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("/change_password status = %d, want 200", response.Code)
	}
}

// TestSuccessfulLoginKeepsPerIPSprayBucket ensures one valid login does not
// reset the per-IP aggregate failure counter.
func TestSuccessfulLoginKeepsPerIPSprayBucket(t *testing.T) {
	srv := testServer(t)
	post := func(username, password string) {
		form := url.Values{"username": {username}, "password": {password}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.77:1234"
		srv.Routes().ServeHTTP(httptest.NewRecorder(), req)
	}
	for _, username := range []string{"alice", "bob"} {
		post(username, "guess")
	}
	post("admin", "changeme")
	srv.ipLimiter.mu.Lock()
	attempt := srv.ipLimiter.attempts["10.0.0.77"]
	srv.ipLimiter.mu.Unlock()
	if attempt == nil || attempt.count != 2 {
		t.Fatalf("per-IP bucket after successful login = %+v, want 2 retained failures", attempt)
	}
}

// TestClientIPIgnoresForwardedForFromUntrustedPeer covers TRUSTED_PROXIES.
func TestClientIPIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := clientIP(r, true); got != "203.0.113.9" {
		t.Fatalf("clientIP() from untrusted peer = %q, want the peer address", got)
	}
}
