package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/session"
	"github.com/arumes31/fortigate-scp-backup/internal/sshhostkey"
	"golang.org/x/crypto/ssh"
)

func TestPageBaseDerivesAuthenticatedPresentationContext(t *testing.T) {
	t.Parallel()

	manager := session.New([]byte("page-base-test-key"), false, false)
	server := &Server{
		cfg: &config.Config{
			ExtAdmVpnConf:  true,
			ExtFgtConfGen:  true,
			ExtFgtConfTail: true,
		},
		sess: manager,
	}
	request := httptest.NewRequest(http.MethodGet, "/fgt-conftail/", nil)
	request.AddCookie(&http.Cookie{Name: "lang", Value: "de"})
	request = request.WithContext(session.WithTestUser(request.Context(), session.Data{
		LoggedIn: true, Username: "fixture-reviewer", IsRadiusUser: true,
	}))

	base := server.PageBase(request, "Configuration Tail", "conftail")
	if base.Title != "Configuration Tail" || base.Username != "fixture-reviewer" || base.Lang != "de" || !base.IsRadius {
		t.Fatalf("PageBase = %+v", base)
	}
	if base.Active != "conftail" || base.ReturnTo != "/fgt-conftail/" || base.Shell.PrimaryNavigation != "Primärnavigation" {
		t.Fatalf("PageBase shell context = %+v", base)
	}
	items := make(map[string]bool)
	current := make(map[string]bool)
	for _, group := range base.Navigation {
		for _, item := range group.Items {
			items[item.Key] = true
			current[item.Key] = item.Current
		}
	}
	if !items["conftail"] || !items["admvpn"] || !items["configgen"] || !current["conftail"] {
		t.Fatalf("enabled/current navigation missing: %v", items)
	}
	if _, ok := items["password"]; ok {
		t.Fatal("RADIUS user received local password navigation")
	}
	if _, ok := items["polsplit"]; ok {
		t.Fatal("disabled extension navigation is present")
	}
}

// TestPageBaseDoesNotExposeAuthenticatedShellOutsideAuthMiddleware guards public views.
func TestPageBaseDoesNotExposeAuthenticatedShellOutsideAuthMiddleware(t *testing.T) {
	t.Parallel()

	manager := session.New([]byte("public-page-test-key"), false, false)
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginRequest.RemoteAddr = "192.0.2.10:1234"
	loginRecorder := httptest.NewRecorder()
	if err := manager.Login(loginRecorder, loginRequest, "cookie-user", true, "operator"); err != nil {
		t.Fatal(err)
	}

	publicRequest := httptest.NewRequest(http.MethodGet, "/topology/shared/fixture", nil)
	publicRequest.RemoteAddr = loginRequest.RemoteAddr
	for _, cookie := range loginRecorder.Result().Cookies() {
		publicRequest.AddCookie(cookie)
	}
	server := &Server{cfg: &config.Config{ExtFgtConfTail: true}, sess: manager}

	base := server.PageBase(publicRequest, "Public share", "conftail")
	if base.Username != "" || base.IsRadius || len(base.Navigation) != 0 {
		t.Fatalf("public request received authenticated shell context: %+v", base)
	}
	if base.Title != "Public share" || base.Lang != "en" {
		t.Fatalf("public-safe presentation fields = %+v", base)
	}
}

func TestServerHostKeyCallbackConcurrentSetters(t *testing.T) {
	manager, err := sshhostkey.New(filepath.Join(t.TempDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	callback := func(string, net.Addr, ssh.PublicKey) error { return nil }
	server := &Server{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 1_000 {
			server.SetHostKeyCallback(callback)
		}
	})
	wg.Go(func() {
		<-start
		for range 1_000 {
			server.SetHostKeyManager(manager)
		}
	})
	wg.Go(func() {
		<-start
		for range 1_000 {
			_ = server.hostKeyCallbackForSSH()
		}
	})
	close(start)
	wg.Wait()
}
