package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPendingTOTP_RoundTripAndIPBinding(t *testing.T) {
	t.Parallel()

	manager := New([]byte("0123456789abcdef0123456789abcdef"), false, false)
	beginRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	beginRequest.RemoteAddr = "192.0.2.10:1234"
	beginResponse := httptest.NewRecorder()
	if err := manager.BeginTOTP(beginResponse, beginRequest, "admin"); err != nil {
		t.Fatalf("BeginTOTP() error = %v", err)
	}

	pendingRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	pendingRequest.RemoteAddr = "192.0.2.10:5678"
	pendingRequest.AddCookie(beginResponse.Result().Cookies()[0])
	if username, ok := manager.PendingTOTP(pendingRequest); !ok || username != "admin" {
		t.Fatalf("PendingTOTP() = %q, %v; want admin, true", username, ok)
	}

	otherIPRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	otherIPRequest.RemoteAddr = "192.0.2.11:5678"
	otherIPRequest.AddCookie(beginResponse.Result().Cookies()[0])
	if username, ok := manager.PendingTOTP(otherIPRequest); ok || username != "" {
		t.Fatalf("PendingTOTP() from another IP = %q, %v; want empty, false", username, ok)
	}
}

func TestPendingTOTP_ExpiresAndIsClearedByLogin(t *testing.T) {
	t.Parallel()

	manager := New([]byte("0123456789abcdef0123456789abcdef"), false, false)
	beginRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	beginRequest.RemoteAddr = "192.0.2.20:1234"
	beginResponse := httptest.NewRecorder()
	if err := manager.BeginTOTP(beginResponse, beginRequest, "admin"); err != nil {
		t.Fatalf("BeginTOTP() error = %v", err)
	}

	pendingRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	pendingRequest.RemoteAddr = beginRequest.RemoteAddr
	pendingRequest.AddCookie(beginResponse.Result().Cookies()[0])
	sess, err := manager.store.Get(pendingRequest, sessionName)
	if err != nil {
		t.Fatalf("decode pending session: %v", err)
	}
	sess.Values[keyPendingTOTPIssued] = time.Now().Add(-pendingTOTPTimeout - time.Second).Unix()
	expiredResponse := httptest.NewRecorder()
	if err := sess.Save(pendingRequest, expiredResponse); err != nil {
		t.Fatalf("save expired pending session: %v", err)
	}
	expiredRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	expiredRequest.RemoteAddr = beginRequest.RemoteAddr
	expiredRequest.AddCookie(expiredResponse.Result().Cookies()[0])
	if username, ok := manager.PendingTOTP(expiredRequest); ok || username != "" {
		t.Fatalf("expired PendingTOTP() = %q, %v; want empty, false", username, ok)
	}

	loginResponse := httptest.NewRecorder()
	if err := manager.Login(loginResponse, pendingRequest, "admin", false); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	loggedInRequest := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	loggedInRequest.RemoteAddr = beginRequest.RemoteAddr
	loggedInRequest.AddCookie(loginResponse.Result().Cookies()[0])
	if username, ok := manager.PendingTOTP(loggedInRequest); ok || username != "" {
		t.Fatalf("PendingTOTP() after Login = %q, %v; want empty, false", username, ok)
	}
	if current := manager.Current(loggedInRequest); !current.LoggedIn || current.Username != "admin" {
		t.Fatalf("Current() after Login = %+v, want logged-in admin", current)
	}
}
