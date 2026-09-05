package session

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestCSRFProtectedRequiresSessionTokenForUnsafeRequest covers reject and accept paths.
func TestCSRFProtectedRequiresSessionTokenForUnsafeRequest(t *testing.T) {
	t.Parallel()
	manager := New([]byte("csrf-test-key-012345678901234567890"), false, false)
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginRequest.RemoteAddr = "192.0.2.30:1234"
	loginResponse := httptest.NewRecorder()
	if err := manager.Login(loginResponse, loginRequest, "operator", true, "operator"); err != nil {
		t.Fatal(err)
	}
	cookie := loginResponse.Result().Cookies()[0]
	protected := manager.CSRFProtected(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	missing := httptest.NewRequest(http.MethodPost, "/change", strings.NewReader("value=x"))
	missing.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missing.AddCookie(cookie)
	missingResponse := httptest.NewRecorder()
	protected.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", missingResponse.Code)
	}

	valid := httptest.NewRequest(http.MethodPost, "/change", nil)
	valid.AddCookie(cookie)
	valid.Header.Set("X-CSRF-Token", manager.Current(valid).CSRFToken)
	validResponse := httptest.NewRecorder()
	protected.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid token status = %d, want 204", validResponse.Code)
	}
}

// TestCSRFProtectedPreservesMultipartBodyForHandlerLimits guards streaming semantics.
func TestCSRFProtectedPreservesMultipartBodyForHandlerLimits(t *testing.T) {
	t.Parallel()
	manager := New([]byte("multipart-csrf-key-0123456789012345"), false, false)
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", nil)
	loginRequest.RemoteAddr = "192.0.2.31:1234"
	loginResponse := httptest.NewRecorder()
	if err := manager.Login(loginResponse, loginRequest, "operator", true, "operator"); err != nil {
		t.Fatal(err)
	}
	cookie := loginResponse.Result().Cookies()[0]
	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.AddCookie(cookie)
	token := manager.Current(probe).CSRFToken

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("csrf_token", token); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("payload", "preserved"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	protected := manager.CSRFProtected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := r.ParseMultipartForm(4 << 10); err != nil {
			t.Errorf("ParseMultipartForm() error = %v", err)
			return
		}
		if got := r.FormValue("payload"); got != "preserved" {
			t.Errorf("payload = %q, want preserved", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("multipart status = %d, want 204", response.Code)
	}
}

// TestPendingTOTP_ExpiresAndIsClearedByLogin covers pre-authentication expiry.
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
	if err := manager.Login(loginResponse, pendingRequest, "admin", false, "admin"); err != nil {
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
