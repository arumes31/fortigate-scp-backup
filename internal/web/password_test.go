package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/session"
)

type passwordChangeCall struct {
	username string
	old      string
	new      string
}

type passwordStore struct {
	fakeStore
	calls []passwordChangeCall
	ok    bool
	err   error
}

func (s *passwordStore) ChangePassword(_ context.Context, username, oldPassword, newPassword string) (bool, error) {
	s.calls = append(s.calls, passwordChangeCall{username: username, old: oldPassword, new: newPassword})
	return s.ok, s.err
}

func passwordRequest(method, target string, form url.Values, radius bool) *http.Request {
	var body string
	if form != nil {
		body = form.Encode()
	}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return req.WithContext(session.WithTestUser(req.Context(), session.Data{
		LoggedIn: true, Username: "operator", IsRadiusUser: radius,
	}))
}

func TestChangePasswordRejectsPolicyViolationsBeforeStore(t *testing.T) {
	tests := []struct {
		name, old, newPassword, confirm, message string
	}{
		{name: "empty", old: "current-password-value", message: "Enter a new password"},
		{name: "short", old: "current-password-value", newPassword: "too-short", confirm: "too-short", message: "at least 16 UTF-8 bytes"},
		{name: "long", old: "current-password-value", newPassword: strings.Repeat("z", 73), confirm: strings.Repeat("z", 73), message: "at most 72 UTF-8 bytes"},
		{name: "unchanged", old: "current-password-value", newPassword: "current-password-value", confirm: "current-password-value", message: "different from your current password"},
		{name: "mismatch", old: "current-password-value", newPassword: "new-password-value", confirm: "different-new-value", message: "confirmation does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activity := []string{}
			store := &passwordStore{fakeStore: fakeStore{activity: &activity}, ok: true}
			srv := testServer(t)
			srv.store = store
			form := url.Values{
				"old_password": {tt.old}, "new_password": {tt.newPassword}, "confirm_password": {tt.confirm},
			}
			rr := httptest.NewRecorder()
			srv.handleChangePassword(rr, passwordRequest(http.MethodPost, "/change_password", form, false))

			if len(store.calls) != 0 {
				t.Fatalf("store called for rejected password: %#v", store.calls)
			}
			if !strings.Contains(rr.Body.String(), tt.message) {
				t.Errorf("response missing %q", tt.message)
			}
			for _, secret := range []string{tt.old, tt.newPassword, tt.confirm} {
				if secret != "" && strings.Contains(rr.Body.String(), secret) {
					t.Errorf("response echoed submitted password")
				}
				for _, entry := range activity {
					if secret != "" && strings.Contains(entry, secret) {
						t.Errorf("activity log contains submitted password")
					}
				}
			}
		})
	}
}

func TestChangePasswordUsesPRGAndAnnouncesSuccess(t *testing.T) {
	activity := []string{}
	store := &passwordStore{fakeStore: fakeStore{activity: &activity}, ok: true}
	srv := testServer(t)
	srv.store = store
	form := url.Values{
		"old_password":     {"current-password-value"},
		"new_password":     {"new-password-value"},
		"confirm_password": {"new-password-value"},
	}
	rr := httptest.NewRecorder()
	srv.handleChangePassword(rr, passwordRequest(http.MethodPost, "/change_password", form, false))
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/change_password?updated=1" {
		t.Fatalf("response = %d Location %q, want 303 PRG", rr.Code, rr.Header().Get("Location"))
	}
	if len(store.calls) != 1 {
		t.Fatalf("store calls = %d, want 1", len(store.calls))
	}
	for _, entry := range activity {
		if strings.Contains(entry, "current-password-value") || strings.Contains(entry, "new-password-value") {
			t.Fatal("activity log contains a submitted password")
		}
	}

	rr = httptest.NewRecorder()
	srv.handleChangePassword(rr, passwordRequest(http.MethodGet, "/change_password?updated=1", nil, false))
	if body := rr.Body.String(); !strings.Contains(body, `role="status"`) || !strings.Contains(body, "Password updated successfully") {
		t.Fatalf("success response is not visibly announced")
	}
}

func TestChangePasswordErrorDoesNotEchoValues(t *testing.T) {
	store := &passwordStore{ok: false, err: errors.New("synthetic database failure")}
	srv := testServer(t)
	srv.store = store
	form := url.Values{
		"old_password":     {"current-password-value"},
		"new_password":     {"new-password-value"},
		"confirm_password": {"new-password-value"},
	}
	rr := httptest.NewRecorder()
	srv.handleChangePassword(rr, passwordRequest(http.MethodPost, "/change_password", form, false))
	for _, forbidden := range []string{"current-password-value", "new-password-value", "synthetic database failure"} {
		if strings.Contains(rr.Body.String(), forbidden) {
			t.Errorf("response contains forbidden detail %q", forbidden)
		}
	}
}

func TestChangePasswordBlocksRadiusUsers(t *testing.T) {
	store := &passwordStore{ok: true}
	srv := testServer(t)
	srv.store = store
	rr := httptest.NewRecorder()
	srv.handleChangePassword(rr, passwordRequest(http.MethodGet, "/change_password", nil, true))
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
		t.Fatalf("response = %d Location %q, want blocked redirect", rr.Code, rr.Header().Get("Location"))
	}
	if len(store.calls) != 0 {
		t.Fatal("RADIUS request reached password store")
	}
}
