// Package session manages authenticated sessions using signed cookies and
// reproduces the original login_required middleware: a one-hour idle timeout
// and X-Forwarded-For pinning that logs the user out on IP change.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"net/http"
	"time"

	"github.com/gorilla/sessions"

	"github.com/arumes31/fortigate-scp-backup/internal/netutil"
)

const (
	sessionName            = "fortisafe"
	idleTimeout            = time.Hour
	pendingTOTPTimeout     = 5 * time.Minute
	keyLoggedIn            = "logged_in"
	keyUsername            = "username"
	keyIsRadius            = "is_radius_user"
	keyLastActive          = "last_activity"
	keyXForwarded          = "x_forwarded_for"
	keyPendingTOTPUsername = "pending_totp_username"
	keyPendingTOTPIssued   = "pending_totp_issued"
	keyPendingTOTPIP       = "pending_totp_ip"
)

type ctxKey struct{}

// Data is the authenticated session snapshot exposed to handlers.
type Data struct {
	LoggedIn     bool
	Username     string
	IsRadiusUser bool
}

// Manager wraps the cookie store.
type Manager struct {
	store      *sessions.CookieStore
	trustProxy bool
}

// clientIP returns the address the session is pinned to. It delegates to the
// shared netutil.ClientIP so session pinning and the login rate limiter resolve
// the address identically (X-Forwarded-For honoured only behind a trusted
// proxy, otherwise the header is ignored so a direct client cannot spoof or
// freeze its pinned address).
func (m *Manager) clientIP(r *http.Request) string {
	return netutil.ClientIP(r, m.trustProxy)
}

// New creates a Manager. When key is non-empty it is used to derive stable
// signing/encryption keys, so sessions survive restarts and are consistent
// across instances; otherwise random keys are generated per process start
// (matching the original behaviour). secure sets the cookie Secure flag;
// trustProxy controls whether X-Forwarded-For is trusted for IP pinning.
func New(key []byte, secure, trustProxy bool) *Manager {
	var hashKey, blockKey []byte
	if len(key) > 0 {
		h := sha512.Sum512(key)
		b := sha256.Sum256(key)
		hashKey = h[:]
		blockKey = b[:]
	} else {
		hashKey = randomBytes(64)
		blockKey = randomBytes(32)
	}
	store := sessions.NewCookieStore(hashKey, blockKey)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(idleTimeout.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	// NewCookieStore seeds the securecookie codec with a 30-day MaxAge; assigning
	// Options above only changes the cookie's browser Max-Age attribute, not the
	// codec's cryptographic expiry. Call MaxAge so a captured cookie stops
	// validating server-side after the idle window, not 30 days later.
	store.MaxAge(int(idleTimeout.Seconds()))
	return &Manager{store: store, trustProxy: trustProxy}
}

// Login establishes an authenticated session.
func (m *Manager) Login(w http.ResponseWriter, r *http.Request, username string, isRadius bool) error {
	sess, _ := m.store.Get(r, sessionName)
	clearPendingTOTP(sess)
	sess.Values[keyLoggedIn] = true
	sess.Values[keyUsername] = username
	sess.Values[keyIsRadius] = isRadius
	sess.Values[keyLastActive] = time.Now().Unix()
	sess.Values[keyXForwarded] = m.clientIP(r)
	return sess.Save(r, w)
}

// BeginTOTP records a short-lived, encrypted pre-authentication state after a
// local password has been verified. It deliberately stores no password or TOTP
// secret and binds the second step to the same client IP as the first.
func (m *Manager) BeginTOTP(w http.ResponseWriter, r *http.Request, username string) error {
	sess, _ := m.store.Get(r, sessionName)
	delete(sess.Values, keyLoggedIn)
	delete(sess.Values, keyUsername)
	delete(sess.Values, keyIsRadius)
	delete(sess.Values, keyLastActive)
	delete(sess.Values, keyXForwarded)
	sess.Values[keyPendingTOTPUsername] = username
	sess.Values[keyPendingTOTPIssued] = time.Now().Unix()
	sess.Values[keyPendingTOTPIP] = m.clientIP(r)
	return sess.Save(r, w)
}

// PendingTOTP returns the local username awaiting its second factor when the
// signed state is fresh and comes from the same client IP as the password step.
func (m *Manager) PendingTOTP(r *http.Request) (string, bool) {
	sess, _ := m.store.Get(r, sessionName)
	username, usernameOK := sess.Values[keyPendingTOTPUsername].(string)
	issued, issuedOK := sess.Values[keyPendingTOTPIssued].(int64)
	clientIP, ipOK := sess.Values[keyPendingTOTPIP].(string)
	if !usernameOK || username == "" || !issuedOK || !ipOK || clientIP != m.clientIP(r) {
		return "", false
	}
	age := time.Since(time.Unix(issued, 0))
	if age < 0 || age > pendingTOTPTimeout {
		return "", false
	}
	return username, true
}

// ClearPendingTOTP removes an incomplete second-factor login without creating
// an authenticated session.
func (m *Manager) ClearPendingTOTP(w http.ResponseWriter, r *http.Request) error {
	sess, _ := m.store.Get(r, sessionName)
	clearPendingTOTP(sess)
	return sess.Save(r, w)
}

// Logout clears the session.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) error {
	sess, _ := m.store.Get(r, sessionName)
	sess.Options.MaxAge = -1
	sess.Values = map[interface{}]interface{}{}
	return sess.Save(r, w)
}

// Current reads the session directly (used by unauthenticated handlers such as
// login to check existing state).
func (m *Manager) Current(r *http.Request) Data {
	sess, _ := m.store.Get(r, sessionName)
	return dataFrom(sess)
}

// User returns the authenticated session placed in context by LoginRequired.
func (m *Manager) User(r *http.Request) Data {
	if d, ok := m.AuthenticatedUser(r); ok {
		return d
	}
	return m.Current(r)
}

// AuthenticatedUser returns only session data established by LoginRequired for
// this request. Unlike User, it deliberately does not fall back to reading a
// cookie. Presentation code uses this stricter boundary so a public route can
// never acquire authenticated shell data merely because the browser happens
// to carry a valid FortiSafe session cookie.
func (m *Manager) AuthenticatedUser(r *http.Request) (Data, bool) {
	d, ok := r.Context().Value(ctxKey{}).(Data)
	return d, ok && d.LoggedIn
}

// WithTestUser returns a context carrying the given session snapshot exactly
// as LoginRequired would store it. Test helper for handler tests in other
// packages (the context key is unexported).
func WithTestUser(ctx context.Context, d Data) context.Context {
	return context.WithValue(ctx, ctxKey{}, d)
}

// LoginRequired guards a handler. It enforces the idle timeout and IP pinning,
// refreshes the activity marker, and stores the session snapshot in context.
func (m *Manager) LoginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := m.store.Get(r, sessionName)
		d := dataFrom(sess)
		if !d.LoggedIn {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Idle timeout.
		if last, ok := sess.Values[keyLastActive].(int64); ok {
			if time.Since(time.Unix(last, 0)) > idleTimeout {
				delete(sess.Values, keyLoggedIn)
				_ = sess.Save(r, w)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}

		// Client-IP pinning (trusted-proxy aware, consistent with the login
		// rate limiter). A direct client cannot spoof this with a header.
		clientIP := m.clientIP(r)
		if stored, ok := sess.Values[keyXForwarded].(string); ok && stored != clientIP {
			delete(sess.Values, keyLoggedIn)
			_ = sess.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		sess.Values[keyLastActive] = time.Now().Unix()
		sess.Values[keyXForwarded] = clientIP
		_ = sess.Save(r, w)

		ctx := context.WithValue(r.Context(), ctxKey{}, d)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func dataFrom(sess *sessions.Session) Data {
	d := Data{}
	if v, ok := sess.Values[keyLoggedIn].(bool); ok {
		d.LoggedIn = v
	}
	if v, ok := sess.Values[keyUsername].(string); ok {
		d.Username = v
	}
	if v, ok := sess.Values[keyIsRadius].(bool); ok {
		d.IsRadiusUser = v
	}
	return d
}

func clearPendingTOTP(sess *sessions.Session) {
	delete(sess.Values, keyPendingTOTPUsername)
	delete(sess.Values, keyPendingTOTPIssued)
	delete(sess.Values, keyPendingTOTPIP)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("session: unable to read random bytes: " + err.Error())
	}
	return b
}
