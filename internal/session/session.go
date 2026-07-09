// Package session manages authenticated sessions using signed cookies and
// reproduces the original login_required middleware: a one-hour idle timeout
// and X-Forwarded-For pinning that logs the user out on IP change.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

const (
	sessionName   = "fortisafe"
	idleTimeout   = time.Hour
	keyLoggedIn   = "logged_in"
	keyUsername   = "username"
	keyIsRadius   = "is_radius_user"
	keyLastActive = "last_activity"
	keyXForwarded = "x_forwarded_for"
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

// clientIP returns the address the session is pinned to. It mirrors the web
// layer's clientIP helper: X-Forwarded-For is honoured only when the app is
// behind a trusted proxy, otherwise the header is ignored so a direct client
// cannot spoof (or freeze) its pinned address by sending a fixed header.
func (m *Manager) clientIP(r *http.Request) string {
	if m.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.LastIndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[i+1:])
			}
			return strings.TrimSpace(xff)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
	sess.Values[keyLoggedIn] = true
	sess.Values[keyUsername] = username
	sess.Values[keyIsRadius] = isRadius
	sess.Values[keyLastActive] = time.Now().Unix()
	sess.Values[keyXForwarded] = m.clientIP(r)
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
	if d, ok := r.Context().Value(ctxKey{}).(Data); ok {
		return d
	}
	return m.Current(r)
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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("session: unable to read random bytes: " + err.Error())
	}
	return b
}
