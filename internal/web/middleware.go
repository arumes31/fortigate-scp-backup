package web

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// clientIP returns the best-guess client address. X-Forwarded-For is honoured
// only when trustProxy is set (the app is behind a trusted reverse proxy);
// otherwise the header is ignored so a direct client cannot spoof its address.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// XFF is appended left-to-right by each hop, so the leftmost
			// entries are client-supplied and spoofable. With a single trusted
			// reverse proxy the rightmost entry is the peer address that proxy
			// actually observed, so use it as the source IP.
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

// securityHeaders sets a conservative set of security response headers. The CSP
// allows inline styles/scripts (used by the login animation and small page
// scripts) and same-origin SSE; tighten with nonces if those are refactored.
func securityHeaders(hsts bool) func(http.Handler) http.Handler {
	const csp = "default-src 'self'; img-src 'self' data:; " +
		"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", csp)
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// accessLog logs one line per request with method, path, status, size, latency
// and the request id.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"dur_ms", time.Since(start).Milliseconds(),
			"reqid", middleware.GetReqID(r.Context()),
			"remote", r.RemoteAddr,
		)
	})
}
