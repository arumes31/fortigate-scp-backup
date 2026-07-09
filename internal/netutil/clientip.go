// Package netutil holds small HTTP networking helpers shared across layers.
package netutil

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the best-guess client address. X-Forwarded-For is honoured
// only when trustProxy is set (the app is behind a trusted reverse proxy);
// otherwise the header is ignored so a direct client cannot spoof (or freeze)
// its address by sending a fixed header. Shared by the login rate limiter and
// session IP pinning so the two stay aligned.
func ClientIP(r *http.Request, trustProxy bool) string {
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
