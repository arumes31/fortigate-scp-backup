package web

import (
	"net/http"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// viewerUnsafeAllowed lists the only state-changing endpoints a read-only
// viewer may call: session housekeeping and the configuration search form.
var viewerUnsafeAllowed = map[string]bool{"/logout": true, "/lang": true, "/search": true}

// viewerDeniedReadPrefixes are read-only routes that still hand out raw
// configuration content or secrets (decrypted backups, config diffs, VPN
// PSK exports and generated bundles), so viewers cannot use them.
var viewerDeniedReadPrefixes = []string{
	"/download_bundle",
	"/download/",
	"/fgt-adm-vpn-conf/export",
	"/fgt-adm-vpn-conf/generate_single/",
	"/fgt-confgen/load_firewall_config",
}

// enforceRoles applies the read-only viewer role server-side. Admin and
// operator sessions pass unchanged; unauthenticated requests are left to
// LoginRequired on the individual routes.
func (s *Server) enforceRoles(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := s.sess.Current(r)
		if d.LoggedIn && d.Role == models.RoleViewer && !viewerMayAccess(r) {
			http.Error(w, "Forbidden: your account has read-only access", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// viewerMayAccess reports whether a read-only viewer may perform the request.
func viewerMayAccess(r *http.Request) bool {
	path := r.URL.Path
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		if strings.HasPrefix(path, "/backups/") && strings.HasSuffix(path, "/compare") {
			return false
		}
		for _, prefix := range viewerDeniedReadPrefixes {
			if strings.HasPrefix(path, prefix) {
				return false
			}
		}
		return true
	default:
		return viewerUnsafeAllowed[path]
	}
}
