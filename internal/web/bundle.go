package web

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// handleDownloadBundle streams a ZIP containing the newest (decrypted) config of
// every firewall, named by FQDN — a one-click "restore bundle".
func (s *Server) handleDownloadBundle(w http.ResponseWriter, r *http.Request) {
	refs, err := s.store.ListFirewallRefs(r.Context())
	if err != nil {
		s.logger.Error("bundle list firewalls failed", "err", err)
		http.Error(w, "failed to list firewalls", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	added := 0
	for _, ref := range refs {
		plain, _, ok := s.latestConfig(ref.ID)
		if !ok {
			continue
		}
		fw, cerr := zw.Create(sanitizeBundleName(ref.FQDN, ref.ID))
		if cerr != nil {
			s.logger.Error("bundle zip entry failed", "fw_id", ref.ID, "err", cerr)
			continue
		}
		if _, werr := io.WriteString(fw, plain); werr != nil {
			s.logger.Error("bundle zip write failed", "fw_id", ref.ID, "err", werr)
			continue
		}
		added++
	}
	if err := zw.Close(); err != nil {
		s.logger.Error("bundle finalize failed", "err", err)
		http.Error(w, "failed to build bundle", http.StatusInternalServerError)
		return
	}

	s.store.LogActivity(s.sess.User(r).Username, "Download Bundle",
		fmt.Sprintf("Downloaded restore bundle (%d configs)", added))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="fortisafe-restore-%s.zip"`, time.Now().Format("20060102")))
	_, _ = w.Write(buf.Bytes())
}

// sanitizeBundleName turns an FQDN into a safe "<fqdn>.conf" archive entry name,
// falling back to the firewall id when the FQDN has no usable characters.
func sanitizeBundleName(fqdn string, id int) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, fqdn)
	safe = strings.Trim(safe, "._")
	if safe == "" {
		safe = fmt.Sprintf("fw-%d", id)
	}
	return safe + ".conf"
}
