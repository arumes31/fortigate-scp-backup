package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/sshhostkey"
)

// handleHealthz is a liveness probe.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	type component struct {
		Status string `json:"status"`
	}
	response := struct {
		Status     string               `json:"status"`
		Components map[string]component `json:"components"`
	}{
		Status:     "ok",
		Components: make(map[string]component),
	}
	s.healthMu.RLock()
	probes := make(map[string]func(context.Context) string, len(s.healthProbes))
	for name, probe := range s.healthProbes {
		probes[name] = probe
	}
	s.healthMu.RUnlock()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	for name, probe := range probes {
		response.Components[name] = component{Status: boundedHealthStatus(probe(ctx))}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func boundedHealthStatus(status string) string {
	switch status {
	case "healthy", "waiting", "stale", "degraded", "failed":
		return status
	default:
		return "unknown"
	}
}

// handleReadyz is a readiness probe: it verifies the database is reachable.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ready"))
}

// handleTestConnection performs an SSH/SCP reachability check and returns JSON.
func (s *Server) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	msg, terr := s.backup.TestConnection(fwID)
	resp := map[string]any{"ok": terr == nil}
	if terr != nil {
		resp["message"] = terr.Error()
	} else {
		resp["message"] = msg
	}
	s.store.LogActivity(s.sess.User(r).Username, "Test Connection",
		"fw_id "+strconv.Itoa(fwID)+": "+resp["message"].(string))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAcceptHostKey replaces a firewall's stored key with the exact
// replacement captured during the most recent failed SSH handshake.
func (s *Server) handleAcceptHostKey(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if s.hostKeyManager == nil {
		http.Error(w, "SSH host-key manager unavailable", http.StatusServiceUnavailable)
		return
	}
	firewalls, err := s.store.ListFirewalls(r.Context())
	if err != nil {
		s.logger.Error("failed to load firewall for SSH key acceptance", "fw_id", fwID, "err", err)
		http.Error(w, "failed to load firewall", http.StatusInternalServerError)
		return
	}
	var firewallFound bool
	var host string
	var port int
	for _, firewall := range firewalls {
		if firewall.ID == fwID {
			firewallFound = true
			host = firewall.FQDN
			port = firewall.SSHPort
			break
		}
	}
	if !firewallFound {
		http.Error(w, "firewall not found", http.StatusNotFound)
		return
	}
	accepted, err := s.hostKeyManager.Accept(host, port)
	if err != nil {
		s.logger.Warn("SSH host-key acceptance rejected", "fw_id", fwID, "err", err)
		if errors.Is(err, sshhostkey.ErrNoPendingKey) {
			http.Error(w, "no detected SSH key is awaiting acceptance", http.StatusConflict)
			return
		}
		http.Error(w, "failed to accept detected SSH key", http.StatusInternalServerError)
		return
	}
	s.store.LogActivity(s.sess.User(r).Username, "Accept SSH Host Key",
		"fw_id "+strconv.Itoa(fwID)+" accepted "+accepted.Fingerprint)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
