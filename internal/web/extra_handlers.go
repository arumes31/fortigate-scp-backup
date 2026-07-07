package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// handleHealthz is a liveness probe.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
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

type dashboardData struct {
	Base     BaseData
	Stats    models.DashboardStats
	Failures []models.Firewall
}

// handleDashboard renders the overview page with health counts and failures.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := s.store.DashboardStats(ctx)
	if err != nil {
		s.logger.Error("dashboard stats failed", "err", err)
	}
	failures, err := s.store.ListErrors(ctx)
	if err != nil {
		s.logger.Error("dashboard failures failed", "err", err)
	}
	s.render(w, "dashboard.html", dashboardData{
		Base:     s.base(r, "Dashboard", "dashboard"),
		Stats:    stats,
		Failures: failures,
	})
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
