package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// topologyData is the topology page shell; the graph itself is fetched from
// /topology/data/{fwID} and rendered client-side with the vendored D3.
type topologyData struct {
	Base      BaseData
	Firewalls []models.FirewallRef
	Error     string
}

// handleTopology renders the standalone interactive topology page.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	refs, err := s.store.ListFirewallRefs(r.Context())
	if err != nil {
		s.logger.Error("topology list firewalls failed", "err", err)
		s.render(w, "topology.html", topologyData{Base: s.base(r, "Topologie", "topology"), Error: "Failed to load firewalls."})
		return
	}
	s.render(w, "topology.html", topologyData{
		Base:      s.base(r, "Topologie", "topology"),
		Firewalls: refs,
	})
}

// topologyJSON is the /topology/data/{fwID} response consumed by the D3 tree.
type topologyJSON struct {
	FwID         int           `json:"fw_id"`
	FQDN         string        `json:"fqdn"`
	HasConfig    bool          `json:"has_config"`
	Model        string        `json:"model,omitempty"`
	Version      string        `json:"version,omitempty"`
	Interfaces   []Interface   `json:"interfaces,omitempty"`
	Routes       []StaticRoute `json:"routes,omitempty"`
	Policies     []Policy      `json:"policies,omitempty"`
	Switches     []FortiSwitch `json:"switches,omitempty"`
	SwitchGroups []SwitchGroup `json:"switch_groups,omitempty"`
	SwitchLinks  []SwitchLink  `json:"switch_links,omitempty"`
}

// buildTopologyJSON assembles the topology payload for one firewall from the
// audit cache (computing lazily on miss). Shared by the authenticated and the
// token-shared endpoints.
func (s *Server) buildTopologyJSON(ctx context.Context, db *sql.DB, fwID int) topologyJSON {
	out := topologyJSON{FwID: fwID}
	if refs, lerr := s.store.ListFirewallRefs(ctx); lerr == nil {
		for _, ref := range refs {
			if ref.ID == fwID {
				out.FQDN = ref.FQDN
				break
			}
		}
	}
	if res, ok := s.auditResultFor(db, fwID); ok {
		out.HasConfig = true
		out.Model = res.Model
		out.Version = res.Version
		out.Interfaces = res.Interfaces
		out.Routes = res.Routes
		out.Policies = res.Policies
		out.Switches = res.Switches
		out.SwitchGroups = res.SwitchGroups
		// Derived at read time (cheap) so interlink-detection improvements do
		// not depend on cached parses.
		out.SwitchLinks = buildSwitchLinks(res.Switches)
	}
	return out
}

// handleTopologyData serves the parsed topology for one firewall.
func (s *Server) handleTopologyData(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid firewall id", http.StatusBadRequest)
		return
	}
	db, dbErr := s.insightsDB()
	if dbErr != nil || db == nil {
		s.logger.Error("insights db unavailable", "err", dbErr)
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}
	out := s.buildTopologyJSON(r.Context(), db, fwID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ---------------------------------------------------------------------------
// Public topology share links: an unguessable token grants read-only access
// to one firewall's topology (page + data) without login. Tokens live in the
// insights DB and can expire and be revoked.
// ---------------------------------------------------------------------------

// topologyShare mirrors a row of the `topology_shares` table.
type topologyShare struct {
	Token     string `json:"token"`
	FwID      int    `json:"fw_id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"` // "" = never
}

// resolveShare validates a token and returns the firewall it grants access
// to. Expired tokens are treated as absent (and cleaned up).
func resolveShare(db *sql.DB, token string) (int, bool) {
	if db == nil || token == "" || len(token) > 128 {
		return 0, false
	}
	var fwID int
	var expiresAt string
	err := db.QueryRow("SELECT fw_id, COALESCE(expires_at, '') FROM topology_shares WHERE token = ?", token).
		Scan(&fwID, &expiresAt)
	if err != nil {
		return 0, false
	}
	if expiresAt != "" {
		// Timestamps are stored as local wall-clock strings: parse them in the
		// same location, otherwise the expiry shifts by the UTC offset.
		if exp, perr := time.ParseInLocation(insightsTimeLayout, expiresAt, time.Local); perr != nil || time.Now().After(exp) {
			_, _ = db.Exec("DELETE FROM topology_shares WHERE token = ?", token)
			return 0, false
		}
	}
	return fwID, true
}

// handleTopologyShareCreate creates a share token for a firewall (POST,
// authenticated). Body: fw_id, expiry_hours (0 = never expires).
func (s *Server) handleTopologyShareCreate(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(r.FormValue("fw_id"))
	if err != nil {
		http.Error(w, "invalid firewall id", http.StatusBadRequest)
		return
	}
	db, dbErr := s.insightsDB()
	if dbErr != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}

	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(buf)

	now := time.Now()
	expiresAt := ""
	hours, herr := strconv.Atoi(r.FormValue("expiry_hours"))
	if herr != nil || hours < 0 {
		hours = 0 // never expires
	}
	if hours > 0 {
		expiresAt = now.Add(time.Duration(hours) * time.Hour).Format(insightsTimeLayout)
	}
	if _, err := db.Exec("INSERT INTO topology_shares (token, fw_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		token, fwID, now.Format(insightsTimeLayout), expiresAt); err != nil {
		http.Error(w, "failed to store share", http.StatusInternalServerError)
		return
	}
	// Log the parsed value, never the raw form input (log injection).
	s.store.LogActivity(s.sess.User(r).Username, "topology_share_created",
		"fw_id="+strconv.Itoa(fwID)+" expiry="+strconv.Itoa(hours)+"h")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(topologyShare{Token: token, FwID: fwID,
		CreatedAt: now.Format(insightsTimeLayout), ExpiresAt: expiresAt})
}

// handleTopologyShareList lists active share tokens (authenticated),
// optionally filtered by fw_id.
func (s *Server) handleTopologyShareList(w http.ResponseWriter, r *http.Request) {
	db, dbErr := s.insightsDB()
	if dbErr != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}
	query := "SELECT token, fw_id, created_at, COALESCE(expires_at, '') FROM topology_shares"
	var args []any
	if fwStr := r.URL.Query().Get("fw_id"); fwStr != "" {
		if fwID, err := strconv.Atoi(fwStr); err == nil {
			query += " WHERE fw_id = ?"
			args = append(args, fwID)
		}
	}
	rows, err := db.Query(query+" ORDER BY created_at DESC", args...)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()

	shares := []topologyShare{}
	now := time.Now()
	for rows.Next() {
		var sh topologyShare
		if scanErr := rows.Scan(&sh.Token, &sh.FwID, &sh.CreatedAt, &sh.ExpiresAt); scanErr != nil {
			continue
		}
		if sh.ExpiresAt != "" {
			if exp, perr := time.ParseInLocation(insightsTimeLayout, sh.ExpiresAt, time.Local); perr == nil && now.After(exp) {
				continue // expired: hide (cleaned lazily by resolveShare)
			}
		}
		shares = append(shares, sh)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(shares)
}

// handleTopologyShareRevoke deletes a share token (POST, authenticated).
func (s *Server) handleTopologyShareRevoke(w http.ResponseWriter, r *http.Request) {
	db, dbErr := s.insightsDB()
	if dbErr != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}
	token := r.FormValue("token")
	_, _ = db.Exec("DELETE FROM topology_shares WHERE token = ?", token)
	s.store.LogActivity(s.sess.User(r).Username, "topology_share_revoked", "token="+token)
	w.WriteHeader(http.StatusNoContent)
}

// topologySharedPage is the template payload of the public shared view.
type topologySharedPage struct {
	Token string
	Lang  string
}

// handleTopologyShared renders the public read-only topology page.
func (s *Server) handleTopologyShared(w http.ResponseWriter, r *http.Request) {
	db, _ := s.insightsDB()
	token := chi.URLParam(r, "token")
	if _, ok := resolveShare(db, token); !ok {
		s.handleNotFound(w, r)
		return
	}
	s.render(w, "topology_shared.html", topologySharedPage{Token: token, Lang: langFromRequest(r)})
}

// handleTopologySharedData serves the topology JSON for a valid share token
// (public).
func (s *Server) handleTopologySharedData(w http.ResponseWriter, r *http.Request) {
	db, _ := s.insightsDB()
	token := chi.URLParam(r, "token")
	fwID, ok := resolveShare(db, token)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	out := s.buildTopologyJSON(r.Context(), db, fwID)
	// A share link intentionally shows the network structure (interfaces,
	// VLANs, addressing, routes, switches and model) — that IS the shared
	// topology. But it must not disclose the attack surface beyond that:
	// strip the firmware version (model + exact version hands a link-holder
	// the CVE surface), policy rule details (addresses, services, actions)
	// and management-access lists.
	out.Version = ""
	for i := range out.Interfaces {
		out.Interfaces[i].AllowAccess = nil
	}
	for i := range out.Policies {
		out.Policies[i] = Policy{
			ID:      out.Policies[i].ID,
			SrcIntf: out.Policies[i].SrcIntf,
			DstIntf: out.Policies[i].DstIntf,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
