package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	graylogdevicedata "github.com/arumes31/fortigate-scp-backup/extensions/graylog_device_data"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// maxShareExpiryHours bounds a public share token's lifetime (~10 years). It
// keeps time.Duration(hours) * time.Hour well within int64 so a large value
// cannot overflow into a past instant, and rejects absurd expiries.
const maxShareExpiryHours = 10 * 365 * 24

// isCheckboxOn reports whether a form checkbox value is truthy (browsers submit
// "on" for a ticked box; accept the common explicit forms too).
func isCheckboxOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

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
	Zones        []Zone        `json:"zones,omitempty"`
	DhcpServers  []DhcpServer  `json:"dhcp_servers,omitempty"`
	Sdwan        *Sdwan        `json:"sdwan,omitempty"`
	Vpns         []VpnTunnel   `json:"vpns,omitempty"`
	HA           *HAInfo       `json:"ha,omitempty"`
	APs          []FortiAP     `json:"aps,omitempty"`
	SSIDs        []WifiSSID    `json:"ssids,omitempty"`
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
		out.SwitchLinks = buildSwitchLinks(res.Switches, res.SwitchGroups, res.IslCustom)
		out.Zones = res.Zones
		out.DhcpServers = res.DhcpServers
		out.Sdwan = res.Sdwan
		out.Vpns = res.Vpns
		out.HA = res.HA
		out.APs = res.APs
		out.SSIDs = res.SSIDs
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
	Token          string `json:"token"`
	FwID           int    `json:"fw_id"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at,omitempty"` // "" = never
	IncludeDevices bool   `json:"include_devices"`      // expose the live device inventory
}

// resolveShare validates a token and returns the firewall it grants access to
// and whether the share includes the live device inventory. Expired tokens are
// treated as absent (and cleaned up).
func resolveShare(db *sql.DB, token string) (fwID int, includeDevices bool, ok bool) {
	if db == nil || token == "" || len(token) > 128 {
		return 0, false, false
	}
	var expiresAt string
	var incDev int
	err := db.QueryRow("SELECT fw_id, COALESCE(expires_at, ''), COALESCE(include_devices, 0) FROM topology_shares WHERE token = ?", token).
		Scan(&fwID, &expiresAt, &incDev)
	if err != nil {
		return 0, false, false
	}
	if expiresAt != "" {
		// Timestamps are stored as local wall-clock strings: parse them in the
		// same location, otherwise the expiry shifts by the UTC offset.
		if exp, perr := time.ParseInLocation(insightsTimeLayout, expiresAt, time.Local); perr != nil || time.Now().After(exp) {
			_, _ = db.Exec("DELETE FROM topology_shares WHERE token = ?", token)
			return 0, false, false
		}
	}
	return fwID, incDev == 1, true
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
	// An empty/absent expiry_hours means "never expires" (documented). A
	// present-but-malformed value must be rejected rather than silently
	// degrading to a never-expiring public token.
	hours := 0
	if raw := strings.TrimSpace(r.FormValue("expiry_hours")); raw != "" {
		h, herr := strconv.Atoi(raw)
		// Reject an out-of-range value rather than let time.Duration(hours) *
		// time.Hour overflow int64 (which would wrap to a past instant and mint
		// an already-expired share).
		if herr != nil || h < 0 || h > maxShareExpiryHours {
			http.Error(w, "invalid expiry_hours", http.StatusBadRequest)
			return
		}
		hours = h
	}
	if hours > 0 {
		expiresAt = now.Add(time.Duration(hours) * time.Hour).Format(insightsTimeLayout)
	}
	// Opt-in device exposure: only when the creator ticks it does the public link
	// disclose client MAC/IP/hostname/802.1X identity. Default off.
	includeDevices := isCheckboxOn(r.FormValue("include_devices"))
	incDev := 0
	if includeDevices {
		incDev = 1
	}
	if _, err := db.Exec("INSERT INTO topology_shares (token, fw_id, created_at, expires_at, include_devices) VALUES (?, ?, ?, ?, ?)",
		token, fwID, now.Format(insightsTimeLayout), expiresAt, incDev); err != nil {
		http.Error(w, "failed to store share", http.StatusInternalServerError)
		return
	}
	// Log the parsed value, never the raw form input (log injection).
	s.store.LogActivity(s.sess.User(r).Username, "topology_share_created",
		"fw_id="+strconv.Itoa(fwID)+" expiry="+strconv.Itoa(hours)+"h devices="+strconv.FormatBool(includeDevices))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(topologyShare{Token: token, FwID: fwID,
		CreatedAt: now.Format(insightsTimeLayout), ExpiresAt: expiresAt, IncludeDevices: includeDevices})
}

// handleTopologyShareList lists active share tokens (authenticated),
// optionally filtered by fw_id.
func (s *Server) handleTopologyShareList(w http.ResponseWriter, r *http.Request) {
	db, dbErr := s.insightsDB()
	if dbErr != nil || db == nil {
		http.Error(w, "Insights DB not available", http.StatusInternalServerError)
		return
	}
	query := "SELECT token, fw_id, created_at, COALESCE(expires_at, ''), COALESCE(include_devices, 0) FROM topology_shares"
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
		var incDev int
		if scanErr := rows.Scan(&sh.Token, &sh.FwID, &sh.CreatedAt, &sh.ExpiresAt, &incDev); scanErr != nil {
			continue
		}
		sh.IncludeDevices = incDev == 1
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
	Token          string
	Lang           string
	IncludeDevices bool // gates the client-side device fetch + device filter
}

// handleTopologyShared renders the public read-only topology page.
func (s *Server) handleTopologyShared(w http.ResponseWriter, r *http.Request) {
	db, _ := s.insightsDB()
	token := chi.URLParam(r, "token")
	_, includeDevices, ok := resolveShare(db, token)
	if !ok {
		s.handleNotFound(w, r)
		return
	}
	s.render(w, "topology_shared.html", topologySharedPage{Token: token, Lang: langFromRequest(r), IncludeDevices: includeDevices})
}

// handleTopologySharedDevices serves the live device inventory + overlays for a
// share token, but only when that share was created with device exposure on.
// The payload matches the authenticated /graylog-devices/data endpoint, so the
// shared frontend renders devices identically.
func (s *Server) handleTopologySharedDevices(w http.ResponseWriter, r *http.Request) {
	db, _ := s.insightsDB()
	token := chi.URLParam(r, "token")
	fwID, includeDevices, ok := resolveShare(db, token)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !includeDevices {
		// Share is structure-only: report empty rather than 403 so the frontend
		// simply renders no devices.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"devices":[]}`))
		return
	}
	payload, err := graylogdevicedata.SharedData(s.cfg.DataDir, fwID)
	if err != nil {
		s.logger.Error("shared topology devices failed", "fw_id", fwID, "err", err)
		http.Error(w, "device data unavailable", http.StatusInternalServerError)
		return
	}
	if payload == nil { // extension disabled / never fetched
		payload = []byte(`{"devices":[]}`)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

// handleTopologySharedData serves the topology JSON for a valid share token
// (public).
func (s *Server) handleTopologySharedData(w http.ResponseWriter, r *http.Request) {
	db, _ := s.insightsDB()
	token := chi.URLParam(r, "token")
	fwID, _, ok := resolveShare(db, token)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	out := s.buildTopologyJSON(r.Context(), db, fwID)
	// A share link intentionally shows the network structure (interfaces,
	// VLANs, addressing, routes, switches, zones, DHCP ranges, APs/SSIDs and
	// model) — that IS the shared topology. But it must not disclose the
	// attack surface beyond that: strip the firmware version (model + exact
	// version hands a link-holder the CVE surface), VPN peer and SD-WAN
	// next-hop addresses (external endpoints), the HA group name (it
	// participates in cluster authentication), policy rule details
	// (addresses, services, actions) and management-access lists. No
	// credential fields exist in the parsed model (PSKs/passwords are never
	// extracted).
	out.Version = ""
	for i := range out.Vpns {
		out.Vpns[i].RemoteGw = ""
	}
	if out.Sdwan != nil {
		for i := range out.Sdwan.Members {
			out.Sdwan.Members[i].Gateway = ""
		}
	}
	if out.HA != nil {
		out.HA.GroupName = ""
	}
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
