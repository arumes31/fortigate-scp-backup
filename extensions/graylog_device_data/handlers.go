package graylogdevicedata

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// liveRangeParam validates the optional Graylog search-window override (seconds)
// passed by the topology live refresh. It accepts a positive integer clamped to
// [60, 3600]; anything else yields "" so the configured default window is used.
// The clamp also caps how far back a single request can make Graylog scan.
func liveRangeParam(s string) string {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return ""
	}
	if n < 60 {
		n = 60
	}
	if n > 3600 {
		n = 3600
	}
	return strconv.Itoa(n)
}

// dataResponse is the JSON payload consumed by the topology page.
type dataResponse struct {
	FwID          int               `json:"fw_id"`
	Devices       []Device          `json:"devices"`
	Stp           []StpPort         `json:"stp"` // [] = no blocked ports; null = STP lookup failed
	StpEvents     []StpEvent        `json:"stp_events,omitempty"`
	MultiMacPorts []MultiMacPort    `json:"multi_mac_ports,omitempty"`
	Edges         []SwitchEdge      `json:"edges,omitempty"` // trunk observations from STP/link events
	Wifi          []WifiClient      `json:"wifi,omitempty"`
	Vpn           []VpnStatus       `json:"vpn,omitempty"`
	HaDetail      string            `json:"ha_detail,omitempty"`
	FwHealth      string            `json:"fw_health,omitempty"` // live CPU/mem/sessions/uptime + HA roles (SSH)
	SwitchHealth  []SwitchHealth    `json:"switch_health,omitempty"`
	LiveRoutes    []LiveRoute       `json:"live_routes,omitempty"`
	SdwanHealth   []SdwanHealth     `json:"sdwan_health,omitempty"`
	Throughput    []IfaceThroughput `json:"throughput,omitempty"`
	DiagStatus    *CollectionStatus `json:"diag_status,omitempty"`
	UpdatedAt     string            `json:"updated_at,omitempty"`
}

// handleData serves the stored device inventory of a firewall.
func (e *Extension) handleData(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid firewall id", http.StatusBadRequest)
		return
	}
	// Viewing the topology triggers a live SSH diagnostics refresh, rate-limited
	// to at most one query per FgtDiagSSHViewSec (default 20 min) per device (the
	// hard 10 s floor still applies). It runs in the background so this response
	// returns the cached overlay immediately; the fresh state lands on the next poll.
	if e.cfg.FgtDiagSSHEnabled {
		go e.runDiagIfAllowed(fwID, time.Duration(e.cfg.FgtDiagSSHViewSec)*time.Second)
	}
	devices, updatedAt, err := e.listDevices(fwID)
	if err != nil {
		e.logger.Error("graylog devices: list failed", "fw_id", fwID, "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if devices == nil {
		devices = []Device{}
	}
	stp, err := e.listStp(fwID)
	if err != nil {
		// The STP overlay is optional: serve the inventory without it. stp is
		// nil here, so the response serializes it as `null` — a failed lookup
		// stays distinguishable from a successful "no blocked ports" (an
		// empty `[]`), rather than both looking healthy.
		e.logger.Warn("graylog devices: stp list failed", "fw_id", fwID, "err", err)
	} else if stp == nil {
		stp = []StpPort{}
	}
	// Event history and multi-MAC ports are decorations: a failure only
	// costs the extra detail, never the inventory.
	events, err := e.listStpEvents(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: stp event list failed", "fw_id", fwID, "err", err)
	}
	multiMac, err := e.listMultiMacPorts(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: multi-mac list failed", "fw_id", fwID, "err", err)
	}
	edges, err := e.listSwitchEdges(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: switch-edge list failed", "fw_id", fwID, "err", err)
	}
	wifi, err := e.listWifi(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: wifi list failed", "fw_id", fwID, "err", err)
	}
	vpn, err := e.listVpn(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: vpn list failed", "fw_id", fwID, "err", err)
	}
	swHealth, err := e.listSwitchHealth(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: switch-health list failed", "fw_id", fwID, "err", err)
	}
	liveRoutes, err := e.listLiveRoutes(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: live-routes list failed", "fw_id", fwID, "err", err)
	}
	sdwan, err := e.listSdwanHealth(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: sdwan list failed", "fw_id", fwID, "err", err)
	}
	throughput, err := e.listIfaceThroughput(fwID)
	if err != nil {
		e.logger.Warn("graylog devices: throughput list failed", "fw_id", fwID, "err", err)
	}
	ds := e.diagStatus(fwID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dataResponse{
		FwID: fwID, Devices: devices, Stp: stp,
		StpEvents: events, MultiMacPorts: multiMac, Edges: edges,
		Wifi: wifi, Vpn: vpn, HaDetail: e.haDetail(fwID), FwHealth: e.fwHealth(fwID),
		SwitchHealth: swHealth, LiveRoutes: liveRoutes,
		SdwanHealth: sdwan, Throughput: throughput, DiagStatus: &ds,
		UpdatedAt: updatedAt,
	})
}

// handleRefresh fetches the device inventory for one firewall from Graylog
// right now ("fetch device data now" in the topology view) and returns the
// fresh list.
func (e *Extension) handleRefresh(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid firewall id", http.StatusBadRequest)
		return
	}

	fqdn, err := e.firewallFQDN(fwID)
	if err != nil {
		http.Error(w, "unknown firewall", http.StatusNotFound)
		return
	}
	// Optional per-request window override: the topology "live" refresh polls
	// every ~minute and passes a small range so it scans only recent logs
	// instead of the full configured window.
	rangeSec := liveRangeParam(r.URL.Query().Get("range"))
	if _, err := e.refreshFirewall(fwID, fqdn, rangeSec); err != nil {
		e.logger.Error("graylog devices: refresh failed", "fw_id", fwID, "err", err)
		http.Error(w, "graylog fetch failed", http.StatusBadGateway)
		return
	}
	// The live button is an explicit manual refresh, so it also pulls fresh SSH
	// diagnostics synchronously (subject only to the hard rate floor, not the
	// 20-min page-view cadence) so the returned overlay reflects the live query.
	if e.cfg.FgtDiagSSHEnabled {
		e.runDiagIfAllowed(fwID, e.diagFloor())
	}
	if e.logActivity != nil {
		user := ""
		if e.currentUser != nil {
			user = e.currentUser(r)
		}
		e.logActivity(user, "graylog_device_refresh", "fw_id="+strconv.Itoa(fwID))
	}
	e.handleData(w, r)
}

// firewallFQDN resolves a firewall id to its FQDN via the shared store.
func (e *Extension) firewallFQDN(fwID int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var fqdn string
	err := e.pool.QueryRow(ctx, `SELECT fqdn FROM firewalls WHERE id = $1`, fwID).Scan(&fqdn)
	return fqdn, err
}
