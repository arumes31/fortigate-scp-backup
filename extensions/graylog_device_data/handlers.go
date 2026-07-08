package graylogdevicedata

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// dataResponse is the JSON payload consumed by the topology page.
type dataResponse struct {
	FwID      int      `json:"fw_id"`
	Devices   []Device `json:"devices"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

// handleData serves the stored device inventory of a firewall.
func (e *Extension) handleData(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Error(w, "invalid firewall id", http.StatusBadRequest)
		return
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dataResponse{FwID: fwID, Devices: devices, UpdatedAt: updatedAt})
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
	if _, err := e.refreshFirewall(fwID, fqdn); err != nil {
		e.logger.Error("graylog devices: refresh failed", "fw_id", fwID, "err", err)
		http.Error(w, "graylog fetch failed", http.StatusBadGateway)
		return
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
