package fgtadmvpnconf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// escapeGraylogValue escapes backslashes and double quotes so a value stays
// inside the quoted phrase and cannot break out into query operators.
func escapeGraylogValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

// getGraylogStatus queries Graylog for recent logs from a single source host.
// Returns "config_missing" if Graylog isn't configured, "online" if any logs
// were found in the timeframe, "offline" if none, or "error" on any failure.
func (e *Extension) getGraylogStatus(hostname string) string {
	graylogURL := strings.TrimRight(e.cfg.GraylogURL, "/")
	graylogToken := e.cfg.GraylogToken
	timeframe := e.cfg.GraylogSearchTimeframe
	if timeframe == "" {
		timeframe = "86400"
	}

	if graylogURL == "" || graylogToken == "" {
		return "config_missing"
	}

	params := url.Values{}
	params.Set("query", fmt.Sprintf(`source:"%s"`, escapeGraylogValue(hostname)))
	params.Set("range", timeframe)
	params.Set("limit", "1")
	apiURL := graylogURL + "/api/search/universal/relative?" + params.Encode()

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "error"
	}
	auth := base64.StdEncoding.EncodeToString([]byte(graylogToken + ":token"))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()
	// urllib.request.urlopen raises for HTTP >= 400; mirror that as an error.
	if resp.StatusCode >= 400 {
		return "error"
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error"
	}
	var data struct {
		TotalResults float64 `json:"total_results"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "error"
	}
	if data.TotalResults > 0 {
		return "online"
	}
	return "offline"
}

// computeStatus checks a config: for a cluster it aggregates across all cluster
// hostnames (config_missing > error > offline > online), otherwise it checks the
// firewallname.
func (e *Extension) computeStatus(c *VpnConfig) string {
	if c.ClusterHostnames != "" {
		hostnames := splitHostnames(c.ClusterHostnames)
		if len(hostnames) == 0 {
			// cluster_hostnames set but parses to nothing -> misconfig, treat as
			// error rather than defaulting to online.
			return "error"
		}
		statuses := make([]string, 0, len(hostnames))
		for _, h := range hostnames {
			statuses = append(statuses, e.getGraylogStatus(h))
		}
		switch {
		case containsStr(statuses, "config_missing"):
			return "config_missing"
		case containsStr(statuses, "error"):
			return "error"
		case containsStr(statuses, "offline"):
			return "offline"
		default:
			return "online"
		}
	}
	return e.getGraylogStatus(c.Firewallname)
}

func containsStr(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// hookwisePayload is the JSON body sent to HookWise (field order matches Python).
type hookwisePayload struct {
	Status   string `json:"status"`
	Monitor  string `json:"monitor"`
	Device   string `json:"device"`
	Cid      string `json:"cid"`
	RemoteIP string `json:"remote_ip"`
	Message  string `json:"message"`
}

// sendHookwiseEvent sends an up/down event for a device to HookWise. It returns
// true when the event was delivered or intentionally skipped (HookWise not
// configured, missing/disabled CID), and false only when a delivery attempt was
// made and failed, so the caller can retry on the next sweep rather than losing
// the alert.
func (e *Extension) sendHookwiseEvent(c *VpnConfig, status string) bool {
	hookwiseURL := strings.TrimRight(e.cfg.HookwiseURL, "/")
	hookwiseToken := e.cfg.HookwiseToken
	if hookwiseURL == "" || hookwiseToken == "" {
		return true
	}

	if strings.TrimSpace(c.Cid) == "" {
		e.logger.Error("cannot send HookWise event: missing CID", "firewall", c.Firewallname)
		return true
	}
	if strings.TrimSpace(c.Cid) == hookwiseDisabledCID {
		e.logger.Info("HookWise alerts disabled", "firewall", c.Firewallname, "cid", hookwiseDisabledCID)
		return true
	}

	eventStatus := "DOWN"
	if status == "online" {
		eventStatus = "UP"
	}
	payload := hookwisePayload{
		Status:   eventStatus,
		Monitor:  c.Firewallname,
		Device:   c.Firewallname,
		Cid:      c.Cid,
		RemoteIP: c.RemoteipFull,
		Message:  fmt.Sprintf("FGT ADM VPN %s is %s", c.Firewallname, eventStatus),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		e.logger.Error("failed to encode HookWise payload", "firewall", c.Firewallname, "err", err)
		return true
	}

	req, err := http.NewRequest(http.MethodPost, hookwiseURL, bytes.NewReader(data))
	if err != nil {
		e.logger.Error("failed to build HookWise request", "firewall", c.Firewallname, "err", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+hookwiseToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		e.logger.Error("failed to send HookWise event", "firewall", c.Firewallname, "status", eventStatus, "err", err)
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		e.logger.Error("HookWise returned an error status", "firewall", c.Firewallname, "status", eventStatus, "code", resp.StatusCode)
		return false
	}
	return true
}

// graylogWorker re-checks every enabled device once per ~15-minute sweep and
// mirrors the current state to HookWise. It starts after a short delay so the
// app is fully up, and never returns.
func (e *Extension) graylogWorker() {
	time.Sleep(10 * time.Second)
	// Ensure schema is migrated before querying the newer columns.
	if err := e.ensureMigrations(); err != nil {
		e.logger.Error("graylog worker: migrations failed", "err", err)
	}
	for {
		if err := e.graylogSweep(); err != nil {
			e.logger.Error("Error in graylog_status_worker loop", "err", err)
			time.Sleep(60 * time.Second)
		}
	}
}

// graylogSweep performs one pass over the enabled devices, spreading the checks
// across a 15-minute window.
func (e *Extension) graylogSweep() error {
	configs, err := e.enabledConfigs()
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		time.Sleep(60 * time.Second)
		return nil
	}

	// Delay between each firewall check so they don't overlap or burst.
	delay := time.Duration(graylogCheckCycleSeconds / float64(len(configs)) * float64(time.Second))

	for _, c := range configs {
		newStatus := e.computeStatus(c)

		// Record when this device was checked (UTC).
		now := time.Now().UTC()

		// Send an up/down event ONLY on a real state transition (#74). The
		// previous status is read from the persisted LastGraylogStatus, so
		// transition detection is correct across application restarts and we do
		// not re-alert for a device whose state is unchanged. Only online/offline
		// map to UP/DOWN; error/config_missing states are never sent. We also only
		// fire when the PREVIOUS state was itself alertable (online/offline), so a
		// recovery out of error/config_missing/unknown does not raise a spurious
		// up/down alert for a state change we never reported the other side of.
		persistStatus := newStatus
		prevAlertable := c.LastGraylogStatus == "online" || c.LastGraylogStatus == "offline"
		if (newStatus == "online" || newStatus == "offline") && prevAlertable && newStatus != c.LastGraylogStatus {
			e.logger.Info("graylog status transition", "firewall", c.Firewallname, "from", c.LastGraylogStatus, "to", newStatus)
			if !e.sendHookwiseEvent(c, newStatus) {
				// Delivery failed: keep the old status so the next sweep re-detects
				// the transition and retries the alert instead of losing it.
				e.logger.Warn("HookWise delivery failed; will retry next sweep", "firewall", c.Firewallname, "status", newStatus)
				persistStatus = c.LastGraylogStatus
			}
		}

		if err := e.updateGraylogStatus(c.ID, now, persistStatus); err != nil {
			return err
		}

		time.Sleep(delay)
	}
	return nil
}
