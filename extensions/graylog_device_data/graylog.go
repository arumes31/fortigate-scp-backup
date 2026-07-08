package graylogdevicedata

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device is one client seen behind the firewall's switches.
type Device struct {
	Mac      string `json:"mac"`
	IP       string `json:"ip"`
	Vlan     string `json:"vlan"`
	Port     string `json:"port"`
	SwitchID string `json:"switch_id"`
	Hostname string `json:"hostname"`
	LastSeen string `json:"last_seen"`

	// SharedMac/SharedIP flag devices whose MAC appears with multiple IPs /
	// whose IP appears with multiple MACs (computed at read time).
	SharedMac bool `json:"shared_mac,omitempty"`
	SharedIP  bool `json:"shared_ip,omitempty"`
}

// escapeGraylogValue escapes backslashes and double quotes so a value stays
// inside the quoted phrase and cannot break out into query operators.
func escapeGraylogValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

// sourceHost derives the Graylog `source` value from a firewall FQDN: the
// short hostname (FortiGates log with their hostname, not the FQDN).
func sourceHost(fqdn string) string {
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}

// fetchDevices queries Graylog for the firewall's device logs and returns the
// normalized, de-duplicated device list (most recent record per MAC+IP wins;
// Graylog returns messages newest-first).
func (e *Extension) fetchDevices(fqdn string) ([]Device, error) {
	graylogURL := strings.TrimRight(e.cfg.GraylogURL, "/")
	if graylogURL == "" || e.cfg.GraylogToken == "" {
		return nil, errors.New("graylog not configured (GRAYLOG_URL/GRAYLOG_TOKEN)")
	}
	timeframe := e.cfg.GraylogDeviceRange
	if timeframe == "" {
		timeframe = "86400"
	}

	query := fmt.Sprintf(e.cfg.GraylogDeviceQuery, escapeGraylogValue(sourceHost(fqdn)))
	params := url.Values{}
	params.Set("query", query)
	params.Set("range", timeframe)
	params.Set("limit", "1000")
	apiURL := graylogURL + "/api/search/universal/relative?" + params.Encode()

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(e.cfg.GraylogToken + ":token"))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("graylog returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}

	var data struct {
		Messages []struct {
			Message map[string]any `json:"message"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []Device
	for _, m := range data.Messages {
		d, ok := deviceFromMessage(m.Message)
		if !ok {
			continue
		}
		key := d.Mac + "|" + d.IP
		if seen[key] {
			continue // newest-first: keep the most recent record
		}
		seen[key] = true
		out = append(out, d)
	}
	return out, nil
}

// field returns the first non-empty message field among the candidates,
// stringified.
func field(msg map[string]any, names ...string) string {
	for _, n := range names {
		if v, ok := msg[n]; ok {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" && s != "N/A" {
				return s
			}
		}
	}
	return ""
}

// deviceFromMessage normalizes one Graylog message into a Device. FortiGate
// switch-controller / DHCP / device-detection logs vary in field naming, so
// several aliases are accepted per attribute. A record without a MAC is
// skipped.
func deviceFromMessage(msg map[string]any) (Device, bool) {
	mac := strings.ToLower(field(msg, "mac", "srcmac", "client_mac"))
	if mac == "" || mac == "00:00:00:00:00:00" {
		return Device{}, false
	}
	d := Device{
		Mac:      mac,
		IP:       field(msg, "ip", "assignedip", "srcip", "client_ip"),
		Vlan:     field(msg, "vlan", "vlanid", "vlan_id"),
		Port:     field(msg, "portname", "port", "interface", "srcintf"),
		SwitchID: field(msg, "switchid", "sn", "swname", "devid_fsw"),
		Hostname: field(msg, "hostname", "srcname", "devname_client", "computer"),
		LastSeen: field(msg, "timestamp"),
	}
	return d, true
}
