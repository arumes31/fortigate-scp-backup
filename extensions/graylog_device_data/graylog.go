package graylogdevicedata

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Device is one client seen behind the firewall's switches.
type Device struct {
	Mac       string `json:"mac"`
	IP        string `json:"ip"`
	Vlan      string `json:"vlan"`
	Port      string `json:"port"`
	SwitchID  string `json:"switch_id"`
	Hostname  string `json:"hostname"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen"`

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
//
// The query must match messages containing MAC addresses. FortiGate produces
// several log types with MACs: switch-controller device-detection (mac,
// portname, switchid), DHCP assignment (srcmac, assignedip), traffic logs
// (srcmac, dstmac), and device-identification (macaddr). The default query
// `source:"%s" AND (mac:* OR srcmac:* OR macaddr:*)` catches all of these.
func (e *Extension) fetchDevices(fqdn string) ([]Device, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogDeviceQuery, "GRAYLOG_DEVICE_QUERY", fqdn)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []Device
	for _, m := range msgs {
		d, ok := deviceFromMessage(m)
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

	// Diagnostic: when Graylog returns messages but none contain a MAC, log
	// at Warn so the operator can adjust GRAYLOG_DEVICE_QUERY or enable
	// device-detection / DHCP logging on the FortiGate.
	if len(msgs) > 0 && len(out) == 0 {
		e.logger.Warn("graylog returned messages but none contained a MAC address",
			"fqdn", fqdn, "total_messages", len(msgs), "query_template", e.cfg.GraylogDeviceQuery,
			"hint", "ensure GRAYLOG_DEVICE_QUERY matches logs with mac/srcmac/macaddr fields; "+
				"check that device-detection or DHCP logging is enabled on the FortiGate")
	}

	return out, nil
}

// queryGraylog runs one relative-range search with the given query template
// (%s = source host) and returns the raw messages, newest first.
func (e *Extension) queryGraylog(template, templateName, fqdn string) ([]map[string]any, error) {
	graylogURL := strings.TrimRight(e.cfg.GraylogURL, "/")
	if graylogURL == "" || e.cfg.GraylogToken == "" {
		return nil, errors.New("graylog not configured (GRAYLOG_URL/GRAYLOG_TOKEN)")
	}
	timeframe := e.cfg.GraylogDeviceRange
	if timeframe == "" {
		timeframe = "86400"
	}

	query := fmt.Sprintf(template, escapeGraylogValue(sourceHost(fqdn)))
	// A template without exactly one %s verb produces fmt error markers; catch
	// the misconfiguration here instead of sending a garbage query (which
	// Graylog may answer with every firewall's logs).
	if strings.Contains(query, "%!") {
		return nil, fmt.Errorf("%s template is invalid (needs exactly one %%s): %q", templateName, template)
	}
	params := url.Values{}
	params.Set("query", query)
	params.Set("range", timeframe)
	params.Set("limit", "1000")
	apiURL := graylogURL + "/api/search/universal/relative?" + params.Encode()

	e.logger.Debug("graylog fetch", "template", templateName, "fqdn", fqdn, "source", sourceHost(fqdn), "query", query, "range", timeframe)

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
	out := make([]map[string]any, 0, len(data.Messages))
	for _, m := range data.Messages {
		out = append(out, m.Message)
	}
	return out, nil
}

// StpPort is the latest spanning-tree / port-guard / link status of one
// switch port, derived from the FortiGate's switch-controller event logs
// ("FortiSwitch spanning Tree", BPDU/loop/root guard, port status events).
type StpPort struct {
	SwitchName string `json:"switch_name"`           // log field "name"
	Serial     string `json:"serial,omitempty"`      // log field "sn"
	Port       string `json:"port"`                  // log field "switchphysicalport"
	Role       string `json:"role,omitempty"`        // designated / root / alternate / disabled …
	State      string `json:"state,omitempty"`       // forwarding / discarding / learning …
	Guard      string `json:"guard,omitempty"`       // "bpdu-guard" / "loop-guard" / "root-guard" while triggered
	Link       string `json:"link,omitempty"`        // "up" / "down" (live link status)
	LastChange string `json:"last_change,omitempty"` // timestamp of the newest event
}

// StpEvent is one raw port event, kept as history (48h) so port details can
// show recent role/state/guard/link transitions.
type StpEvent struct {
	SwitchName string `json:"switch_name"`
	Serial     string `json:"serial,omitempty"`
	Port       string `json:"port"`
	Kind       string `json:"kind"` // "role" | "state" | "guard" | "link"
	From       string `json:"from,omitempty"`
	To         string `json:"to"`
	Time       string `json:"time,omitempty"`
}

// reStpMsg extracts the transition from event messages like
// "primary port port30 instance 0 changed state from forwarding to discarding".
var reStpMsg = regexp.MustCompile(`changed (role|state) from (\S+) to (\S+)`)

// reGuardKind identifies BPDU/loop/root guard events; reGuardClear matches
// recovery wording (port restored / re-enabled / timeout cleared).
var (
	reGuardKind  = regexp.MustCompile(`(?i)(bpdu|loop|root)[ -]?guard`)
	reGuardClear = regexp.MustCompile(`(?i)recover|restor|clear|re-?enab|normal|reset`)
	// reLinkMsg matches port link status wording ("port11 status up",
	// "link status: down", "changed status to down").
	reLinkMsg = regexp.MustCompile(`(?i)(?:link|status)\b.{0,16}?\b(up|down)\b`)
)

// stpEvent is one parsed event: exactly one kind applies.
type stpEvent struct {
	kind  string // "role" | "state" | "guard" | "link"
	from  string // previous value when the message carries one
	value string // role/state/link value, or guard kind ("" = guard cleared)
}

// fetchStpStates queries the STP/guard/port-status event logs and folds them
// into the latest status per switch port (messages arrive newest-first, so
// the first event of each kind seen per port wins). The full event list is
// returned alongside for the port history.
func (e *Extension) fetchStpStates(fqdn string) ([]StpPort, []StpEvent, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogStpQuery, "GRAYLOG_STP_QUERY", fqdn)
	if err != nil {
		return nil, nil, err
	}
	byPort := map[string]*StpPort{}
	seenKind := map[string]bool{} // key: port-key + "|" + kind
	var order []*StpPort
	var events []StpEvent
	for _, m := range msgs {
		p, ev := stpFromMessage(m)
		if p == nil {
			continue
		}
		to := ev.value
		if ev.kind == "guard" && to == "" {
			to = "recovered"
		}
		events = append(events, StpEvent{
			SwitchName: p.SwitchName, Serial: p.Serial, Port: p.Port,
			Kind: ev.kind, From: ev.from, To: to, Time: p.LastChange,
		})
		key := p.SwitchName + "|" + p.Port
		cur := byPort[key]
		if cur == nil {
			byPort[key] = p
			order = append(order, p)
			cur = p
		}
		// Newest-first: per port, only the newest event of each kind counts.
		if seenKind[key+"|"+ev.kind] {
			continue
		}
		seenKind[key+"|"+ev.kind] = true
		switch ev.kind {
		case "role":
			cur.Role = ev.value
		case "state":
			cur.State = ev.value
		case "guard":
			cur.Guard = ev.value // "" when the newest guard event is a recovery
		case "link":
			cur.Link = ev.value
		}
	}
	out := make([]StpPort, 0, len(order))
	for _, p := range order {
		out = append(out, *p)
	}
	return out, events, nil
}

// stpFromMessage normalizes one STP/guard/port-status event log message;
// returns nil when the message carries nothing parsable.
func stpFromMessage(msg map[string]any) (*StpPort, stpEvent) {
	port := field(msg, "switchphysicalport")
	name := field(msg, "name")
	sn := field(msg, "sn")
	if port == "" || (name == "" && sn == "") {
		return nil, stpEvent{}
	}
	text := field(msg, "msg", "message")
	var ev stpEvent
	if mm := reStpMsg.FindStringSubmatch(text); mm != nil {
		ev = stpEvent{kind: mm[1], from: mm[2], value: mm[3]}
	} else if gm := reGuardKind.FindStringSubmatch(text + " " + field(msg, "eventtype") + " " + field(msg, "action")); gm != nil {
		guard := strings.ToLower(gm[1]) + "-guard"
		if reGuardClear.MatchString(text) {
			guard = "" // recovery: the newest guard event clears the block
		}
		ev = stpEvent{kind: "guard", value: guard}
	} else if link := linkStatus(msg, text); link != "" {
		ev = stpEvent{kind: "link", value: link}
	} else {
		return nil, stpEvent{}
	}
	if name == "" {
		name = sn
	}
	return &StpPort{
		SwitchName: name,
		Serial:     sn,
		Port:       port,
		LastChange: field(msg, "timestamp"),
	}, ev
}

// linkStatus extracts a live "up"/"down" from port-status events: the status
// field when it carries exactly up/down (STP events use "None"), otherwise
// link-status wording in the message text.
func linkStatus(msg map[string]any, text string) string {
	if s := strings.ToLower(field(msg, "status")); s == "up" || s == "down" {
		return s
	}
	if lm := reLinkMsg.FindStringSubmatch(text); lm != nil {
		return strings.ToLower(lm[1])
	}
	return ""
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
// logs vary widely in field naming across log types:
//
//   - Switch-controller device-detection: mac, portname, switchid, vlan
//   - DHCP assignment / DHCP-snooping:    srcmac, assignedip, srcintf, vlanid
//   - Traffic logs:                       srcmac, mastersrcmac, srcip, srcname,
//     unauthuser, srcintf
//   - Device-identification:              macaddr, devtype, srcip
//   - Switch-controller events:           sn (serial), switchphysicalport
//   - NAC / RADIUS:                       client_mac, client_ip
//
// Several aliases are accepted per attribute. A record without a MAC is
// skipped.
//
// NOTE: "devname" is intentionally excluded from hostname candidates — it is
// always the FortiGate's own hostname, never the client device name.
func deviceFromMessage(msg map[string]any) (Device, bool) {
	mac := strings.ToLower(field(msg, "mac", "srcmac", "client_mac", "macaddr", "mastersrcmac", "dstmac"))
	if mac == "" || mac == "00:00:00:00:00:00" {
		return Device{}, false
	}
	d := Device{
		Mac:      mac,
		IP:       field(msg, "ip", "assignedip", "srcip", "client_ip", "dstip"),
		Vlan:     field(msg, "vlan", "vlanid", "vlan_id", "cvid"),
		Port:     field(msg, "portname", "port", "interface", "srcintf", "switchphysicalport"),
		SwitchID: field(msg, "switchid", "sn", "swname", "devid_fsw", "switch_sn"),
		Hostname: field(msg, "hostname", "srcname", "devname_client", "computer", "unauthuser"),
		LastSeen: field(msg, "timestamp"),
	}
	return d, true
}
