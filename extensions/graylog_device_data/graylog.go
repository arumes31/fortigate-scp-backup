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
	"slices"
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

	// Endpoint fingerprint from FortiGate device-identification (traffic logs).
	DevType   string `json:"devtype,omitempty"`
	OsName    string `json:"osname,omitempty"`
	OsVersion string `json:"osversion,omitempty"`
	Vendor    string `json:"vendor,omitempty"`

	// Wireless association (enriched from wireless assoc logs, by MAC).
	Ap     string `json:"ap,omitempty"`
	Ssid   string `json:"ssid,omitempty"`
	Signal string `json:"signal,omitempty"`

	// SharedMac/SharedIP flag devices whose MAC appears with multiple IPs /
	// whose IP appears with multiple MACs (computed at read time).
	SharedMac bool `json:"shared_mac,omitempty"`
	SharedIP  bool `json:"shared_ip,omitempty"`
}

// MacPort is one client MAC's current wired switch + physical port, derived
// from FortiSwitch MAC add/move events (the port lives in free-text msg).
// Deleted marks a MAC-delete tombstone: the newest event for the MAC says it
// left the table, so any stored binding must be dropped, not updated.
type MacPort struct {
	Mac        string
	Port       string
	Vlan       string
	SwitchName string
	Deleted    bool
}

// WifiClient is one wireless client's live association (client↔AP↔SSID).
type WifiClient struct {
	Mac     string `json:"mac"`
	Ap      string `json:"ap"`
	Ssid    string `json:"ssid"`
	Signal  string `json:"signal,omitempty"`
	Channel string `json:"channel,omitempty"`
	Vlan    string `json:"vlan,omitempty"`
}

// VpnStatus is one IPsec/SSL tunnel's last-known up/down state and remote peer.
type VpnStatus struct {
	Name   string `json:"name"`
	RemIP  string `json:"remip,omitempty"`
	Type   string `json:"type,omitempty"`   // ipsec | ssl
	Status string `json:"status,omitempty"` // up | down
}

// SwitchEdge is one switch-side trunk observed in STP/link events — the log
// signal that reveals the switch-to-switch wiring. FortiSwitch names auto-ISL
// trunks after the PEER's serial fragment (e.g. "8EN0000000003-0"), and
// FortiLink MC-LAG trunks "_FlInK…_MLAG…_" / ICL trunks "…_ICL…_". Role is
// the newest STP role on the trunk ("root" = this switch's uplink TOWARD the
// peer); Ports are the physical member legs from trunk-membership link events
// ("Physical port (portN) became active member of trunk (T)").
type SwitchEdge struct {
	SwitchSN   string   `json:"switch_sn"`
	SwitchName string   `json:"switch_name,omitempty"`
	Trunk      string   `json:"trunk"`
	Role       string   `json:"role,omitempty"`
	Ports      []string `json:"ports,omitempty"`
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

// graylogSources returns the Graylog `source` value(s) to match for a firewall:
// the operator-maintained hostnames from the fgt_adm_vpn_conf extension (which
// include both HA cluster nodes) when available, otherwise the short hostname
// derived from the FQDN.
func (e *Extension) graylogSources(fqdn string) []string {
	if hs := e.vpnConfigSources(fqdn); len(hs) > 0 {
		return hs
	}
	return []string{sourceHost(fqdn)}
}

// buildSourceQuery substitutes the `source:"%s"` term of a query template with
// the resolved source(s). A single source keeps the original form; multiple
// sources (an HA cluster) become a grouped OR so the rest of the template's
// filter still applies to all of them, e.g.
// `(source:"fw-n1" OR source:"fw-n2") AND (mac:* OR …)`.
func buildSourceQuery(template string, sources []string) string {
	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		parts = append(parts, fmt.Sprintf(`source:"%s"`, escapeGraylogValue(s)))
	}
	var clause string
	switch len(parts) {
	case 0:
		return template // nothing resolved: leave %s so the caller errors visibly
	case 1:
		clause = parts[0]
	default:
		clause = "(" + strings.Join(parts, " OR ") + ")"
	}
	if strings.Contains(template, `source:"%s"`) {
		return strings.Replace(template, `source:"%s"`, clause, 1)
	}
	// Template without the standard source token: AND the clause in front.
	return clause + " AND (" + template + ")"
}

// effectiveRange picks the Graylog search window in seconds: a per-request
// override (e.g. a live refresh) wins, else the configured default, else 24h.
func effectiveRange(override, cfg string) string {
	if override != "" {
		return override
	}
	if cfg != "" {
		return cfg
	}
	return "86400"
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
func (e *Extension) fetchDevices(fqdn, rangeSec string) ([]Device, error) {
	sources := e.graylogSources(fqdn)
	msgs, err := e.queryGraylog(e.cfg.GraylogDeviceQuery, "GRAYLOG_DEVICE_QUERY", fqdn, sources, rangeSec)
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

	// Visibility into why the inventory may be empty. 0 messages almost always
	// means the log "source" does not match the firewall's short hostname (the
	// GRAYLOG_DEVICE_QUERY `source:"%s"` filter) or the time range excludes
	// them; messages-but-no-MAC means the matched logs carry no MAC field.
	src := strings.Join(sources, ",")
	e.logger.Info("graylog device fetch",
		"fqdn", fqdn, "sources", src,
		"messages", len(msgs), "devices", len(out))
	switch {
	case len(msgs) == 0:
		e.logger.Warn("graylog device fetch returned 0 messages — verify the Graylog 'source' matches this firewall (set cluster_hostnames in the FGT ADM VPN config for HA pairs) and that the search window covers it",
			"fqdn", fqdn, "sources", src,
			"query_template", e.cfg.GraylogDeviceQuery, "range_seconds", effectiveRange(rangeSec, e.cfg.GraylogDeviceRange))
	case len(out) == 0:
		e.logger.Warn("graylog returned messages but none contained a MAC address — adjust GRAYLOG_DEVICE_QUERY or enable device-detection / DHCP logging on the FortiGate",
			"fqdn", fqdn, "total_messages", len(msgs), "query_template", e.cfg.GraylogDeviceQuery)
	}

	return out, nil
}

// queryGraylog runs one relative-range search with the given query template
// (%s = source host) and returns the raw messages, newest first.
func (e *Extension) queryGraylog(template, templateName, fqdn string, sources []string, rangeSec string) ([]map[string]any, error) {
	graylogURL := strings.TrimRight(e.cfg.GraylogURL, "/")
	if graylogURL == "" || e.cfg.GraylogToken == "" {
		return nil, errors.New("graylog not configured (GRAYLOG_URL/GRAYLOG_TOKEN)")
	}
	// rangeSec (set by e.g. a live topology refresh) overrides the configured
	// window so frequent polls scan only recent logs instead of the full range.
	timeframe := effectiveRange(rangeSec, e.cfg.GraylogDeviceRange)

	query := buildSourceQuery(template, sources)
	// A leftover %s / fmt error marker means the template's source term was not
	// `source:"%s"`; catch the misconfiguration here instead of sending a
	// garbage query (which Graylog may answer with every firewall's logs).
	if strings.Contains(query, "%s") || strings.Contains(query, "%!") {
		return nil, fmt.Errorf(`%s template is invalid (needs a source:"%%s" term): %q`, templateName, template)
	}
	params := url.Values{}
	params.Set("query", query)
	params.Set("range", timeframe)
	params.Set("limit", "1000")
	apiURL := graylogURL + "/api/search/universal/relative?" + params.Encode()

	e.logger.Debug("graylog fetch: sending query", "template", templateName, "fqdn", fqdn,
		"sources", strings.Join(sources, ","), "query", query, "range", timeframe)

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
		return nil, fmt.Errorf("graylog request failed (%s): %w", templateName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		// Surface Graylog's own error text (e.g. a query-syntax complaint)
		// instead of a bare status code — that is what the operator needs.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("graylog %s returned HTTP %d for source %q: %s",
			templateName, resp.StatusCode, sourceHost(fqdn), strings.TrimSpace(string(snippet)))
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
		return nil, fmt.Errorf("decode graylog response (%s): %w", templateName, err)
	}
	out := make([]map[string]any, 0, len(data.Messages))
	for _, m := range data.Messages {
		out = append(out, m.Message)
	}
	e.logger.Debug("graylog fetch: response received", "template", templateName, "fqdn", fqdn,
		"status", resp.StatusCode, "messages", len(out))
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

// rePhysPort matches plain physical port names ("port11"); anything else in
// switchphysicalport is a trunk whose NAME identifies the peer (auto-ISL
// trunks carry the peer serial fragment, FortiLink MLAG/ICL trunks their role).
var rePhysPort = regexp.MustCompile(`(?i)^port\d+$`)

// reTrunkMember parses trunk-membership link events, the only signal that
// resolves an MC-LAG/LAG trunk into its physical member legs:
// "Physical port (port27) became active member of trunk (_FlInK1_MLAG0_)".
var reTrunkMember = regexp.MustCompile(`(?i)physical port \(?"?([^\s"()]+)"?\)? became (?:an )?(?:active )?member of trunk \(?"?([^\s"()]+)"?\)?`)

// fetchStpStates queries the STP/guard/port-status event logs and folds them
// into the latest status per switch port (messages arrive newest-first, so
// the first event of each kind seen per port wins). The full event list is
// returned alongside for the port history, plus the switch-edge observations
// (trunk-named STP ports and trunk memberships) for interlink detection.
func (e *Extension) fetchStpStates(fqdn, rangeSec string) ([]StpPort, []StpEvent, []SwitchEdge, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogStpQuery, "GRAYLOG_STP_QUERY", fqdn, e.graylogSources(fqdn), rangeSec)
	if err != nil {
		return nil, nil, nil, err
	}
	byPort := map[string]*StpPort{}
	seenKind := map[string]bool{} // key: port-key + "|" + kind
	var order []*StpPort
	var events []StpEvent
	edges := map[string]*SwitchEdge{} // key: sn + "|" + trunk
	var edgeOrder []*SwitchEdge
	edgeFor := func(sn, name, trunk string) *SwitchEdge {
		key := sn + "|" + trunk
		if g := edges[key]; g != nil {
			return g
		}
		g := &SwitchEdge{SwitchSN: sn, SwitchName: name, Trunk: trunk}
		edges[key] = g
		edgeOrder = append(edgeOrder, g)
		return g
	}
	for _, m := range msgs {
		// Switch-edge observations ride along on the same message stream.
		if sn := field(m, "sn", "name"); sn != "" {
			name := field(m, "name")
			text := field(m, "msg", "message")
			if mm := reTrunkMember.FindStringSubmatch(text); mm != nil {
				g := edgeFor(sn, name, mm[2])
				if !slices.Contains(g.Ports, mm[1]) {
					g.Ports = append(g.Ports, mm[1])
				}
			}
			if port := field(m, "switchphysicalport"); port != "" && !rePhysPort.MatchString(port) {
				edgeFor(sn, name, port)
			}
		}
		p, ev := stpFromMessage(m)
		if p == nil {
			continue
		}
		// Newest STP role per trunk orients the edge (root = uplink).
		if ev.kind == "role" && !rePhysPort.MatchString(p.Port) {
			g := edgeFor(p.Serial, p.SwitchName, p.Port)
			if g.Role == "" {
				g.Role = ev.value
			}
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
	edgeOut := make([]SwitchEdge, 0, len(edgeOrder))
	for _, g := range edgeOrder {
		edgeOut = append(edgeOut, *g)
	}
	return out, events, edgeOut, nil
}

// fetchMacPorts pulls the FortiSwitch MAC add/move/delete events and returns
// the latest state per client MAC (messages are newest-first, so the first
// event seen per MAC wins — a delete tombstone shadows older add/move events).
func (e *Extension) fetchMacPorts(fqdn, rangeSec string) ([]MacPort, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogMacQuery, "GRAYLOG_MAC_QUERY", fqdn, e.graylogSources(fqdn), rangeSec)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []MacPort
	tombstones := 0
	for _, m := range msgs {
		mp, ok := macEventFromMessage(m)
		if !ok || seen[mp.Mac] {
			continue
		}
		seen[mp.Mac] = true
		if mp.Deleted {
			tombstones++
		}
		out = append(out, mp)
	}
	// Make an empty result diagnosable: "no events at all" means the FortiGate
	// is not logging FortiSwitch MAC-table events (device→switch-port pinning
	// has no data source), while "events but nothing parsed" means the msg
	// wording drifted from what reMacEvent expects.
	switch {
	case len(msgs) == 0:
		e.logger.Info("graylog mac-ports: no FortiSwitch MAC-table events — device→switch-port pinning unavailable; enable 'set mac-event-logging enable' under 'config switch-controller global' on the FortiGate",
			"fqdn", fqdn)
	case len(out) == 0:
		e.logger.Warn("graylog mac-ports: messages returned but none parsed — the log wording may have changed; adjust GRAYLOG_MAC_QUERY or report the msg format",
			"fqdn", fqdn, "messages", len(msgs), "sample", field(msgs[0], "msg", "message"))
	default:
		e.logger.Debug("graylog mac-ports parsed",
			"fqdn", fqdn, "messages", len(msgs), "bindings", len(out)-tombstones, "tombstones", tombstones)
	}
	return out, nil
}

// fetchWifiClients pulls wireless association events and returns the latest
// AP/SSID/signal per client MAC (newest-first).
func (e *Extension) fetchWifiClients(fqdn, rangeSec string) ([]WifiClient, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogWifiQuery, "GRAYLOG_WIFI_QUERY", fqdn, e.graylogSources(fqdn), rangeSec)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []WifiClient
	for _, m := range msgs {
		w, ok := wifiFromMessage(m)
		if !ok || w.Ap == "" && w.Ssid == "" || seen[w.Mac] {
			continue
		}
		seen[w.Mac] = true
		out = append(out, w)
	}
	return out, nil
}

// fetchVpnStatuses pulls VPN tunnel events and returns the latest up/down state
// per tunnel (newest-first).
func (e *Extension) fetchVpnStatuses(fqdn, rangeSec string) ([]VpnStatus, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogVpnQuery, "GRAYLOG_VPN_QUERY", fqdn, e.graylogSources(fqdn), rangeSec)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []VpnStatus
	for _, m := range msgs {
		v, ok := vpnFromMessage(m)
		if !ok || v.Status == "" || seen[v.Name] {
			continue
		}
		seen[v.Name] = true
		out = append(out, v)
	}
	return out, nil
}

// fetchHaDetail returns a short summary of the newest HA event for the firewall
// ("" when none), giving the topology a liveness hint for the HA cluster node.
func (e *Extension) fetchHaDetail(fqdn, rangeSec string) (string, error) {
	msgs, err := e.queryGraylog(e.cfg.GraylogHaQuery, "GRAYLOG_HA_QUERY", fqdn, e.graylogSources(fqdn), rangeSec)
	if err != nil {
		return "", err
	}
	for _, m := range msgs { // newest-first
		if d := field(m, "logdesc", "msg"); d != "" {
			return d, nil
		}
	}
	return "", nil
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
		Mac:       mac,
		IP:        field(msg, "ip", "assignedip", "srcip", "client_ip", "dstip"),
		Vlan:      field(msg, "vlan", "vlanid", "vlan_id", "cvid"),
		Port:      field(msg, "portname", "port", "interface", "srcintf", "switchphysicalport"),
		SwitchID:  field(msg, "switchid", "sn", "swname", "devid_fsw", "switch_sn"),
		Hostname:  field(msg, "hostname", "srcname", "devname_client", "computer", "unauthuser"),
		DevType:   field(msg, "devtype", "srcfamily", "device_type"),
		OsName:    field(msg, "osname", "os"),
		OsVersion: field(msg, "osversion", "os_version"),
		Vendor:    field(msg, "srchwvendor", "hwvendor", "manuf", "vendor"),
		LastSeen:  field(msg, "timestamp"),
	}
	return d, true
}

// reMacEvent parses FortiSwitch MAC add/move messages, which carry the client
// MAC, physical port and VLAN only in free-text. Live FortiOS 7.x wording
// (verified against a production Graylog):
//
//	add:    "50:4f:94:…:e8 discovered on interface port11 in vlan 1 on Switch NAME"
//	move:   "46:a8:d4:…:39 moved from interface port11 to interface port8 in vlan 100 on Switch NAME"
//	delete: "fa:40:d7:…:2a deleted from vlan 300 on Switch NAME"   (no port)
//
// The MAC is not anchored to the start so label-prefixed variants ("MAC xx:…
// has added on interface …") parse too, and the port tolerates quoting.
var reMacEvent = regexp.MustCompile(`(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b.*?\binterface "?([^\s"]+?)"?(?:\s+in vlan (\d+))?(?: on Switch (\S+))?\s*$`)

// reMacAddr extracts a bare colon-separated MAC (used for delete tombstones,
// whose messages carry no interface for reMacEvent to hook onto).
var reMacAddr = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b`)

// macEventFromMessage extracts the client MAC → physical port / VLAN / switch
// binding from one FortiSwitch MAC add/move/delete or NAC device add/delete
// log. The switch prefers the indexed `sn` field (the FortiSwitch serial — the
// key the config backup's managed-switch entries use, so the frontend can
// match it exactly), then the friendly `name`, then the free-text tail. Delete
// events return Deleted=true so the caller can tombstone the MAC (messages are
// newest-first, so a delete newer than the last add/move means the MAC left).
func macEventFromMessage(msg map[string]any) (MacPort, bool) {
	text := field(msg, "msg", "message")
	lower := strings.ToLower(text)
	sw := field(msg, "sn", "name", "sw")
	// "delet" covers both "FortiSwitch MAC delete" and "NAC device deletion";
	// NAC deletions also flag themselves via action=nac-device-del.
	deleted := strings.Contains(strings.ToLower(field(msg, "logdesc")), "delet") ||
		strings.HasSuffix(strings.ToLower(field(msg, "action")), "-del") ||
		strings.Contains(lower, " deleted ")
	// NAC device events (logid 0115022861/2) carry everything as indexed
	// fields — no free-text parsing needed (vlan holds the VLAN *name*).
	if mac := strings.ToLower(reMacAddr.FindString(field(msg, "MAC", "mac"))); mac != "" {
		if deleted {
			return MacPort{Mac: mac, SwitchName: sw, Deleted: true}, true
		}
		if port := field(msg, "port"); port != "" {
			return MacPort{Mac: mac, Port: port, Vlan: field(msg, "vlan"), SwitchName: sw}, true
		}
	}
	// Delete events carry no interface token — emit a tombstone.
	if deleted {
		mac := strings.ToLower(reMacAddr.FindString(text))
		if mac == "" {
			return MacPort{}, false
		}
		return MacPort{Mac: mac, SwitchName: sw, Deleted: true}, true
	}
	// A move has two "interface" tokens ("… from interface OLD to interface
	// NEW …"); cut the "from interface OLD to " span so the regex captures the
	// NEW (current) port. Byte offsets are safe: these messages are ASCII.
	if i := strings.Index(lower, "from interface "); i >= 0 {
		if j := strings.LastIndex(lower, "to interface "); j > i {
			text = text[:i] + text[j+len("to "):]
		}
	}
	m := reMacEvent.FindStringSubmatch(text)
	if m == nil || m[2] == "" {
		return MacPort{}, false
	}
	if sw == "" {
		sw = m[4]
	}
	return MacPort{
		Mac:        strings.ToLower(m[1]),
		Port:       m[2],
		Vlan:       m[3],
		SwitchName: sw,
	}, true
}

// wifiFromMessage normalizes one wireless association log into a WifiClient.
func wifiFromMessage(msg map[string]any) (WifiClient, bool) {
	mac := strings.ToLower(field(msg, "stamac", "mac", "srcmac"))
	if mac == "" {
		return WifiClient{}, false
	}
	return WifiClient{
		Mac:     mac,
		Ap:      field(msg, "ap", "apname", "wtpname"),
		Ssid:    field(msg, "ssid"),
		Signal:  field(msg, "signal", "rssi"),
		Channel: field(msg, "channel"),
		Vlan:    field(msg, "vlan", "vlanid", "vlan_id"),
	}, true
}

// vpnFromMessage normalizes one VPN log into a per-tunnel status. Up/down is
// inferred from the controlled `action` and `logdesc` fields only — never the
// free-text `msg`, which contains negotiation wording like "DH group 14" or
// "teardown" that would otherwise false-match "up"/"down".
func vpnFromMessage(msg map[string]any) (VpnStatus, bool) {
	name := field(msg, "vpntunnel", "tunnelid", "tunnel")
	if name == "" {
		return VpnStatus{}, false
	}
	act := strings.ToLower(field(msg, "action"))
	ld := strings.ToLower(field(msg, "logdesc"))
	status := ""
	switch {
	case strings.Contains(act, "down") || strings.Contains(ld, "down") ||
		strings.Contains(ld, "deleted") || strings.Contains(ld, "teardown"):
		status = "down"
	case strings.Contains(act, "up") || strings.Contains(act, "stats") ||
		strings.Contains(ld, "installed") || strings.Contains(ld, "established") ||
		strings.Contains(ld, "statistics"):
		status = "up"
	}
	return VpnStatus{
		Name:   name,
		RemIP:  field(msg, "remip", "remote_ip"),
		Type:   field(msg, "tunneltype"),
		Status: status,
	}, true
}
