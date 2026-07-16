package fgt_polsplit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Graylog access for the policy split advisor. The traffic analysis runs as
// server-side aggregations (Graylog's Search Scripting API): grouping by
// srcip/dstip/proto/dstport/service with a count() metric returns one row per
// observed combination regardless of message volume, so week- or month-long
// windows on busy policies stay complete and cheap. The source-resolution and
// API plumbing mirror extensions/graylog_device_data.
// ---------------------------------------------------------------------------

// timeRange selects either a relative window (seconds back from now) or an
// absolute from/to range (ISO-8601, as produced by the UI's custom range).
type timeRange struct {
	RelativeSec int
	From, To    string
}

func (t timeRange) valid() bool {
	return t.RelativeSec > 0 || (t.From != "" && t.To != "")
}

type aggregateGroup struct {
	Field string `json:"field"`
	Limit int    `json:"limit,omitempty"`
}
type aggregateMetric struct {
	Function string `json:"function"`
	Field    string `json:"field,omitempty"`
}
type aggregateTimerange struct {
	Type  string `json:"type"`
	Range int    `json:"range,omitempty"` // seconds, for type "relative"
	From  string `json:"from,omitempty"`  // ISO-8601, for type "absolute"
	To    string `json:"to,omitempty"`
}
type aggregateRequest struct {
	Query     string             `json:"query"`
	Timerange aggregateTimerange `json:"timerange"`
	GroupBy   []aggregateGroup   `json:"group_by"`
	Metrics   []aggregateMetric  `json:"metrics"`
}
type aggregateColumn struct {
	ColumnType string `json:"column_type"` // "grouping" | "metric"
	Field      string `json:"field,omitempty"`
	Function   string `json:"function,omitempty"`
}

func (t timeRange) aggregate() aggregateTimerange {
	if t.RelativeSec > 0 {
		return aggregateTimerange{Type: "relative", Range: t.RelativeSec}
	}
	return aggregateTimerange{Type: "absolute", From: t.From, To: t.To}
}

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

// graylogSources returns the Graylog `source` value(s) to match for a
// firewall: the operator-maintained hostnames from the fgt_adm_vpn_conf
// extension (which include both HA cluster nodes) when available, otherwise
// the short hostname derived from the FQDN.
func (e *Extension) graylogSources(fqdn string) []string {
	if hs := e.vpnConfigSources(fqdn); len(hs) > 0 {
		return hs
	}
	return []string{sourceHost(fqdn)}
}

// vpnConfigSources resolves the Graylog source name(s) from the
// fgt_adm_vpn_conf extension's database (same contract as the
// graylog_device_data copy of this helper: nil when absent or no match).
func (e *Extension) vpnConfigSources(fqdn string) []string {
	dbFile := filepath.Join(e.dataDir, "fgt-adm-vpn-conf-db.db")
	if _, err := os.Stat(dbFile); err != nil {
		if !os.IsNotExist(err) {
			e.logger.Warn("polsplit: cannot stat adm-vpn-conf db", "path", dbFile, "err", err)
		}
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile)+"?mode=ro")
	if err != nil {
		e.logger.Debug("polsplit: cannot open adm-vpn-conf db", "err", err)
		return nil
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	short := sourceHost(fqdn)
	var firewallname, clusters string
	err = db.QueryRow(`SELECT COALESCE(firewallname,''), COALESCE(cluster_hostnames,'')
		FROM vpn_config
		WHERE lower(firewallname) IN (lower(?), lower(?))
		   OR lower(dns_name)      IN (lower(?), lower(?))
		   OR lower(dns_name_full) IN (lower(?), lower(?))
		LIMIT 1`,
		fqdn, short, fqdn, short, fqdn, short).Scan(&firewallname, &clusters)
	if err != nil {
		if err != sql.ErrNoRows {
			e.logger.Debug("polsplit: adm-vpn-conf lookup failed", "fqdn", fqdn, "err", err)
		}
		return nil
	}
	var hosts []string
	for _, h := range strings.Split(clusters, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) > 0 {
		return hosts
	}
	if firewallname != "" {
		return []string{firewallname}
	}
	return nil
}

// buildQuery substitutes the template's `policyid:%s` term with the policy ID
// and its `source:"%s"` term with the resolved source clause (grouped OR for
// HA clusters). An error is returned when placeholders remain, so a broken
// template never reaches Graylog as a query matching every firewall.
func buildQuery(template string, sources []string, policyID int) (string, error) {
	q := template
	id := strconv.Itoa(policyID)
	replaced := false
	if strings.Contains(q, `policyid:"%s"`) {
		q = strings.Replace(q, `policyid:"%s"`, `policyid:"`+id+`"`, 1)
		replaced = true
	}
	if strings.Contains(q, `policyid:%s`) {
		q = strings.Replace(q, `policyid:%s`, `policyid:`+id, 1)
		replaced = true
	}
	if !replaced {
		return "", fmt.Errorf("query template does not contain policy ID placeholder")
	}

	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		parts = append(parts, fmt.Sprintf(`source:"%s"`, escapeGraylogValue(s)))
	}
	var clause string
	switch len(parts) {
	case 0:
		return "", errors.New("no Graylog source resolved for firewall")
	case 1:
		clause = parts[0]
	default:
		clause = "(" + strings.Join(parts, " OR ") + ")"
	}
	if strings.Contains(q, `source:"%s"`) {
		q = strings.Replace(q, `source:"%s"`, clause, 1)
	} else {
		q = clause + " AND (" + q + ")"
	}
	if strings.Contains(q, "%s") || strings.Contains(q, "%!") {
		return "", fmt.Errorf(`GRAYLOG_POLSPLIT_QUERY template is invalid (needs source:"%%s" and policyid:%%s terms): %q`, template)
	}
	return q, nil
}

func (e *Extension) graylogAuth(req *http.Request) {
	auth := base64.StdEncoding.EncodeToString([]byte(e.cfg.GraylogToken + ":token"))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
}

// countMessages returns the total number of log messages matching the query in
// the window — a diagnostic anchor: tuples==0 with messages>0 means the field
// extraction (srcip/dstip/…) is missing, not the traffic.
func (e *Extension) countMessages(ctx context.Context, query string, tr timeRange) (int64, error) {
	graylogURL := strings.TrimRight(e.cfg.GraylogURL, "/")
	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", "1")
	var apiURL string
	if tr.RelativeSec > 0 {
		params.Set("range", strconv.Itoa(tr.RelativeSec))
		apiURL = graylogURL + "/api/search/universal/relative?" + params.Encode()
	} else {
		params.Set("from", tr.From)
		params.Set("to", tr.To)
		apiURL = graylogURL + "/api/search/universal/absolute?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return 0, err
	}
	e.graylogAuth(req)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("graylog count request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("graylog count returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	var data struct {
		TotalResults int64 `json:"total_results"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, fmt.Errorf("decode graylog count response: %w", err)
	}
	return data.TotalResults, nil
}

// aggregate runs one aggregation via the Search Scripting API. The endpoint is
// a state-changing POST, so it needs the X-Requested-By CSRF header.
func (e *Extension) aggregate(ctx context.Context, body aggregateRequest) ([]aggregateColumn, [][]any, error) {
	graylogURL := strings.TrimRight(e.cfg.GraylogURL, "/")
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graylogURL+"/api/search/aggregate", bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	e.graylogAuth(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "fortisafe")

	// Aggregations scan far more than a page of messages; give them headroom.
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("graylog aggregate request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, nil, fmt.Errorf("graylog aggregate returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, nil, err
	}
	var data struct {
		Schema   []aggregateColumn `json:"schema"`
		Datarows [][]any           `json:"datarows"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, nil, fmt.Errorf("decode graylog aggregate response: %w", err)
	}
	return data.Schema, data.Datarows, nil
}

// groupLimit caps distinct values per grouping field (Graylog defaults to 15,
// which would silently truncate). Hitting the cap on srcip/dstip is reported
// as a truncation warning.
const groupLimit = 1000

// fetchPolicyTraffic aggregates the policy's traffic into src/dst/service
// tuples. Two aggregations run because grouping drops documents missing a
// grouped field: one over port-carrying logs (tcp/udp/sctp) grouped by dstport,
// one over portless logs (icmp/gre/esp/…) without it. totalMessages carries the
// window's raw match count for diagnostics.
func (e *Extension) fetchPolicyTraffic(ctx context.Context, fqdn string, policyID int, vdom string, tr timeRange) (tuples []TrafficTuple, totalMessages int64, warnings []string, err error) {
	if strings.TrimRight(e.cfg.GraylogURL, "/") == "" || e.cfg.GraylogToken == "" {
		return nil, 0, []string{"Graylog is not configured (set GRAYLOG_URL and GRAYLOG_TOKEN) — no traffic data available"}, nil
	}
	if !tr.valid() {
		return nil, 0, nil, errors.New("invalid time range")
	}
	query, err := e.buildPolicyQuery(fqdn, policyID, vdom)
	if err != nil {
		return nil, 0, nil, err
	}

	totalMessages, err = e.countMessages(ctx, query, tr)
	if err != nil {
		return nil, 0, nil, err
	}

	// 1. Authoritative complete result without service grouping (so no messages are omitted)
	tuples, warnings, err = e.aggregateTuples(ctx, query, tr, false)
	if err != nil {
		return nil, 0, nil, err
	}

	// 2. Separate query with service grouping to get service names
	svcTuples, svcWarnings, err := e.aggregateTuples(ctx, query, tr, true)
	if err != nil {
		e.logger.Warn("polsplit: service-present aggregation failed, using no-service results only", "err", err)
	} else {
		warnings = append(warnings, svcWarnings...)
		svcMap := make(map[string]string)
		for _, st := range svcTuples {
			if st.Service != "" {
				key := fmt.Sprintf("%s|%s|%s|%d", st.SrcIP, st.DstIP, st.Proto, st.Port)
				svcMap[key] = st.Service
			}
		}
		for i := range tuples {
			key := fmt.Sprintf("%s|%s|%s|%d", tuples[i].SrcIP, tuples[i].DstIP, tuples[i].Proto, tuples[i].Port)
			if svc, ok := svcMap[key]; ok {
				tuples[i].Service = svc
			}
		}
	}

	warnings = append(warnings, truncationWarnings(tuples)...)
	e.logger.Info("polsplit: graylog traffic fetch", "fqdn", fqdn, "policyid", policyID,
		"sources", strings.Join(e.graylogSources(fqdn), ","), "messages", totalMessages, "tuples", len(tuples))
	return tuples, totalMessages, warnings, nil
}

// buildPolicyQuery resolves the firewall's Graylog sources and assembles the
// full traffic-log query for one policy, including the VDOM filter.
func (e *Extension) buildPolicyQuery(fqdn string, policyID int, vdom string) (string, error) {
	sources := e.graylogSources(fqdn)
	query, err := buildQuery(e.cfg.GraylogPolsplitQuery, sources, policyID)
	if err != nil {
		return "", err
	}
	if vdom != "" {
		// FortiGate syslog carries the virtual domain in the `vd` field
		// (there is no `vdom` field in FortiOS log output).
		query = query + ` AND vd:"` + escapeGraylogValue(vdom) + `"`
	}
	return query, nil
}

// fetchBaselineTuples runs only the tuple aggregation pair for the baseline
// comparison window — no message count and no service decoration, since flow
// flagging needs just the src/dst/proto/port identity sets.
func (e *Extension) fetchBaselineTuples(ctx context.Context, fqdn string, policyID int, vdom string, tr timeRange) ([]TrafficTuple, error) {
	if strings.TrimRight(e.cfg.GraylogURL, "/") == "" || e.cfg.GraylogToken == "" {
		return nil, errors.New("graylog not configured")
	}
	if !tr.valid() {
		return nil, errors.New("invalid baseline time range")
	}
	query, err := e.buildPolicyQuery(fqdn, policyID, vdom)
	if err != nil {
		return nil, err
	}
	tuples, _, err := e.aggregateTuples(ctx, query, tr, false)
	return tuples, err
}

// aggregateTuples runs the tuple aggregation pair: one query over
// port-carrying logs (tcp/udp/sctp) grouped by dstport, one over portless logs
// (icmp/gre/esp/…) without it — grouping drops documents that miss a grouped
// field, so a single combined aggregation would silently lose ICMP traffic.
func (e *Extension) aggregateTuples(ctx context.Context, query string, tr timeRange, includeService bool) (tuples []TrafficTuple, warnings []string, err error) {
	base := []aggregateGroup{
		{Field: "srcip", Limit: groupLimit},
		{Field: "dstip", Limit: groupLimit},
		{Field: "proto", Limit: 200},
	}
	if includeService {
		base = append(base, aggregateGroup{Field: "service", Limit: groupLimit})
	}
	metrics := []aggregateMetric{
		{Function: "count"},
		{Function: "latest", Field: "timestamp"},
	}

	withPort := aggregateRequest{
		Query:     query + " AND _exists_:dstport",
		Timerange: tr.aggregate(),
		GroupBy:   append(append([]aggregateGroup{}, base...), aggregateGroup{Field: "dstport", Limit: groupLimit}),
		Metrics:   metrics,
	}
	schema, rows, err := e.aggregate(ctx, withPort)
	if err != nil {
		return nil, nil, err
	}
	tuples = append(tuples, parseTupleRows(schema, rows)...)

	withoutPort := aggregateRequest{
		Query:     query + " AND NOT _exists_:dstport",
		Timerange: tr.aggregate(),
		GroupBy:   base,
		Metrics:   metrics,
	}
	schema, rows, err = e.aggregate(ctx, withoutPort)
	if err != nil {
		e.logger.Warn("polsplit: portless-traffic aggregation failed, continuing with port-carrying tuples only", "err", err)
		warnings = append(warnings, "portless-protocol aggregation failed: "+err.Error())
	} else {
		tuples = append(tuples, parseTupleRows(schema, rows)...)
	}
	return tuples, warnings, nil
}

// parseTupleRows converts aggregation datarows into tuples, resolving columns
// by schema so field order never matters.
func parseTupleRows(schema []aggregateColumn, rows [][]any) []TrafficTuple {
	col := map[string]int{}
	for i, c := range schema {
		switch {
		case c.ColumnType == "grouping":
			col[c.Field] = i
		case c.ColumnType == "metric" && c.Function == "count":
			col["_count"] = i
		case c.ColumnType == "metric" && c.Function == "latest":
			col["_latest"] = i
		}
	}
	cell := func(row []any, name string) string {
		idx, ok := col[name]
		if !ok || idx >= len(row) || row[idx] == nil {
			return ""
		}
		switch v := row[idx].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			if v == float64(int64(v)) {
				return strconv.FormatInt(int64(v), 10)
			}
			return strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return strings.TrimSpace(fmt.Sprintf("%v", v))
		}
	}
	var out []TrafficTuple
	for _, row := range rows {
		src, dst := cell(row, "srcip"), cell(row, "dstip")
		if src == "" || dst == "" || strings.EqualFold(src, "(Empty Value)") || strings.EqualFold(dst, "(Empty Value)") {
			continue
		}
		hits, _ := strconv.ParseInt(cell(row, "_count"), 10, 64)
		port, _ := strconv.Atoi(cell(row, "dstport"))
		if port < 0 || port > 65535 {
			port = 0 // unparseable/out-of-range dstport → treated as portless
		}
		proto := protoName(cell(row, "proto"), port)
		if proto == "unknown" {
			continue
		}
		t := TrafficTuple{
			SrcIP:    src,
			DstIP:    dst,
			Proto:    proto,
			Port:     port,
			Service:  cell(row, "service"),
			Hits:     hits,
			LastSeen: cell(row, "_latest"),
			IPv6:     strings.Contains(src, ":") || strings.Contains(dst, ":"),
		}
		out = append(out, t)
	}
	return out
}

// protoName normalizes the log's proto field (usually the IP protocol number)
// to a lowercase name.
func protoName(proto string, port int) string {
	p := strings.ToLower(strings.TrimSpace(proto))
	switch p {
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "132", "sctp":
		return "sctp"
	case "1", "icmp":
		return "icmp"
	case "58", "icmp6", "ipv6-icmp":
		return "icmp6"
	case "47", "gre":
		return "ip-47"
	case "50", "esp":
		return "ip-50"
	case "51", "ah":
		return "ip-51"
	case "":
		// No proto field extracted — do not infer a protocol.
		return "unknown"
	}
	if _, err := strconv.Atoi(p); err == nil {
		return "ip-" + p
	}
	return "unknown"
}

// truncationWarnings reports when a grouping dimension hit the aggregation
// limit, meaning only the top combinations by volume are shown.
func truncationWarnings(tuples []TrafficTuple) []string {
	srcs, dsts := map[string]bool{}, map[string]bool{}
	for _, t := range tuples {
		srcs[t.SrcIP] = true
		dsts[t.DstIP] = true
	}
	var w []string
	if len(srcs) >= groupLimit {
		w = append(w, fmt.Sprintf("distinct sources reached the aggregation limit (%d) — only the top combinations are analyzed", groupLimit))
	}
	if len(dsts) >= groupLimit {
		w = append(w, fmt.Sprintf("distinct destinations reached the aggregation limit (%d) — only the top combinations are analyzed", groupLimit))
	}
	return w
}
