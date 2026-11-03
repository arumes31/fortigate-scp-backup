package reportlogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"
	"unicode"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

type datasetSpec struct {
	id, title, titleDE, clause string
	fields                     []string
}

var specs = []datasetSpec{
	{"traffic_actions", "Forward traffic records by action", "Forward-Verkehrslogs nach Aktion", `type:"traffic" AND subtype:"forward"`, []string{"action"}},
	{"applications", "Applications in forward traffic records", "Anwendungen in Forward-Verkehrslogs", `type:"traffic" AND subtype:"forward"`, []string{"app"}},
	{"source_ips", "Source addresses in forward traffic records", "Quelladressen in Forward-Verkehrslogs", `type:"traffic" AND subtype:"forward"`, []string{"srcip"}},
	{"destination_ips", "Destination addresses in forward traffic records", "Zieladressen in Forward-Verkehrslogs", `type:"traffic" AND subtype:"forward"`, []string{"dstip"}},
	{"policies", "Policies referenced by forward traffic records", "Regelreferenzen in Forward-Verkehrslogs", `type:"traffic" AND subtype:"forward"`, []string{"vd", "policyid"}},
	{"security_events", "Received UTM events by subtype and action", "Empfangene UTM-Ereignisse nach Untertyp und Aktion", `type:"utm"`, []string{"subtype", "action"}},
	{"vpn_events", "Received VPN events by tunnel and action", "Empfangene VPN-Ereignisse nach Tunnel und Aktion", `type:"event" AND subtype:"vpn"`, []string{"vpntunnel", "action"}},
}

// Collect produces observation metadata even when Graylog is absent or a
// request fails. Callers decide whether an overall error should retain the last
// successful report generation; configuration analysis is never modified.
func (c *Collector) Collect(ctx context.Context, source reportmodel.Source, a reportmodel.Assessment, profile reportmodel.Profile, now time.Time) (result reportmodel.Telemetry) {
	result = reportmodel.Telemetry{Status: "error", Sources: []string{}, Datasets: []reportmodel.TelemetryDataset{}}
	defer func() { result.RetrievedAt = time.Now().UTC() }()
	p, err := reportmodel.NormalizeProfile(profile)
	if err != nil || now.IsZero() {
		result.Reason = "The report observation settings are invalid."
		return result
	}
	result.VDOMs = append([]string{}, p.Filters.VDOMs...)
	duration := 24 * time.Hour
	switch p.TimeRange {
	case "last7d":
		duration *= 7
	case "last30d":
		duration *= 30
	}
	window := timeWindow{end: now.UTC().Truncate(time.Millisecond)}
	window.start = window.end.Add(-duration)
	result.WindowStart, result.WindowEnd = window.start, window.end
	if !p.Traffic {
		result.Status, result.Reason = "disabled", "Log observations are disabled in this report profile."
		return result
	}
	if c.setupErr != "" {
		result.Reason = c.setupErr
		return result
	}
	if c.baseURL == "" || c.token == "" {
		result.Status, result.Reason = "not_configured", "Graylog URL and API token are required for log observations."
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	resolved, err := c.sources(ctx, source, a)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	result.Sources, result.SourceOrigin, result.SourceMatch = resolved.hosts, resolved.origin, resolved.match
	if validIdentity(source.Firewall) {
		result.DeviceIdentity = source.Firewall
	} else {
		result.DeviceIdentity = fmt.Sprintf("Firewall #%d", source.FirewallID)
	}
	r := &run{collector: c, window: window, sem: make(chan struct{}, 2), counts: map[string]*countResult{}}
	base := scopeQuery(result.Sources, p.Filters.VDOMs, window)
	if len(base) > maxScopeQueryBytes {
		result.Reason = "The source and VDOM selectors exceed the supported query size."
		return result
	}
	result.Query = base
	total, err := r.count(ctx, base)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	if total == 0 {
		result.Status = "no_data"
		result.Reason = "No received records matched the displayed source, VDOM scope, and time window. Use the captured query in Graylog to check source spelling, vd extraction, forwarding, retention, and search permissions. This does not establish absence of activity."
		return result
	}
	classified, err := r.count(ctx, base+" AND _exists_:type AND _exists_:subtype")
	if err != nil || classified > total {
		result.Reason = "Log field coverage could not be established consistently."
		return result
	}
	if classified == 0 {
		result.Status = "missing_fields"
		result.Reason = "Matching records were received, but the canonical FortiGate type/subtype fields are unavailable. Map these fields in Graylog before interpreting report categories."
		return result
	}
	result.Datasets = make([]reportmodel.TelemetryDataset, len(specs)+2)
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result.Datasets[i] = r.grouped(ctx, base+" AND ("+spec.clause+")", spec)
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		result.Datasets[len(specs)] = r.reportedBytes(ctx, base)
	}()
	go func() {
		defer wg.Done()
		result.Datasets[len(specs)+1] = r.trend(ctx, base+" AND ("+specs[0].clause+")")
	}()
	wg.Wait()
	result.Status, result.Reason = summarize(result.Datasets, classified < total)
	return result
}

func (r *run) grouped(ctx context.Context, query string, spec datasetSpec) reportmodel.TelemetryDataset {
	d := reportmodel.TelemetryDataset{ID: spec.id, Title: spec.title, TitleDE: spec.titleDE, Status: "error", Limit: groupLimit, MissingFields: []string{}, Rows: []reportmodel.TelemetryRow{}}
	total, err := r.count(ctx, query)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	d.Total = total
	if total == 0 {
		d.Status, d.Reason = "no_data", "No matching log records were received for this category in the selected scope and window."
		return d
	}
	coveredQuery := query
	for _, field := range spec.fields {
		coveredQuery += " AND _exists_:" + field
	}
	covered, err := r.count(ctx, coveredQuery)
	if err != nil || covered > total {
		d.Reason = "Required-field coverage could not be established consistently."
		return d
	}
	if covered < total {
		d.MissingFields = append([]string{}, spec.fields...)
	}
	if covered == 0 {
		d.Status, d.Reason = "missing_fields", "Records exist, but one or more required grouping fields are absent. Counts are not interpreted as zero activity."
		d.Rows = append(d.Rows, reportmodel.TelemetryRow{Label: "Missing required fields", Count: total})
		return d
	}
	response, err := r.aggregate(ctx, coveredQuery, spec.fields, []aggregateMetric{{Function: "count", Sort: "desc"}})
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	rows, err := groupedRows(response, spec.fields)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	var sum int64
	for _, row := range rows {
		if row.Count > covered-sum {
			d.Reason = "Grouping counts exceed the matched-record denominator; data may have changed or contain multivalued group fields."
			return d
		}
		sum += row.Count
	}
	if len(rows) == 0 {
		d.Reason = "The aggregation returned no groups despite records with the required fields."
		return d
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if rows[i].Label != rows[j].Label {
			return rows[i].Label < rows[j].Label
		}
		return rows[i].Secondary < rows[j].Secondary
	})
	if len(rows) > groupLimit {
		rows = rows[:groupLimit]
	}
	sum = 0
	for _, row := range rows {
		sum += row.Count
	}
	d.Returned = len(rows)
	d.Rows = rows
	d.Status = "available"
	d.Reason = "Received log-record counts from server aggregation; up to 20 returned groups are displayed. These are not unique sessions or attacks."
	if sum < covered {
		d.Truncated = true
		d.Status = "partial"
		d.Rows = append(d.Rows, reportmodel.TelemetryRow{Label: "Other / not returned", Count: covered - sum})
		d.Reason += " Remaining covered records are shown as an unreturned-group remainder."
	}
	if covered < total {
		d.Status = "partial"
		d.Rows = append(d.Rows, reportmodel.TelemetryRow{Label: "Missing required fields", Count: total - covered})
		d.Reason += " Some records lack one or more required grouping fields."
	}
	return d
}

func groupedRows(response aggregateResponse, fields []string) ([]reportmodel.TelemetryRow, error) {
	groupColumns := make([]int, len(fields))
	for i, field := range fields {
		column, err := findColumn(response.Schema, "grouping", field, "")
		if err != nil {
			return nil, err
		}
		groupColumns[i] = column
	}
	countColumn, err := findColumn(response.Schema, "metric", "", "count")
	if err != nil {
		return nil, err
	}
	rows := make([]reportmodel.TelemetryRow, 0, len(response.Datarows))
	seen := map[string]bool{}
	for _, data := range response.Datarows {
		if len(data) != len(response.Schema) {
			return nil, errors.New("graylog aggregation row does not match its schema")
		}
		labels := make([]string, len(fields))
		for i, column := range groupColumns {
			labels[i], err = groupLabel(fields[i], data[column])
			if err != nil {
				return nil, err
			}
		}
		key, _ := json.Marshal(labels)
		if seen[string(key)] {
			return nil, errors.New("graylog returned duplicate or indistinguishable aggregation groups")
		}
		seen[string(key)] = true
		count, err := nonnegativeInteger(data[countColumn])
		if err != nil {
			return nil, err
		}
		row := reportmodel.TelemetryRow{Label: labels[0], Count: count}
		if len(labels) > 1 {
			row.Secondary = labels[1]
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func findColumn(schema []aggregateColumn, kind, field, function string) (int, error) {
	result := -1
	for i, column := range schema {
		if column.ColumnType == kind && column.Field == field && column.Function == function {
			if result >= 0 {
				return -1, errors.New("graylog aggregation contains duplicate metric or grouping columns")
			}
			result = i
		}
	}
	if result < 0 {
		return -1, errors.New("graylog aggregation is missing an expected metric or grouping column")
	}
	return result, nil
}

func groupLabel(field string, value any) (string, error) {
	var label string
	switch v := value.(type) {
	case string:
		label = v
	case json.Number:
		n, err := nonnegativeInteger(v)
		if err != nil {
			return "", err
		}
		label = fmt.Sprint(n)
	default:
		return "", errors.New("graylog aggregation contains an unsupported grouping value")
	}
	if len(label) > 4096 {
		return "", errors.New("graylog aggregation grouping value exceeds the size limit")
	}
	if field == "srcip" || field == "dstip" {
		if _, err := netip.ParseAddr(label); err != nil {
			return "", errors.New("graylog address grouping field is not a valid IP address")
		}
	}
	var text []rune
	for _, r := range label {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		text = append(text, r)
		if len(text) == 160 {
			text = append(text, '…')
			break
		}
	}
	if len(text) == 0 {
		return "(empty value)", nil
	}
	return string(text), nil
}

func (r *run) reportedBytes(ctx context.Context, base string) reportmodel.TelemetryDataset {
	d := reportmodel.TelemetryDataset{ID: "reported_bytes", Title: "Reported terminal-session byte counters", TitleDE: "Gemeldete Bytezähler bei Sitzungsende", Status: "error", Limit: 1, MissingFields: []string{}, Rows: []reportmodel.TelemetryRow{}}
	// Fortinet documents 0000000013 as LOG_ID_TRAFFIC_END_FORWARD. Restricting
	// to this canonical ID excludes start/stat records and their cumulative
	// counters; no delta fields are mixed in. Duplicates and cross-window
	// sessions still prevent treating this sum as unique traffic or bandwidth.
	// https://docs.fortinet.com/document/fortigate/7.6.0/fortios-log-message-reference/13/13-log-id-traffic-end-forward
	query := base + ` AND (type:"traffic" AND subtype:"forward" AND logid:"0000000013")`
	total, err := r.count(ctx, query)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	d.Total = total
	if total == 0 {
		d.Status, d.Reason = "no_data", "No canonical forward-session end records were received in this scope and window; byte counters are unavailable."
		return d
	}
	coveredQuery := query + " AND _exists_:sentbyte AND _exists_:rcvdbyte"
	covered, err := r.count(ctx, coveredQuery)
	if err != nil || covered > total {
		d.Reason = "Byte-counter field coverage could not be established consistently."
		return d
	}
	if covered < total {
		d.MissingFields = []string{"sentbyte", "rcvdbyte"}
	}
	if covered == 0 {
		d.Status, d.Reason = "missing_fields", "Terminal-session records exist, but sentbyte and/or rcvdbyte are missing; a zero byte total is not inferred."
		d.Rows = append(d.Rows, reportmodel.TelemetryRow{Label: "Missing required fields", Count: total})
		return d
	}
	response, err := r.aggregate(ctx, coveredQuery, nil, []aggregateMetric{{Function: "count"}, {Function: "sum", Field: "sentbyte"}, {Function: "sum", Field: "rcvdbyte"}})
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	if len(response.Datarows) != 1 || len(response.Datarows[0]) != len(response.Schema) {
		d.Reason = "Graylog returned an unsupported byte-counter aggregation shape."
		return d
	}
	values := make([]int64, 3)
	for i, metric := range []aggregateMetric{{Function: "count"}, {Function: "sum", Field: "sentbyte"}, {Function: "sum", Field: "rcvdbyte"}} {
		column, err := findColumn(response.Schema, "metric", metric.Field, metric.Function)
		if err != nil {
			d.Reason = err.Error()
			return d
		}
		values[i], err = nonnegativeInteger(response.Datarows[0][column])
		if err != nil {
			d.Reason = err.Error()
			return d
		}
	}
	if values[0] != covered || values[1] > math.MaxInt64-values[2] {
		d.Reason = "Byte-counter aggregation changed during collection or exceeded the supported numeric range."
		return d
	}
	combined := values[1] + values[2]
	d.Rows = append(d.Rows, reportmodel.TelemetryRow{Label: "Reported terminal-session counters", Count: covered, Bytes: &combined, SentBytes: &values[1], ReceivedBytes: &values[2]})
	d.Returned, d.Status = 1, "available"
	d.Reason = "Sum of received logid 0000000013 sentbyte/rcvdbyte counters only. Session lifetimes can cross the window; duplicated or missing logs and HA observations are not deduplicated. This is not unique transferred traffic, an interface throughput measurement, or billing evidence."
	if covered < total {
		d.Status = "partial"
		d.Rows = append(d.Rows, reportmodel.TelemetryRow{Label: "Missing required fields", Count: total - covered})
	}
	return d
}

func (r *run) trend(ctx context.Context, query string) reportmodel.TelemetryDataset {
	d := reportmodel.TelemetryDataset{ID: "traffic_trend", Title: "Received forward-traffic records over time", TitleDE: "Empfangene Forward-Verkehrslogs im Zeitverlauf", Status: "error", Limit: 12, MissingFields: []string{}, Rows: []reportmodel.TelemetryRow{}}
	total, err := r.count(ctx, query)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	d.Total = total
	if total == 0 {
		d.Status, d.Reason = "no_data", "No forward-traffic records were received for the selected scope and window."
		return d
	}
	step := r.window.end.Sub(r.window.start) / 12
	var sum int64
	rows := make([]reportmodel.TelemetryRow, 0, 12)
	for i := 0; i < 12; i++ {
		start := r.window.start.Add(time.Duration(i) * step)
		end := start.Add(step)
		count, err := r.count(ctx, query+" AND "+halfOpenWindow(start, end))
		if err != nil || count > total-sum {
			d.Reason = "Time-bucket counts could not be established consistently within the collection limits."
			return d
		}
		sum += count
		rows = append(rows, reportmodel.TelemetryRow{Label: start.Format(time.RFC3339Nano), Secondary: end.Format(time.RFC3339Nano), Timestamp: start, Count: count})
	}
	if sum != total {
		d.Rows = []reportmodel.TelemetryRow{}
		d.Reason = "Time-bucket counts changed during collection or do not cover the matched-record denominator."
		return d
	}
	d.Returned, d.Status = 12, "available"
	d.Rows = rows
	d.Reason = "Twelve adjacent half-open UTC intervals [start, end) count received log records. Shared boundaries are counted once. This is not a bandwidth or session-rate measurement."
	return d
}

func summarize(datasets []reportmodel.TelemetryDataset, missingClassification bool) (string, string) {
	useful, failed, incomplete := false, false, missingClassification
	for _, dataset := range datasets {
		if dataset.Status == "error" {
			failed = true
		}
		if dataset.Status == "partial" || dataset.Status == "missing_fields" {
			incomplete = true
		}
		if dataset.Status != "error" && dataset.Status != "no_data" && dataset.Total > 0 {
			useful = true
		}
	}
	if failed && !useful {
		return "error", "No usable analytics datasets were completed; consult dataset status. Configuration facts are independent of this failure."
	}
	if useful && (failed || incomplete) {
		return "partial", "Some observations are available, but required fields, returned-group limits, or collection failures limit coverage. Dataset totals overlap and must not be added together."
	}
	if useful {
		return "available", "Observations cover received Graylog records in the selected source/VDOM/time scope. Log completeness and unique-session accounting are not established. Dataset totals overlap and must not be added together."
	}
	if missingClassification {
		return "missing_fields", "Some matching records lack canonical type/subtype fields, so available report categories may not represent all received activity."
	}
	return "no_data", "Matching source records exist, but no supported traffic, UTM, or VPN observations were available for this window."
}
