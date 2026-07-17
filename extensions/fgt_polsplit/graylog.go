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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// graylogHTTPTimeout is a generous per-request ceiling on Graylog HTTP calls.
// It is a backstop only: the effective limit is the caller's context deadline
// (POLSPLIT_ANALYZE_TIMEOUT), so no single request may be capped shorter than
// the analysis budget still allows.
const graylogHTTPTimeout = 120 * time.Second

// chunkSemKey carries a shared chunk-concurrency semaphore through the context.
// The independent aggregation rounds of one analysis run in parallel but draw
// their sub-window slots from this single bound, so peak Graylog concurrency
// stays at chunkConcurrency even while the rounds overlap.
type chunkSemKey struct{}

func withChunkSem(ctx context.Context, sem chan struct{}) context.Context {
	return context.WithValue(ctx, chunkSemKey{}, sem)
}

func chunkSemFrom(ctx context.Context) chan struct{} {
	if s, ok := ctx.Value(chunkSemKey{}).(chan struct{}); ok {
		return s
	}
	return nil
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
	// A generous per-request ceiling; the real governor is the caller's
	// context deadline (POLSPLIT_ANALYZE_TIMEOUT). A fixed 30s here used to
	// abort the whole analysis at its very first step even when most of the
	// budget was still available.
	client := &http.Client{Timeout: graylogHTTPTimeout}
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
	// The context deadline (POLSPLIT_ANALYZE_TIMEOUT) is the real governor.
	client := &http.Client{Timeout: graylogHTTPTimeout}
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

// Chunked-loading tuning: windows larger than chunkAlwaysAbove are ALWAYS
// aggregated as a series of absolute sub-windows and merged — long windows on
// busy policies push a single Graylog aggregation past its execution limits,
// and per-step aggregation also raises the effective group limits. Shorter
// windows run as one call and fall back to the same chunking when the
// full-window call fails. Steps are one hour; long windows grow the step so
// a run never exceeds maxChunks calls (30 days → 48 × 15h instead of 720 × 1h).
const (
	chunkStep        = time.Hour
	chunkAlwaysAbove = 12 * time.Hour
	maxChunks        = 48
	// minChunk floors the adaptive subdivision: a failing sub-window is
	// halved and retried until it either succeeds or reaches this size —
	// extremely busy policies can overrun Graylog's aggregation limits even
	// within a single hour.
	minChunk = 15 * time.Minute
)

// bounds resolves the window to absolute UTC instants (relative windows are
// anchored at now).
func (t timeRange) bounds(now time.Time) (from, to time.Time, err error) {
	if t.RelativeSec > 0 {
		to = now.UTC()
		return to.Add(-time.Duration(t.RelativeSec) * time.Second), to, nil
	}
	if from, err = time.Parse(graylogTimeLayout, t.From); err != nil {
		return from, to, err
	}
	to, err = time.Parse(graylogTimeLayout, t.To)
	return from, to, err
}

// splitTimeRange cuts the window into consecutive absolute sub-windows of
// chunkStep (grown so at most maxChunks result). Windows that fit in a single
// step return nil — there is nothing to split.
func splitTimeRange(tr timeRange, now time.Time) []timeRange {
	from, to, err := tr.bounds(now)
	if err != nil || !to.After(from) {
		return nil
	}
	window := to.Sub(from)
	if window <= chunkStep {
		return nil
	}
	step := chunkStep
	if window > time.Duration(maxChunks)*step {
		step = (window + maxChunks - 1) / maxChunks
	}
	var out []timeRange
	for cur := from; cur.Before(to); cur = cur.Add(step) {
		end := cur.Add(step)
		if end.After(to) {
			end = to
		}
		out = append(out, timeRange{
			From: cur.UTC().Format(graylogTimeLayout),
			To:   end.UTC().Format(graylogTimeLayout),
		})
	}
	return out
}

// mergeTuples folds per-chunk aggregation results back into one tuple set:
// identical (src,dst,proto,port,service) rows sum their hits and keep the
// latest timestamp.
func mergeTuples(lists ...[]TrafficTuple) []TrafficTuple {
	type key struct {
		src, dst, proto, svc string
		port                 int
	}
	idx := map[key]int{}
	var out []TrafficTuple
	for _, list := range lists {
		for _, t := range list {
			k := key{t.SrcIP, t.DstIP, t.Proto, t.Service, t.Port}
			if i, ok := idx[k]; ok {
				out[i].Hits += t.Hits
				if t.LastSeen > out[i].LastSeen {
					out[i].LastSeen = t.LastSeen
				}
			} else {
				idx[k] = len(out)
				out = append(out, t)
			}
		}
	}
	return out
}

// runTupleAggregation executes one tuple aggregation. Windows larger than
// chunkAlwaysAbove go straight to chunked sub-window loading; shorter windows
// run as one full-window call and fall back to chunking when that call fails.
// Sub-window progress is published as a note (never a step) so the UI bar can
// interpolate within the current stage.
func (e *Extension) runTupleAggregation(ctx context.Context, body aggregateRequest, tr timeRange, label string) ([]TrafficTuple, []string, error) {
	now := time.Now()
	if from, to, berr := tr.bounds(now); berr == nil && to.Sub(from) > chunkAlwaysAbove {
		if chunks := splitTimeRange(tr, now); len(chunks) >= 2 {
			tuples, err := e.runChunks(ctx, body, chunks, label)
			return tuples, nil, err
		}
	}
	schema, rows, err := e.aggregate(ctx, body)
	if err == nil {
		return parseTupleRows(schema, rows), nil, nil
	}
	if ctx.Err() != nil {
		return nil, nil, err // caller gone — don't hammer Graylog with retries
	}
	chunks := splitTimeRange(tr, now)
	if len(chunks) < 2 {
		return nil, nil, err
	}
	e.logger.Warn("polsplit: full-window aggregation failed, retrying in sub-windows",
		"label", label, "chunks", len(chunks), "err", err)
	tuples, cerr := e.runChunks(ctx, body, chunks, label)
	if cerr != nil {
		return nil, nil, cerr
	}
	warning := fmt.Sprintf("%s: the full-window aggregation failed and was completed in %d smaller time steps instead (full-window error: %v)",
		label, len(chunks), err)
	return tuples, []string{warning}, nil
}

// chunkConcurrency bounds how many sub-window aggregations run at once.
// Sequential chunking turned a 24h window into ~24 back-to-back Graylog
// round-trips (60s+ on a small policy — enough to trip a 60s reverse-proxy
// timeout); running them a few at a time cuts wall time proportionally while
// staying well within what the Graylog cluster tolerates.
const chunkConcurrency = 5

// runChunks runs the aggregation for every sub-window (bounded-concurrently)
// and merges the results, publishing completed-count progress notes. Chunk
// order does not affect the merge, so results are gathered by index and the
// first failure cancels the rest.
func (e *Extension) runChunks(ctx context.Context, body aggregateRequest, chunks []timeRange, label string) ([]TrafficTuple, error) {
	note := progressNoteFrom(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([][]TrafficTuple, len(chunks))
	errs := make([]error, len(chunks))
	// A shared semaphore from the context bounds concurrency across all the
	// aggregation rounds that run in parallel (see fetchPolicyTraffic); absent
	// that, each call bounds itself.
	sem := chunkSemFrom(ctx)
	if sem == nil {
		sem = make(chan struct{}, chunkConcurrency)
	}
	var wg sync.WaitGroup
	var done int32
	// The failure that triggered cancellation is captured directly: after
	// cancel(), other chunks fail with context.Canceled, and an index-ordered
	// scan of errs could surface one of those instead of the root cause.
	var firstErr error
	var firstIdx int
	var errOnce sync.Once

	for i := range chunks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			// runChunkWindow takes body by value, so concurrent calls never
			// share the mutated Timerange field.
			tuples, err := e.runChunkWindow(ctx, body, chunks[i])
			if err != nil {
				if ctx.Err() == nil { // a real failure, not cancellation fallout
					errOnce.Do(func() { firstErr, firstIdx = err, i })
				}
				errs[i] = err
				cancel() // stop remaining sub-windows on the first hard failure
				return
			}
			results[i] = tuples
			n := atomic.AddInt32(&done, 1)
			note(fmt.Sprintf("time step %d/%d", n, len(chunks)), int(n), len(chunks))
		}(i)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, fmt.Errorf("%s: sub-window %d/%d (%s to %s): %w", label, firstIdx+1, len(chunks), chunks[firstIdx].From, chunks[firstIdx].To, firstErr)
	}
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("%s: sub-window %d/%d (%s to %s): %w", label, i+1, len(chunks), chunks[i].From, chunks[i].To, err)
		}
	}
	note(fmt.Sprintf("merging %d time steps", len(chunks)), len(chunks), len(chunks))
	return mergeTuples(results...), nil
}

// runChunkWindow aggregates one sub-window, adaptively halving it on failure
// down to minChunk — the busiest policies can exceed Graylog's aggregation
// limits even inside a one-hour step.
func (e *Extension) runChunkWindow(ctx context.Context, body aggregateRequest, c timeRange) ([]TrafficTuple, error) {
	body.Timerange = c.aggregate()
	schema, rows, err := e.aggregate(ctx, body)
	if err == nil {
		return parseTupleRows(schema, rows), nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	from, ferr := time.Parse(graylogTimeLayout, c.From)
	to, terr := time.Parse(graylogTimeLayout, c.To)
	if ferr != nil || terr != nil || to.Sub(from) <= minChunk {
		return nil, err
	}
	e.logger.Warn("polsplit: sub-window aggregation failed, halving", "from", c.From, "to", c.To, "err", err)
	mid := from.Add(to.Sub(from) / 2).UTC().Format(graylogTimeLayout)
	first, err := e.runChunkWindow(ctx, body, timeRange{From: c.From, To: mid})
	if err != nil {
		return nil, err
	}
	second, err := e.runChunkWindow(ctx, body, timeRange{From: mid, To: c.To})
	if err != nil {
		return nil, err
	}
	return mergeTuples(first, second), nil
}

// fetchPolicyTraffic aggregates the policy's traffic into src/dst/service
// tuples. Two aggregations run because grouping drops documents missing a
// grouped field: one over port-carrying logs (tcp/udp/sctp) grouped by dstport,
// one over portless logs (icmp/gre/esp/…) without it. totalMessages carries the
// window's raw match count for diagnostics.
// vdDropped reports that the VDOM filter was dropped because the deployment
// does not index the vd field — the caller must drop it from its follow-up
// queries (baseline, UTM, identity) too.
func (e *Extension) fetchPolicyTraffic(ctx context.Context, fqdn string, policyID int, vdom string, tr timeRange, report func(string)) (tuples []TrafficTuple, totalMessages int64, warnings []string, vdDropped bool, err error) {
	if report == nil {
		report = func(string) {}
	}
	if strings.TrimRight(e.cfg.GraylogURL, "/") == "" || e.cfg.GraylogToken == "" {
		return nil, 0, []string{"Graylog is not configured (set GRAYLOG_URL and GRAYLOG_TOKEN) — no traffic data available"}, false, nil
	}
	if !tr.valid() {
		return nil, 0, nil, false, errors.New("invalid time range")
	}
	query, err := e.buildPolicyQuery(fqdn, policyID, vdom)
	if err != nil {
		return nil, 0, nil, false, err
	}

	report("Counting matching log messages")
	totalMessages, err = e.countMessages(ctx, query, tr)
	if err != nil {
		return nil, 0, nil, false, err
	}
	// Many Graylog deployments never index the `vd` field even though the
	// raw syslog carries it — the filter then silently zeroes every result.
	// Detect it: if the vd-qualified query matches nothing but the same
	// query without the clause does, drop the clause and say so.
	if totalMessages == 0 && vdom != "" {
		if noVd, qerr := e.buildPolicyQuery(fqdn, policyID, ""); qerr == nil {
			if n, cerr := e.countMessages(ctx, noVd, tr); cerr == nil && n > 0 {
				query, totalMessages, vdDropped = noVd, n, true
				warnings = append(warnings, fmt.Sprintf(
					"the VDOM filter (vd:%q) matched nothing but %d message(s) match without it — this Graylog deployment likely does not index the vd field; the VDOM filter was dropped for this analysis (results may include other VDOMs' traffic for the same policy ID)",
					vdom, n))
			}
		}
	}
	progressNoteFrom(ctx)(fmt.Sprintf("%d log messages in the window", totalMessages), 0, 0)

	// Two independent aggregation rounds run concurrently: (1) the
	// authoritative tuple set without service grouping (so no message is
	// omitted), and (2) the service-grouped set used only to decorate service
	// names. They share one chunk-concurrency semaphore, so peak Graylog load
	// stays at chunkConcurrency even though the rounds overlap — this roughly
	// halves wall time on long windows versus running them back-to-back.
	sem := make(chan struct{}, chunkConcurrency)
	cctx := withChunkSem(ctx, sem)
	var (
		tupleWarnings, svcWarnings []string
		svcTuples                  []TrafficTuple
		tupleErr, svcErr           error
		wg                         sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		tuples, tupleWarnings, tupleErr = e.aggregateTuples(cctx, query, tr, false, report)
	}()
	go func() {
		defer wg.Done()
		svcTuples, svcWarnings, svcErr = e.aggregateTuples(cctx, query, tr, true, report)
	}()
	wg.Wait()

	// 1. The authoritative round must succeed.
	if tupleErr != nil {
		return nil, 0, nil, vdDropped, tupleErr
	}
	warnings = append(warnings, tupleWarnings...)

	// 2. Service-name decoration is best-effort.
	err = svcErr
	if err != nil {
		e.logger.Warn("polsplit: service-present aggregation failed, using no-service results only", "err", err)
		warnings = append(warnings, "service-name aggregation failed — traffic tuples are complete but shown without FortiOS service names: "+err.Error())
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
	return tuples, totalMessages, warnings, vdDropped, nil
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
	// The whole baseline fetch counts as one progress step in the handler.
	tuples, _, err := e.aggregateTuples(ctx, query, tr, false, nil)
	return tuples, err
}

// utmGroupLimit caps the UTM-blocked destination aggregation; reaching it is
// reported by the handler as a truncation warning.
const utmGroupLimit = 1000

// utmBlocked is one destination that triggered UTM block verdicts under the
// analyzed policy — a signal to review before re-allowing it in a split.
type utmBlocked struct {
	IP   string `json:"ip"`
	Hits int64  `json:"hits"`
}

// fetchUTMBlocked aggregates destinations whose sessions under this policy
// were blocked/dropped/reset by UTM inspection in the analysis window.
func (e *Extension) fetchUTMBlocked(ctx context.Context, fqdn string, policyID int, vdom string, tr timeRange) ([]utmBlocked, error) {
	if strings.TrimRight(e.cfg.GraylogURL, "/") == "" || e.cfg.GraylogToken == "" {
		return nil, nil
	}
	query, err := e.buildPolicyQuery(fqdn, policyID, vdom)
	if err != nil {
		return nil, err
	}
	// FortiOS UTM logs use both "blocked" and "block" as action values
	// depending on the inspecting engine — both are real block verdicts.
	query += ` AND type:"utm" AND action:("blocked" OR "block" OR "dropped" OR "reset")`
	body := aggregateRequest{
		Query:     query,
		Timerange: tr.aggregate(),
		GroupBy:   []aggregateGroup{{Field: "dstip", Limit: utmGroupLimit}},
		Metrics:   []aggregateMetric{{Function: "count"}},
	}
	schema, rows, err := e.aggregate(ctx, body)
	if err != nil {
		return nil, err
	}
	ipCol, cntCol := -1, -1
	for i, c := range schema {
		switch {
		case c.ColumnType == "grouping" && c.Field == "dstip":
			ipCol = i
		case c.ColumnType == "metric" && c.Function == "count":
			cntCol = i
		}
	}
	if ipCol < 0 || cntCol < 0 {
		return nil, fmt.Errorf("graylog utm aggregation: unexpected schema %+v", schema)
	}
	var out []utmBlocked
	for _, row := range rows {
		if ipCol >= len(row) || cntCol >= len(row) || row[ipCol] == nil {
			continue
		}
		ip, _ := row[ipCol].(string)
		ip = strings.TrimSpace(ip)
		if ip == "" || strings.EqualFold(ip, "(Empty Value)") {
			continue
		}
		var hits int64
		if f, ok := row[cntCol].(float64); ok {
			hits = int64(f)
		}
		out = append(out, utmBlocked{IP: ip, Hits: hits})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

// aggregateTuples runs the tuple aggregation pair: one query over
// port-carrying logs (tcp/udp/sctp) grouped by dstport, one over portless logs
// (icmp/gre/esp/…) without it — grouping drops documents that miss a grouped
// field, so a single combined aggregation would silently lose ICMP traffic.
func (e *Extension) aggregateTuples(ctx context.Context, query string, tr timeRange, includeService bool, report func(string)) (tuples []TrafficTuple, warnings []string, err error) {
	if report == nil {
		report = func(string) {}
	}
	stage := "Aggregating traffic tuples"
	if includeService {
		stage = "Fetching service names"
	}
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

	report(stage + " (port traffic)")
	withPort := aggregateRequest{
		Query:     query + " AND _exists_:dstport",
		Timerange: tr.aggregate(),
		GroupBy:   append(append([]aggregateGroup{}, base...), aggregateGroup{Field: "dstport", Limit: groupLimit}),
		Metrics:   metrics,
	}
	portTuples, w, err := e.runTupleAggregation(ctx, withPort, tr, stage+" (port traffic)")
	if err != nil {
		return nil, nil, err
	}
	warnings = append(warnings, w...)
	tuples = append(tuples, portTuples...)

	report(stage + " (portless protocols)")
	withoutPort := aggregateRequest{
		Query:     query + " AND NOT _exists_:dstport",
		Timerange: tr.aggregate(),
		GroupBy:   base,
		Metrics:   metrics,
	}
	plTuples, w, err := e.runTupleAggregation(ctx, withoutPort, tr, stage+" (portless protocols)")
	if err != nil {
		e.logger.Warn("polsplit: portless-traffic aggregation failed, continuing with port-carrying tuples only", "err", err)
		warnings = append(warnings, "portless-protocol aggregation failed: "+err.Error())
	} else {
		warnings = append(warnings, w...)
		tuples = append(tuples, plTuples...)
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

// userActivity is one authenticated identity observed under the policy.
// FortiGate populates user/group on identity-based traffic (VPN, FSSO,
// captive portal) — for those policies, splitting by group beats splitting
// by source IP, since client IPs are pool-assigned and ephemeral.
type userActivity struct {
	User  string `json:"user"`
	Group string `json:"group"`
	Hits  int64  `json:"hits"`
}

// fetchUserActivity aggregates the authenticated users (and their groups)
// seen in the policy's traffic. Best-effort: policies without identity
// traffic simply return nothing.
func (e *Extension) fetchUserActivity(ctx context.Context, fqdn string, policyID int, vdom string, tr timeRange) ([]userActivity, error) {
	if strings.TrimRight(e.cfg.GraylogURL, "/") == "" || e.cfg.GraylogToken == "" {
		return nil, nil
	}
	query, err := e.buildPolicyQuery(fqdn, policyID, vdom)
	if err != nil {
		return nil, err
	}
	body := aggregateRequest{
		Query:     query + " AND _exists_:user",
		Timerange: tr.aggregate(),
		GroupBy:   []aggregateGroup{{Field: "user", Limit: 200}, {Field: "group", Limit: 50}},
		Metrics:   []aggregateMetric{{Function: "count"}},
	}
	schema, rows, err := e.aggregate(ctx, body)
	if err != nil {
		return nil, err
	}
	userCol, grpCol, cntCol := -1, -1, -1
	for i, c := range schema {
		switch {
		case c.ColumnType == "grouping" && c.Field == "user":
			userCol = i
		case c.ColumnType == "grouping" && c.Field == "group":
			grpCol = i
		case c.ColumnType == "metric" && c.Function == "count":
			cntCol = i
		}
	}
	if userCol < 0 || cntCol < 0 {
		return nil, fmt.Errorf("graylog user aggregation: unexpected schema %+v", schema)
	}
	var out []userActivity
	for _, row := range rows {
		if userCol >= len(row) || cntCol >= len(row) || row[userCol] == nil {
			continue
		}
		user, _ := row[userCol].(string)
		user = strings.TrimSpace(user)
		if user == "" || strings.EqualFold(user, "(Empty Value)") {
			continue
		}
		group := ""
		if grpCol >= 0 && grpCol < len(row) {
			group, _ = row[grpCol].(string)
			group = strings.TrimSpace(group)
			if strings.EqualFold(group, "(Empty Value)") {
				group = ""
			}
		}
		var hits int64
		if f, ok := row[cntCol].(float64); ok {
			hits = int64(f)
		}
		out = append(out, userActivity{User: user, Group: group, Hits: hits})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].User < out[j].User
	})
	return out, nil
}

// appUsage is one application-control detection under the policy, with the
// backup's matching Internet-Service objects (ISDB tracks the provider's IP
// ranges automatically — usually better than IP/FQDN objects for SaaS).
type appUsage struct {
	App      string   `json:"app"`
	Category string   `json:"category"`
	Hits     int64    `json:"hits"`
	ISDB     []string `json:"isdb"`
}

// fetchAppUsage aggregates application-control detections (app/appcat) in
// the policy's traffic. Best-effort: policies without an application-list
// simply log no app field and return nothing.
func (e *Extension) fetchAppUsage(ctx context.Context, fqdn string, policyID int, vdom string, tr timeRange) ([]appUsage, error) {
	if strings.TrimRight(e.cfg.GraylogURL, "/") == "" || e.cfg.GraylogToken == "" {
		return nil, nil
	}
	query, err := e.buildPolicyQuery(fqdn, policyID, vdom)
	if err != nil {
		return nil, err
	}
	body := aggregateRequest{
		Query:     query + " AND _exists_:app",
		Timerange: tr.aggregate(),
		GroupBy:   []aggregateGroup{{Field: "app", Limit: 200}, {Field: "appcat", Limit: 50}},
		Metrics:   []aggregateMetric{{Function: "count"}},
	}
	schema, rows, err := e.aggregate(ctx, body)
	if err != nil {
		return nil, err
	}
	appCol, catCol, cntCol := -1, -1, -1
	for i, c := range schema {
		switch {
		case c.ColumnType == "grouping" && c.Field == "app":
			appCol = i
		case c.ColumnType == "grouping" && c.Field == "appcat":
			catCol = i
		case c.ColumnType == "metric" && c.Function == "count":
			cntCol = i
		}
	}
	if appCol < 0 || cntCol < 0 {
		return nil, fmt.Errorf("graylog app aggregation: unexpected schema %+v", schema)
	}
	var out []appUsage
	for _, row := range rows {
		if appCol >= len(row) || cntCol >= len(row) || row[appCol] == nil {
			continue
		}
		app, _ := row[appCol].(string)
		app = strings.TrimSpace(app)
		if app == "" || strings.EqualFold(app, "(Empty Value)") {
			continue
		}
		cat := ""
		if catCol >= 0 && catCol < len(row) {
			cat, _ = row[catCol].(string)
			cat = strings.TrimSpace(cat)
			if strings.EqualFold(cat, "(Empty Value)") {
				cat = ""
			}
		}
		var hits int64
		if f, ok := row[cntCol].(float64); ok {
			hits = int64(f)
		}
		out = append(out, appUsage{App: app, Category: cat, Hits: hits})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].App < out[j].App
	})
	return out, nil
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
