// Package reportlogs collects bounded, server-aggregated FortiGate observations
// from the configured Graylog service. It never fetches a sample and presents
// its counts as an exhaustive report.
package reportlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

const (
	maxResponse = 2 << 20
	maxQueries  = 40
	groupLimit  = 20
)

type Collector struct {
	baseURL  string
	token    string
	dataDir  string
	setupErr string
	client   *http.Client
}

// New copies integration settings so a collection has a stable credential and
// destination. Redirects are rejected, including redirects to the same host.
func New(cfg *config.Config, dataDir string) *Collector {
	c := &Collector{dataDir: dataDir, client: &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if cfg == nil || cfg.GraylogURL == "" || cfg.GraylogToken == "" {
		return c
	}
	u, err := url.Parse(cfg.GraylogURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") {
		c.setupErr = "The configured Graylog URL is invalid."
		return c
	}
	if u.Scheme == "http" && !cfg.AllowInsecureHTTPIntegrations {
		c.setupErr = "Graylog requires HTTPS unless insecure HTTP integrations are explicitly enabled."
		return c
	}
	c.baseURL = strings.TrimRight(u.String(), "/")
	c.token = cfg.GraylogToken
	return c
}

type timeWindow struct{ start, end time.Time }

type run struct {
	collector *Collector
	window    timeWindow
	sem       chan struct{}
	calls     atomic.Int32
	mu        sync.Mutex
	counts    map[string]*countResult
}

type countResult struct {
	ready chan struct{}
	n     int64
	err   error
}

type aggregateGroup struct {
	Field string `json:"field"`
	Limit int    `json:"limit"`
}

type aggregateMetric struct {
	Function string `json:"function"`
	Field    string `json:"field,omitempty"`
	Sort     string `json:"sort,omitempty"`
}

type aggregateRequest struct {
	Query     string             `json:"query"`
	Timerange aggregateTimerange `json:"timerange"`
	GroupBy   []aggregateGroup   `json:"group_by"`
	Metrics   []aggregateMetric  `json:"metrics"`
}

type aggregateTimerange struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

type aggregateColumn struct {
	ColumnType string `json:"column_type"`
	Field      string `json:"field"`
	Function   string `json:"function"`
}

type aggregateResponse struct {
	Schema   []aggregateColumn `json:"schema"`
	Datarows [][]any           `json:"datarows"`
	Errors   json.RawMessage   `json:"errors"`
	Metadata responseMetadata  `json:"metadata"`
}

type responseMetadata struct {
	EffectiveTimerange aggregateTimerange `json:"effective_timerange"`
}

func (r *run) request(ctx context.Context, method, path string, data []byte, result any) error {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return errors.New("graylog collection was canceled or exceeded its time limit")
	}
	if r.calls.Add(1) > maxQueries {
		return errors.New("graylog collection reached the query limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, r.collector.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("graylog request could not be created")
	}
	req.SetBasicAuth(r.collector.token, "token")
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-By", "fortisafe-reports")
	}
	resp, err := r.collector.client.Do(req)
	if err != nil {
		return errors.New("graylog request failed or exceeded its time limit")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("graylog returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return errors.New("graylog response could not be read within the response-size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err = decoder.Decode(result); err != nil {
		return errors.New("graylog response is not valid structured data")
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("graylog response contains unexpected trailing data")
	}
	return nil
}

func (r *run) count(ctx context.Context, query string) (int64, error) {
	r.mu.Lock()
	if cached := r.counts[query]; cached != nil {
		r.mu.Unlock()
		select {
		case <-cached.ready:
			return cached.n, cached.err
		case <-ctx.Done():
			return 0, errors.New("graylog collection was canceled or exceeded its time limit")
		}
	}
	cached := &countResult{ready: make(chan struct{})}
	r.counts[query] = cached
	r.mu.Unlock()
	defer close(cached.ready)
	params := url.Values{"query": {query}, "limit": {"1"}, "from": {r.window.start.Format(time.RFC3339Nano)}, "to": {r.window.end.Format(time.RFC3339Nano)}}
	var response struct {
		TotalResults json.Number `json:"total_results"`
		From         string      `json:"from"`
		To           string      `json:"to"`
	}
	cached.err = r.request(ctx, http.MethodGet, "/api/search/universal/absolute?"+params.Encode(), nil, &response)
	if cached.err == nil {
		// Universal search returns its effective range at the top level, unlike
		// aggregation metadata. Require both bounds even for an empty result so
		// a server-side range limit cannot become a full-window no-data claim.
		cached.err = r.validateWindow(response.From, response.To)
	}
	if cached.err == nil {
		cached.n, cached.err = nonnegativeInteger(response.TotalResults)
	}
	return cached.n, cached.err
}

func (r *run) aggregate(ctx context.Context, query string, groups []string, metrics []aggregateMetric) (aggregateResponse, error) {
	body := aggregateRequest{Query: query, Timerange: aggregateTimerange{Type: "absolute", From: r.window.start.Format(time.RFC3339Nano), To: r.window.end.Format(time.RFC3339Nano)}, GroupBy: []aggregateGroup{}, Metrics: metrics}
	for _, field := range groups {
		body.GroupBy = append(body.GroupBy, aggregateGroup{Field: field, Limit: groupLimit})
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return aggregateResponse{}, errors.New("graylog aggregation could not be created")
	}
	var response aggregateResponse
	if err = r.request(ctx, http.MethodPost, "/api/search/aggregate", encoded, &response); err != nil {
		return aggregateResponse{}, err
	}
	if len(response.Schema) == 0 || len(response.Schema) > 16 || len(response.Datarows) > groupLimit*groupLimit {
		return aggregateResponse{}, errors.New("graylog aggregation has an unsupported schema or exceeds the row limit")
	}
	if e := strings.TrimSpace(string(response.Errors)); e != "" && e != "null" && e != "[]" && e != "{}" {
		return aggregateResponse{}, errors.New("graylog reported an incomplete aggregation")
	}
	if err = r.validateEffectiveWindow(response.Metadata); err != nil {
		return aggregateResponse{}, err
	}
	return response, nil
}

func (r *run) validateEffectiveWindow(metadata responseMetadata) error {
	effective := metadata.EffectiveTimerange
	if effective.Type == "" && effective.From == "" && effective.To == "" {
		return nil // Older endpoints do not return effective range metadata.
	}
	if effective.Type != "" && effective.Type != "absolute" {
		return errors.New("graylog effective time window differs from the requested pinned window")
	}
	return r.validateWindow(effective.From, effective.To)
}

func (r *run) validateWindow(start, end string) error {
	from, fromErr := time.Parse(time.RFC3339Nano, start)
	to, toErr := time.Parse(time.RFC3339Nano, end)
	if fromErr != nil || toErr != nil || !from.Equal(r.window.start) || !to.Equal(r.window.end) {
		return errors.New("graylog effective time window differs from the requested pinned window")
	}
	return nil
}

// JSON numbers are kept exact, including values above 2^53. Integral decimal
// sums such as 12.0 are accepted; fractions, negatives, and overflow fail.
func nonnegativeInteger(value any) (int64, error) {
	number, ok := value.(json.Number)
	if !ok || len(number.String()) == 0 || len(number.String()) > 128 {
		return 0, errors.New("graylog returned an invalid numeric count or counter")
	}
	text := number.String()
	if pos := strings.IndexAny(text, "eE"); pos >= 0 {
		exponent, err := strconv.Atoi(text[pos+1:])
		if err != nil || exponent < -100 || exponent > 100 {
			return 0, errors.New("graylog numeric count or counter exceeds the supported range")
		}
	}
	valueRat, ok := new(big.Rat).SetString(text)
	if !ok || valueRat.Sign() < 0 || !valueRat.IsInt() || !valueRat.Num().IsInt64() {
		return 0, errors.New("graylog returned a negative, fractional, or overflowing count or counter")
	}
	return valueRat.Num().Int64(), nil
}

func escaped(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func halfOpenWindow(start, end time.Time) string {
	return `timestamp:["` + start.Format(time.RFC3339Nano) + `" TO "` + end.Format(time.RFC3339Nano) + `"}`
}
