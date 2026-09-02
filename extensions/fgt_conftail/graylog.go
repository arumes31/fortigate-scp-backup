package fgtconftail

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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	graylogDefaultPageSize    = 500
	graylogMaxPageSize        = 1000
	graylogMaxPages           = 100
	graylogMaxResponseBytes   = 8 << 20
	graylogMaxDecodedBytes    = 64 << 20
	graylogMaxSourceAliases   = 64
	graylogMaxSourceAliasSize = 512
	graylogMaxQuerySize       = 32 << 10
	graylogMaxEventTimeDigits = 128
	graylogCanonicalLogIDSize = 10
	graylogRetryAttempts      = 3
	graylogRetryBase          = 250 * time.Millisecond
	graylogRetryMax           = 30 * time.Second
)

var graylogSelectedFields = []string{
	"timestamp",
	"gl2_message_id",
	"eventtime",
	"type",
	"subtype",
	"source",
	"devname",
	"devid",
	"vd",
	"user",
	"ui",
	"action",
	"cfgtid",
	"cfgpath",
	"cfgobj",
	"cfgattr",
	"logid",
	"logdesc",
	"msg",
	"uuid",
}

// RawEvent is one validated Graylog row before firewall attribution and
// persistence. EventTime remains a json.Number so large FortiGate nanosecond
// values are never rounded through float64.
type RawEvent struct {
	Timestamp           time.Time   `json:"timestamp"`
	MessageID           string      `json:"message_id"`
	EventTime           json.Number `json:"eventtime,omitempty"`
	Type                string      `json:"type,omitempty"`
	Subtype             string      `json:"subtype,omitempty"`
	Source              string      `json:"source,omitempty"`
	DeviceName          string      `json:"devname,omitempty"`
	DeviceID            string      `json:"devid,omitempty"`
	VDOM                string      `json:"vd,omitempty"`
	User                string      `json:"user,omitempty"`
	UI                  string      `json:"ui,omitempty"`
	Action              string      `json:"action,omitempty"`
	ConfigTransactionID string      `json:"cfgtid,omitempty"`
	ConfigPath          string      `json:"cfgpath,omitempty"`
	ConfigObject        string      `json:"cfgobj,omitempty"`
	ConfigAttribute     string      `json:"cfgattr,omitempty"`
	LogID               string      `json:"logid,omitempty"`
	LogDescription      string      `json:"logdesc,omitempty"`
	Message             string      `json:"msg,omitempty"`
	UUID                string      `json:"uuid,omitempty"`
}

// FetchStats describes pages and rows received by the Graylog client. Rows
// includes quarantined rows; only valid events are returned. Callers can report
// partial progress when fetch returns an error, but events are deliberately
// returned only after every page succeeds.
type FetchStats struct {
	Pages       int
	Rows        int
	Quarantined int
	Retries     int
}

type graylogClient struct {
	endpoint         string
	token            string
	httpClient       *http.Client
	pageSize         int
	maxPages         int
	maxResponseBytes int64
	maxDecodedBytes  int64
	retryAttempts    int
	retryBase        time.Duration
	retryMax         time.Duration
	retryJitter      func(time.Duration) time.Duration
	sleep            func(context.Context, time.Duration) error
	now              func() time.Time
}

type graylogPage struct {
	events      []RawEvent
	rows        int
	quarantined int
	retries     int
}

type graylogAttemptError struct {
	err        error
	retryable  bool
	retryAfter time.Duration
}

func (e *graylogAttemptError) Error() string { return e.err.Error() }

func (e *graylogAttemptError) Unwrap() error { return e.err }

type graylogAbsoluteTimerange struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

type graylogSearchRequest struct {
	Query     string                   `json:"query"`
	Fields    []string                 `json:"fields"`
	From      int                      `json:"from"`
	Size      int                      `json:"size"`
	Timerange graylogAbsoluteTimerange `json:"timerange"`
	Sort      string                   `json:"sort"`
	SortOrder string                   `json:"sort_order"`
}

type graylogColumn struct {
	ColumnType string `json:"column_type"`
	Field      string `json:"field"`
}

func newGraylogClient(baseURL, token string, httpClient *http.Client) (*graylogClient, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New("graylog URL is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse graylog URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Opaque != "" {
		return nil, errors.New("graylog URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil {
		return nil, errors.New("graylog URL must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("graylog URL must not contain a query or fragment")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("graylog access token is required")
	}
	for _, r := range token {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return nil, errors.New("graylog access token contains whitespace or control characters")
		}
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &graylogClient{
		endpoint:         strings.TrimRight(baseURL, "/") + "/api/search/messages",
		token:            token,
		httpClient:       &clientCopy,
		pageSize:         graylogDefaultPageSize,
		maxPages:         graylogMaxPages,
		maxResponseBytes: graylogMaxResponseBytes,
		maxDecodedBytes:  graylogMaxDecodedBytes,
		retryAttempts:    graylogRetryAttempts,
		retryBase:        graylogRetryBase,
		retryMax:         graylogRetryMax,
		retryJitter:      randomRetryJitter,
		sleep:            sleepWithContext,
		now:              time.Now,
	}, nil
}

func (c *graylogClient) fetch(
	ctx context.Context,
	baseQuery string,
	sourceAliases []string,
	from, to time.Time,
) ([]RawEvent, FetchStats, error) {
	var stats FetchStats
	if c == nil {
		return nil, stats, errors.New("graylog client is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, stats, err
	}
	if from.IsZero() || to.IsZero() || !from.Before(to) {
		return nil, stats, errors.New("graylog timerange must have non-zero increasing bounds")
	}
	if c.pageSize <= 0 || c.pageSize > graylogMaxPageSize {
		return nil, stats, fmt.Errorf("graylog page size must be between 1 and %d", graylogMaxPageSize)
	}
	if c.maxPages <= 0 || c.maxPages > graylogMaxPages {
		return nil, stats, fmt.Errorf("graylog maximum page count must be between 1 and %d", graylogMaxPages)
	}
	if c.maxResponseBytes <= 0 || c.maxResponseBytes > graylogMaxResponseBytes {
		return nil, stats, fmt.Errorf("graylog response limit must be between 1 and %d bytes", graylogMaxResponseBytes)
	}
	if c.maxDecodedBytes <= 0 || c.maxDecodedBytes > graylogMaxDecodedBytes {
		return nil, stats, fmt.Errorf("graylog decoded-data limit must be between 1 and %d bytes", graylogMaxDecodedBytes)
	}

	query, err := composeGraylogQuery(baseQuery, sourceAliases)
	if err != nil {
		return nil, stats, err
	}
	timerange := graylogAbsoluteTimerange{
		Type: "absolute",
		From: from.UTC().Format(time.RFC3339Nano),
		To:   to.UTC().Format(time.RFC3339Nano),
	}

	events := make([]RawEvent, 0, c.pageSize)
	var decodedBytes int64
	for page := 0; page < c.maxPages; page++ {
		offset := page * c.pageSize
		request := graylogSearchRequest{
			Query:     query,
			Fields:    graylogSelectedFields,
			From:      offset,
			Size:      c.pageSize,
			Timerange: timerange,
			// gl2_message_id is a unique, lexicographically sortable ULID. Using it
			// avoids unstable offset pages when many messages share a timestamp;
			// the completed result is sorted chronologically below.
			Sort:      "gl2_message_id",
			SortOrder: "asc",
		}
		result, err := c.fetchPage(ctx, request)
		if err != nil {
			return nil, stats, fmt.Errorf("fetch graylog page at offset %d: %w", offset, err)
		}
		stats.Pages++
		stats.Rows += result.rows
		stats.Quarantined += result.quarantined
		stats.Retries += result.retries
		for i := range result.events {
			decodedBytes += rawEventBytes(result.events[i])
			if decodedBytes > c.maxDecodedBytes {
				return nil, stats, fmt.Errorf("graylog decoded data exceeds %d-byte limit", c.maxDecodedBytes)
			}
		}
		events = append(events, result.events...)
		if result.rows < c.pageSize {
			sortRawEvents(events)
			return events, stats, nil
		}
	}

	return nil, stats, fmt.Errorf("graylog result exceeded the %d-page safety limit", c.maxPages)
}

func rawEventBytes(event RawEvent) int64 {
	return int64(len(event.EventTime) + len(event.MessageID) + len(event.Type) +
		len(event.Subtype) + len(event.Source) +
		len(event.DeviceName) + len(event.DeviceID) + len(event.VDOM) +
		len(event.User) + len(event.UI) + len(event.Action) +
		len(event.ConfigTransactionID) + len(event.ConfigPath) +
		len(event.ConfigObject) + len(event.ConfigAttribute) + len(event.LogID) +
		len(event.LogDescription) + len(event.Message) + len(event.UUID))
}

func (c *graylogClient) fetchPage(ctx context.Context, body graylogSearchRequest) (graylogPage, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return graylogPage{}, fmt.Errorf("encode graylog request: %w", err)
	}
	attempts := c.retryAttempts
	if attempts <= 0 {
		attempts = graylogRetryAttempts
	}
	for attempt := 0; attempt < attempts; attempt++ {
		page, requestErr := c.fetchPageAttempt(ctx, payload, body.Size)
		if requestErr == nil {
			page.retries = attempt
			return page, nil
		}
		if !requestErr.retryable || attempt == attempts-1 {
			return graylogPage{}, requestErr
		}
		delay := c.retryDelay(attempt, requestErr.retryAfter)
		sleep := c.sleep
		if sleep == nil {
			sleep = sleepWithContext
		}
		if err := sleep(ctx, delay); err != nil {
			return graylogPage{}, err
		}
	}
	return graylogPage{}, errors.New("graylog retry attempts exhausted")
}

func (c *graylogClient) fetchPageAttempt(
	ctx context.Context,
	payload []byte,
	pageSize int,
) (graylogPage, *graylogAttemptError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return graylogPage{}, &graylogAttemptError{
			err: fmt.Errorf("create graylog request: %w", err),
		}
	}
	req.SetBasicAuth(c.token, "token")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "fortisafe")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return graylogPage{}, &graylogAttemptError{err: contextErr}
		}
		return graylogPage{}, &graylogAttemptError{
			err:       fmt.Errorf("send graylog request: %w", err),
			retryable: true,
		}
	}
	if resp.Body == nil {
		return graylogPage{}, &graylogAttemptError{
			err:       errors.New("graylog returned an empty response body"),
			retryable: true,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// Response bodies are controlled by the external service and can contain
		// configuration values. Drain only a small prefix for connection hygiene,
		// but never copy it into logs, SQLite health state, or user-visible errors.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		now := time.Now()
		if c.now != nil {
			now = c.now()
		}
		return graylogPage{}, &graylogAttemptError{
			err:        fmt.Errorf("graylog returned HTTP %d", resp.StatusCode),
			retryable:  graylogStatusRetryable(resp.StatusCode),
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), now),
		}
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if err != nil {
		return graylogPage{}, &graylogAttemptError{
			err:       fmt.Errorf("read graylog response: %w", err),
			retryable: true,
		}
	}
	if int64(len(responseBody)) > c.maxResponseBytes {
		return graylogPage{}, &graylogAttemptError{
			err: fmt.Errorf("graylog response exceeds %d-byte limit", c.maxResponseBytes),
		}
	}
	page, err := decodeGraylogPage(responseBody)
	if err != nil {
		return graylogPage{}, &graylogAttemptError{err: err}
	}
	if page.rows > pageSize {
		return graylogPage{}, &graylogAttemptError{
			err: fmt.Errorf("graylog returned %d rows for a page size of %d", page.rows, pageSize),
		}
	}
	return page, nil
}

func graylogStatusRetryable(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooManyRequests ||
		(status >= http.StatusInternalServerError && status <= 599)
}

func (c *graylogClient) retryDelay(attempt int, retryAfter time.Duration) time.Duration {
	delay := c.retryBase
	if delay <= 0 {
		delay = graylogRetryBase
	}
	for range min(max(attempt, 0), 16) {
		delay *= 2
	}
	maximum := c.retryMax
	if maximum <= 0 {
		maximum = graylogRetryMax
	}
	if delay > maximum {
		delay = maximum
	}
	if c.retryJitter != nil {
		delay += max(c.retryJitter(delay/5), 0)
	}
	if retryAfter > delay {
		delay = retryAfter
	}
	return min(delay, maximum)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func composeGraylogQuery(baseQuery string, sourceAliases []string) (string, error) {
	baseQuery = strings.TrimSpace(baseQuery)
	if baseQuery == "" {
		return "", errors.New("graylog base query is required")
	}
	if len(baseQuery) > graylogMaxQuerySize {
		return "", fmt.Errorf("graylog base query exceeds %d-byte limit", graylogMaxQuerySize)
	}
	if len(sourceAliases) > graylogMaxSourceAliases {
		return "", fmt.Errorf("graylog source aliases exceed the %d-entry limit", graylogMaxSourceAliases)
	}

	unique := make(map[string]struct{}, len(sourceAliases))
	aliases := make([]string, 0, len(sourceAliases))
	for _, source := range sourceAliases {
		source = strings.TrimSpace(source)
		if source == "" {
			return "", errors.New("graylog source alias must not be blank")
		}
		if len(source) > graylogMaxSourceAliasSize {
			return "", fmt.Errorf("graylog source alias exceeds %d-byte limit", graylogMaxSourceAliasSize)
		}
		for _, r := range source {
			if unicode.IsControl(r) {
				return "", errors.New("graylog source alias contains a control character")
			}
		}
		if _, exists := unique[source]; exists {
			continue
		}
		unique[source] = struct{}{}
		aliases = append(aliases, source)
	}
	if len(aliases) == 0 {
		return baseQuery, nil
	}

	sort.Strings(aliases)
	clauses := make([]string, 0, len(aliases))
	for _, source := range aliases {
		clauses = append(clauses, `source:"`+escapeGraylogQueryValue(source)+`"`)
	}
	query := "(" + baseQuery + ") AND (" + strings.Join(clauses, " OR ") + ")"
	if len(query) > graylogMaxQuerySize {
		return "", fmt.Errorf("composed graylog query exceeds %d-byte limit", graylogMaxQuerySize)
	}
	return query, nil
}

func escapeGraylogQueryValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func decodeGraylogPage(body []byte) (graylogPage, error) {
	var response struct {
		Schema   *[]graylogColumn `json:"schema"`
		Datarows *[][]any         `json:"datarows"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return graylogPage{}, fmt.Errorf("decode graylog response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return graylogPage{}, errors.New("decode graylog response: trailing JSON value")
		}
		return graylogPage{}, fmt.Errorf("decode graylog response trailing data: %w", err)
	}
	if response.Schema == nil || len(*response.Schema) == 0 {
		return graylogPage{}, errors.New("decode graylog response: schema is missing or empty")
	}
	if response.Datarows == nil {
		return graylogPage{}, errors.New("decode graylog response: datarows are missing or null")
	}

	schema := *response.Schema
	indexes := make(map[string]int, len(schema))
	for i, column := range schema {
		if column.ColumnType != "field" || column.Field == "" {
			return graylogPage{}, fmt.Errorf("decode graylog response: invalid schema column %d", i)
		}
		if _, duplicate := indexes[column.Field]; duplicate {
			return graylogPage{}, errors.New("decode graylog response: duplicate schema field")
		}
		indexes[column.Field] = i
	}
	for _, field := range graylogSelectedFields {
		if _, exists := indexes[field]; !exists {
			return graylogPage{}, fmt.Errorf("decode graylog response: schema missing requested field %q", field)
		}
	}

	rows := *response.Datarows
	events := make([]RawEvent, 0, len(rows))
	quarantined := 0
	for _, row := range rows {
		if len(row) != len(schema) {
			quarantined++
			continue
		}
		event, err := rawEventFromRow(row, indexes)
		if err != nil {
			quarantined++
			continue
		}
		events = append(events, event)
	}
	return graylogPage{
		events:      events,
		rows:        len(rows),
		quarantined: quarantined,
	}, nil
}

func rawEventFromRow(row []any, indexes map[string]int) (RawEvent, error) {
	timestampText, err := requiredString(row[indexes["timestamp"]], "timestamp")
	if err != nil {
		return RawEvent{}, err
	}
	timestamp, err := time.Parse(time.RFC3339Nano, timestampText)
	if err != nil {
		return RawEvent{}, errors.New("timestamp is not RFC3339")
	}
	messageID, err := requiredString(row[indexes["gl2_message_id"]], "gl2_message_id")
	if err != nil {
		return RawEvent{}, err
	}
	eventTime, err := graylogEventTime(row[indexes["eventtime"]])
	if err != nil {
		return RawEvent{}, err
	}

	logID, err := graylogLogID(row[indexes["logid"]])
	if err != nil {
		return RawEvent{}, fmt.Errorf("field logid: %w", err)
	}

	values := make(map[string]string, len(graylogSelectedFields))
	for _, field := range graylogSelectedFields[3:] {
		if field == "logid" {
			continue
		}
		value, err := graylogScalarString(row[indexes[field]])
		if err != nil {
			return RawEvent{}, fmt.Errorf("field %s: %w", field, err)
		}
		values[field] = value
	}
	return RawEvent{
		Timestamp:           timestamp.UTC(),
		MessageID:           messageID,
		EventTime:           eventTime,
		Type:                values["type"],
		Subtype:             values["subtype"],
		Source:              values["source"],
		DeviceName:          values["devname"],
		DeviceID:            values["devid"],
		VDOM:                values["vd"],
		User:                values["user"],
		UI:                  values["ui"],
		Action:              values["action"],
		ConfigTransactionID: values["cfgtid"],
		ConfigPath:          values["cfgpath"],
		ConfigObject:        values["cfgobj"],
		ConfigAttribute:     values["cfgattr"],
		LogID:               logID,
		LogDescription:      values["logdesc"],
		Message:             values["msg"],
		UUID:                values["uuid"],
	}, nil
}

func requiredString(value any, field string) (string, error) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("field %s must be a non-empty string", field)
	}
	return text, nil
}

func graylogEventTime(value any) (json.Number, error) {
	if value == nil {
		return "", nil
	}
	var text string
	switch value := value.(type) {
	case json.Number:
		text = value.String()
	case string:
		text = strings.TrimSpace(value)
	default:
		return "", fmt.Errorf("field eventtime must be an integer, got %T", value)
	}
	if text == "" || text == "-" {
		return "", nil
	}
	integer, err := normalizeDecimalInteger(text)
	if err != nil {
		return "", fmt.Errorf("field eventtime must be a non-negative integer: %w", err)
	}
	return json.Number(integer), nil
}

func graylogLogID(value any) (string, error) {
	if value == nil {
		return "", nil
	}
	var text string
	switch value := value.(type) {
	case json.Number:
		text = value.String()
	case string:
		text = strings.TrimSpace(value)
	default:
		return "", fmt.Errorf("must be an integer, got %T", value)
	}
	if text == "" {
		return "", nil
	}

	integer, err := normalizeDecimalInteger(text)
	if err != nil {
		return "", fmt.Errorf("must be a non-negative integer: %w", err)
	}
	switch len(integer) {
	case graylogCanonicalLogIDSize - 1:
		return "0" + integer, nil
	case graylogCanonicalLogIDSize:
		return integer, nil
	default:
		return "", fmt.Errorf("must contain %d decimal digits", graylogCanonicalLogIDSize)
	}
}

func normalizeDecimalInteger(text string) (string, error) {
	if len(text) > graylogMaxEventTimeDigits {
		return "", errors.New("numeric representation is too long")
	}
	exponentAt := strings.IndexAny(text, "eE")
	mantissa := text
	if exponentAt >= 0 {
		if strings.ContainsAny(text[exponentAt+1:], "eE") {
			return "", errors.New("invalid decimal number")
		}
		mantissa = text[:exponentAt]
		exponent, err := strconv.ParseInt(text[exponentAt+1:], 10, 32)
		if err != nil || exponent < -graylogMaxEventTimeDigits || exponent > graylogMaxEventTimeDigits {
			return "", errors.New("invalid decimal exponent")
		}
	}
	if strings.HasPrefix(mantissa, "-") {
		return "", errors.New("negative value")
	}
	mantissa = strings.TrimPrefix(mantissa, "+")
	digits := 0
	dots := 0
	for _, r := range mantissa {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		default:
			return "", errors.New("invalid decimal number")
		}
	}
	if digits == 0 || dots > 1 {
		return "", errors.New("invalid decimal number")
	}

	var number big.Rat
	if _, ok := number.SetString(text); !ok {
		return "", errors.New("invalid decimal number")
	}
	if number.Sign() < 0 {
		return "", errors.New("negative value")
	}
	if !number.IsInt() {
		return "", errors.New("fractional value")
	}
	integer := number.Num().String()
	if len(integer) > graylogMaxEventTimeDigits {
		return "", errors.New("integer value is too long")
	}
	return integer, nil
}

func graylogScalarString(value any) (string, error) {
	switch value := value.(type) {
	case nil:
		return "", nil
	case string:
		if strings.TrimSpace(value) == "-" {
			return "", nil
		}
		return value, nil
	case json.Number:
		return value.String(), nil
	case bool:
		return strconv.FormatBool(value), nil
	default:
		return "", fmt.Errorf("expected a scalar value, got %T", value)
	}
}

func sortRawEvents(events []RawEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].MessageID < events[j].MessageID
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
}
