package fgtconftail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHookwiseHTTPTimeout      = 10 * time.Second
	defaultHookwiseMaxResponseBytes = 64 << 10
	maxHookwiseCorrelationIDBytes   = 512
	maxHookwiseRequestIDBytes       = 512
	maxHookwiseTokenBytes           = 4_096
)

var errHookwiseResponseTooLarge = errors.New("hookwise response exceeds size limit")

type hookwiseErrorKind uint8

const (
	hookwiseErrorRequest hookwiseErrorKind = iota + 1
	hookwiseErrorCanceled
	hookwiseErrorTimeout
	hookwiseErrorNetwork
	hookwiseErrorRateLimited
	hookwiseErrorServer
	hookwiseErrorRejected
	hookwiseErrorProtocol
)

// hookwiseError contains only bounded classification data. In particular, it
// never retains the Bearer token, payload, endpoint, or untrusted response body.
type hookwiseError struct {
	Kind       hookwiseErrorKind
	StatusCode int
	RetryAfter time.Duration
	cause      error
}

func (e *hookwiseError) Error() string {
	switch e.Kind {
	case hookwiseErrorRequest:
		return "hookwise request is invalid"
	case hookwiseErrorCanceled:
		return "hookwise request was canceled"
	case hookwiseErrorTimeout:
		return "hookwise request timed out"
	case hookwiseErrorNetwork:
		return "hookwise network request failed"
	case hookwiseErrorRateLimited:
		return fmt.Sprintf("hookwise request was rate limited with http status %d", e.StatusCode)
	case hookwiseErrorServer:
		return fmt.Sprintf("hookwise server returned http status %d", e.StatusCode)
	case hookwiseErrorRejected:
		return fmt.Sprintf("hookwise request was rejected with http status %d", e.StatusCode)
	default:
		if e.StatusCode != 0 {
			return fmt.Sprintf("hookwise returned an invalid response with http status %d", e.StatusCode)
		}
		return "hookwise returned an invalid response"
	}
}

func (e *hookwiseError) Unwrap() error {
	return e.cause
}

// IsTransient reports whether retrying the identical frozen request may
// succeed without an operator correcting configuration or the API contract.
func (e *hookwiseError) IsTransient() bool {
	switch e.Kind {
	case hookwiseErrorTimeout,
		hookwiseErrorNetwork,
		hookwiseErrorRateLimited,
		hookwiseErrorServer:
		return true
	default:
		return false
	}
}

type hookwiseClient struct {
	endpoint         string
	token            string
	httpClient       *http.Client
	maxResponseBytes int64
	now              func() time.Time
}

type hookwiseAcceptedResponse struct {
	Status    string `json:"status"`
	RequestID string `json:"request_id"`
}

func newHookwiseClient(
	endpoint string,
	token string,
	httpClient *http.Client,
) (*hookwiseClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || !validHookwiseEndpoint(parsed) {
		return nil, errors.New("hookwise endpoint is invalid")
	}
	if !validBearerToken(token) {
		return nil, errors.New("hookwise token is invalid")
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHookwiseHTTPTimeout}
	}
	clientCopy := *httpClient
	// A redirect can change POST semantics or move credentials to an unintended
	// endpoint. The configured dedicated endpoint is the only accepted target.
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &hookwiseClient{
		endpoint:         parsed.String(),
		token:            token,
		httpClient:       &clientCopy,
		maxResponseBytes: defaultHookwiseMaxResponseBytes,
		now:              time.Now,
	}, nil
}

func (c *hookwiseClient) send(
	ctx context.Context,
	correlationID string,
	frozenPayload []byte,
) (string, error) {
	if ctx == nil || !validHeaderValue(correlationID, maxHookwiseCorrelationIDBytes) || len(frozenPayload) == 0 {
		return "", &hookwiseError{Kind: hookwiseErrorRequest}
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpoint,
		bytes.NewReader(frozenPayload),
	)
	if err != nil {
		return "", &hookwiseError{Kind: hookwiseErrorRequest}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Correlation-ID", correlationID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return "", classifyHookwiseTransportError(ctx, err)
	}
	if resp.Body == nil {
		return "", &hookwiseError{
			Kind:       hookwiseErrorProtocol,
			StatusCode: resp.StatusCode,
		}
	}

	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
	body, bodyErr := readBoundedHookwiseResponse(resp.Body, c.maxResponseBytes)
	if resp.StatusCode != http.StatusAccepted {
		// The status is authoritative for retry classification. Response bodies
		// are deliberately ignored even when reading them fails.
		return "", classifyHookwiseStatus(resp.StatusCode, retryAfter)
	}
	if bodyErr != nil {
		if errors.Is(bodyErr, errHookwiseResponseTooLarge) {
			return "", &hookwiseError{
				Kind:       hookwiseErrorProtocol,
				StatusCode: resp.StatusCode,
			}
		}
		return "", &hookwiseError{
			Kind:       hookwiseErrorNetwork,
			StatusCode: resp.StatusCode,
		}
	}

	var accepted hookwiseAcceptedResponse
	if err := json.Unmarshal(body, &accepted); err != nil {
		return "", &hookwiseError{
			Kind:       hookwiseErrorProtocol,
			StatusCode: resp.StatusCode,
		}
	}
	requestID := strings.TrimSpace(accepted.RequestID)
	validAcceptedResponse := accepted.Status == "queued" &&
		validOpaqueID(requestID, maxHookwiseRequestIDBytes)
	if !validAcceptedResponse {
		return "", &hookwiseError{
			Kind:       hookwiseErrorProtocol,
			StatusCode: resp.StatusCode,
		}
	}
	return requestID, nil
}

func validHookwiseEndpoint(endpoint *url.URL) bool {
	if endpoint == nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" ||
		endpoint.RawQuery != "" || endpoint.RawPath != "" || endpoint.Opaque != "" {
		return false
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return false
	}
	const prefix = "/w/"
	if !strings.HasPrefix(endpoint.Path, prefix) {
		return false
	}
	endpointID := strings.TrimPrefix(endpoint.Path, prefix)
	if endpointID == "" || len(endpointID) > maxHookwiseCorrelationIDBytes {
		return false
	}
	for _, r := range endpointID {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func validHeaderValue(value string, maxBytes int) bool {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return false
	}
	return maxBytes <= 0 || len(value) <= maxBytes
}

func validBearerToken(value string) bool {
	if value == "" || len(value) > maxHookwiseTokenBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validOpaqueID(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func classifyHookwiseTransportError(ctx context.Context, err error) *hookwiseError {
	if cause := ctx.Err(); cause != nil {
		if errors.Is(cause, context.Canceled) {
			return &hookwiseError{Kind: hookwiseErrorCanceled, cause: context.Canceled}
		}
		return &hookwiseError{Kind: hookwiseErrorTimeout, cause: context.DeadlineExceeded}
	}
	if errors.Is(err, context.Canceled) {
		return &hookwiseError{Kind: hookwiseErrorCanceled, cause: context.Canceled}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &hookwiseError{Kind: hookwiseErrorTimeout, cause: context.DeadlineExceeded}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &hookwiseError{Kind: hookwiseErrorTimeout}
	}
	return &hookwiseError{Kind: hookwiseErrorNetwork}
}

func classifyHookwiseStatus(status int, retryAfter time.Duration) *hookwiseError {
	err := &hookwiseError{
		StatusCode: status,
		RetryAfter: retryAfter,
	}
	switch {
	case status == http.StatusRequestTimeout:
		err.Kind = hookwiseErrorTimeout
	case status == http.StatusTooManyRequests:
		err.Kind = hookwiseErrorRateLimited
	case status >= 500 && status <= 599:
		err.Kind = hookwiseErrorServer
	case status >= 400 && status <= 499:
		err.Kind = hookwiseErrorRejected
	default:
		err.Kind = hookwiseErrorProtocol
	}
	return err
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		maxSeconds := int64(^uint64(0)>>1) / int64(time.Second)
		if seconds < 0 || seconds > maxSeconds {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	delay := retryAt.Sub(now)
	if delay < 0 {
		return 0
	}
	return delay
}

func readBoundedHookwiseResponse(body io.ReadCloser, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 {
		maxBytes = defaultHookwiseMaxResponseBytes
	}
	data, readErr := io.ReadAll(io.LimitReader(body, maxBytes+1))
	_ = body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(data)) > maxBytes {
		return nil, errHookwiseResponseTooLarge
	}
	return data, nil
}
