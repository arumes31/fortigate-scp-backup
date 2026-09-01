package fgtconftail

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHookwiseClientRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		token    string
	}{
		{name: "empty endpoint", endpoint: "", token: "token"},
		{name: "relative endpoint", endpoint: "/w/endpoint", token: "token"},
		{name: "unsupported endpoint scheme", endpoint: "ftp://hookwise.example/w/endpoint", token: "token"},
		{name: "endpoint without host", endpoint: "https:///w/endpoint", token: "token"},
		{name: "endpoint with credentials", endpoint: "https://unsafe:secret@hookwise.example/w/endpoint", token: "token"},
		{name: "endpoint with fragment", endpoint: "https://hookwise.example/w/endpoint#unsafe", token: "token"},
		{name: "endpoint without webhook path", endpoint: "https://hookwise.example/api", token: "token"},
		{name: "endpoint without webhook id", endpoint: "https://hookwise.example/w/", token: "token"},
		{name: "endpoint with extra path", endpoint: "https://hookwise.example/w/endpoint/extra", token: "token"},
		{name: "endpoint with query", endpoint: "https://hookwise.example/w/endpoint?unsafe=true", token: "token"},
		{name: "endpoint with encoded id", endpoint: "https://hookwise.example/w/end%70oint", token: "token"},
		{name: "empty token", endpoint: "https://hookwise.example/w/endpoint", token: ""},
		{name: "unsafe token", endpoint: "https://hookwise.example/w/endpoint", token: "secret\r\nX-Unsafe: true"},
		{name: "token with space", endpoint: "https://hookwise.example/w/endpoint", token: "secret value"},
		{name: "token with tab", endpoint: "https://hookwise.example/w/endpoint", token: "secret\tvalue"},
		{name: "token with nul", endpoint: "https://hookwise.example/w/endpoint", token: "secret\x00value"},
		{name: "token with del", endpoint: "https://hookwise.example/w/endpoint", token: "secret\x7fvalue"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := newHookwiseClient(tt.endpoint, tt.token, nil)
			if err == nil {
				t.Fatalf("newHookwiseClient() = %#v, nil; want an error", client)
			}
			for _, unsafe := range []string{tt.endpoint, tt.token, "unsafe", "secret"} {
				if unsafe != "" && strings.Contains(err.Error(), unsafe) {
					t.Fatalf("error %q exposes configuration value %q", err, unsafe)
				}
			}
		})
	}
}

func TestHookwiseClientSendPostsFrozenPayload(t *testing.T) {
	type capturedRequest struct {
		method        string
		path          string
		authorization string
		contentType   string
		accept        string
		correlationID string
		body          string
		readErr       error
	}

	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		requests <- capturedRequest{
			method:        r.Method,
			path:          r.URL.EscapedPath(),
			authorization: r.Header.Get("Authorization"),
			contentType:   r.Header.Get("Content-Type"),
			accept:        r.Header.Get("Accept"),
			correlationID: r.Header.Get("X-Correlation-ID"),
			body:          string(body),
			readErr:       err,
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"status":"queued","request_id":"request-123","future_field":true}`)
	}))
	defer server.Close()

	const token = "hookwise-token"
	const correlationID = "5b654f85-1fb3-4be2-b378-bc74f274ace0"
	frozenPayload := []byte("{\n  \"status\": \"OPEN\",\n  \"description\": \"frozen bytes\"\n}")
	client := mustNewHookwiseClient(t, server.URL+"/w/endpoint-id", token, server.Client())

	requestID, err := client.send(t.Context(), correlationID, frozenPayload)
	if err != nil {
		t.Fatalf("send() error = %v", err)
	}
	if requestID != "request-123" {
		t.Fatalf("send() request id = %q, want %q", requestID, "request-123")
	}

	got := <-requests
	if got.readErr != nil {
		t.Fatalf("reading request body: %v", got.readErr)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if got.path != "/w/endpoint-id" {
		t.Errorf("path = %q, want /w/endpoint-id", got.path)
	}
	if got.authorization != "Bearer "+token {
		t.Errorf("Authorization = %q, want Bearer token", got.authorization)
	}
	if got.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got.contentType)
	}
	if got.accept != "application/json" {
		t.Errorf("Accept = %q, want application/json", got.accept)
	}
	if got.correlationID != correlationID {
		t.Errorf("X-Correlation-ID = %q, want %q", got.correlationID, correlationID)
	}
	if got.body != string(frozenPayload) {
		t.Errorf("body changed:\n got %q\nwant %q", got.body, frozenPayload)
	}
}

func TestHookwiseClientSendRejectsInvalidAcceptedResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing fields", body: `{}`},
		{name: "missing status", body: `{"request_id":"request-123"}`},
		{name: "wrong status", body: `{"status":"accepted","request_id":"request-123"}`},
		{name: "status has wrong case", body: `{"status":"QUEUED","request_id":"request-123"}`},
		{name: "missing request id", body: `{"status":"queued"}`},
		{name: "empty request id", body: `{"status":"queued","request_id":""}`},
		{name: "blank request id", body: `{"status":"queued","request_id":"  "}`},
		{name: "null response", body: `null`},
		{name: "array response", body: `[]`},
		{name: "request id has wrong type", body: `{"status":"queued","request_id":123}`},
		{name: "status has wrong type", body: `{"status":true,"request_id":"request-123"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := hookwiseResponseServer(http.StatusAccepted, "", tt.body)
			defer server.Close()
			client := mustNewHookwiseClient(t, server.URL+"/w/endpoint", "token", server.Client())

			requestID, err := client.send(t.Context(), "chain-id", []byte(`{"status":"OPEN"}`))
			if err == nil {
				t.Fatalf("send() = %q, nil; want an error", requestID)
			}
			hookErr := requireHookwiseError(t, err)
			if hookErr.Kind != hookwiseErrorProtocol {
				t.Errorf("error kind = %v, want protocol", hookErr.Kind)
			}
			if hookErr.StatusCode != http.StatusAccepted {
				t.Errorf("status code = %d, want 202", hookErr.StatusCode)
			}
			if hookErr.IsTransient() {
				t.Error("invalid accepted response classified as transient")
			}
			if strings.Contains(err.Error(), tt.body) || strings.Contains(err.Error(), "request-123") {
				t.Fatalf("error %q exposes response body", err)
			}
		})
	}
}

func TestHookwiseClientSendClassifiesHTTPStatus(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		kind      hookwiseErrorKind
		transient bool
	}{
		{name: "request timeout", status: http.StatusRequestTimeout, kind: hookwiseErrorTimeout, transient: true},
		{name: "rate limited", status: http.StatusTooManyRequests, kind: hookwiseErrorRateLimited, transient: true},
		{name: "internal server error", status: http.StatusInternalServerError, kind: hookwiseErrorServer, transient: true},
		{name: "service unavailable", status: http.StatusServiceUnavailable, kind: hookwiseErrorServer, transient: true},
		{name: "upper server error boundary", status: 599, kind: hookwiseErrorServer, transient: true},
		{name: "bad request", status: http.StatusBadRequest, kind: hookwiseErrorRejected, transient: false},
		{name: "unauthorized", status: http.StatusUnauthorized, kind: hookwiseErrorRejected, transient: false},
		{name: "not found", status: http.StatusNotFound, kind: hookwiseErrorRejected, transient: false},
		{name: "unprocessable entity", status: http.StatusUnprocessableEntity, kind: hookwiseErrorRejected, transient: false},
		{name: "unexpected success", status: http.StatusOK, kind: hookwiseErrorProtocol, transient: false},
		{name: "redirect", status: http.StatusTemporaryRedirect, kind: hookwiseErrorProtocol, transient: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := hookwiseResponseServer(tt.status, "", `unsafe response body with secret material`)
			defer server.Close()
			client := mustNewHookwiseClient(t, server.URL+"/w/endpoint", "token", server.Client())

			_, err := client.send(t.Context(), "chain-id", []byte(`{"description":"private payload"}`))
			if err == nil {
				t.Fatal("send() error = nil")
			}
			hookErr := requireHookwiseError(t, err)
			if hookErr.Kind != tt.kind {
				t.Errorf("error kind = %v, want %v", hookErr.Kind, tt.kind)
			}
			if hookErr.StatusCode != tt.status {
				t.Errorf("status code = %d, want %d", hookErr.StatusCode, tt.status)
			}
			if hookErr.IsTransient() != tt.transient {
				t.Errorf("IsTransient() = %t, want %t", hookErr.IsTransient(), tt.transient)
			}
			for _, unsafe := range []string{"unsafe response body", "secret material", "private payload"} {
				if strings.Contains(err.Error(), unsafe) {
					t.Fatalf("error %q exposes %q", err, unsafe)
				}
			}
		})
	}
}

func TestHookwiseClientSendParsesRetryAfter(t *testing.T) {
	fixedNow := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		header     string
		retryAfter time.Duration
	}{
		{name: "delta seconds", header: "120", retryAfter: 2 * time.Minute},
		{name: "http date", header: fixedNow.Add(90 * time.Second).Format(http.TimeFormat), retryAfter: 90 * time.Second},
		{name: "past http date", header: fixedNow.Add(-time.Minute).Format(http.TimeFormat), retryAfter: 0},
		{name: "invalid value", header: "unsafe retry value", retryAfter: 0},
		{name: "negative delta", header: "-1", retryAfter: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := hookwiseResponseServer(http.StatusTooManyRequests, tt.header, "ignored")
			defer server.Close()
			client := mustNewHookwiseClient(t, server.URL+"/w/endpoint", "token", server.Client())
			client.now = func() time.Time { return fixedNow }

			_, err := client.send(t.Context(), "chain-id", []byte(`{"status":"OPEN"}`))
			hookErr := requireHookwiseError(t, err)
			if hookErr.RetryAfter != tt.retryAfter {
				t.Errorf("RetryAfter = %v, want %v", hookErr.RetryAfter, tt.retryAfter)
			}
			if strings.Contains(err.Error(), tt.header) {
				t.Fatalf("error %q exposes Retry-After input %q", err, tt.header)
			}
		})
	}
}

func TestHookwiseClientSendRejectsOversizedResponse(t *testing.T) {
	const unsafeBody = "response-secret-that-must-not-appear"
	server := hookwiseResponseServer(http.StatusAccepted, "", strings.Repeat(unsafeBody, 8))
	defer server.Close()
	client := mustNewHookwiseClient(t, server.URL+"/w/endpoint", "token", server.Client())
	client.maxResponseBytes = 64

	_, err := client.send(t.Context(), "chain-id", []byte(`{"status":"OPEN"}`))
	hookErr := requireHookwiseError(t, err)
	if hookErr.Kind != hookwiseErrorProtocol || hookErr.StatusCode != http.StatusAccepted {
		t.Fatalf("error = %+v, want 202 protocol error", hookErr)
	}
	if hookErr.IsTransient() {
		t.Error("oversized response classified as transient")
	}
	if strings.Contains(err.Error(), unsafeBody) {
		t.Fatalf("error %q exposes oversized response", err)
	}
}

func TestHookwiseClientSendRejectsMalformedResponse(t *testing.T) {
	const unsafeBody = `{not-json:"response-secret"}`
	server := hookwiseResponseServer(http.StatusAccepted, "", unsafeBody)
	defer server.Close()
	client := mustNewHookwiseClient(t, server.URL+"/w/endpoint", "token", server.Client())

	_, err := client.send(t.Context(), "chain-id", []byte(`{"status":"OPEN"}`))
	hookErr := requireHookwiseError(t, err)
	if hookErr.Kind != hookwiseErrorProtocol || hookErr.StatusCode != http.StatusAccepted {
		t.Fatalf("error = %+v, want 202 protocol error", hookErr)
	}
	if strings.Contains(err.Error(), unsafeBody) || strings.Contains(err.Error(), "response-secret") {
		t.Fatalf("error %q exposes malformed response", err)
	}
}

func TestHookwiseClientSendHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{})
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	client := mustNewHookwiseClient(
		t,
		"https://hookwise.example/w/endpoint",
		"cancel-secret-token",
		&http.Client{Transport: transport},
	)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := client.send(ctx, "chain-id", []byte(`{"description":"cancel-secret-payload"}`))
		result <- err
	}()

	<-started
	cancel()
	err := <-result
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("send() error = %v, want context.Canceled", err)
	}
	hookErr := requireHookwiseError(t, err)
	if hookErr.Kind != hookwiseErrorCanceled {
		t.Errorf("error kind = %v, want canceled", hookErr.Kind)
	}
	if hookErr.IsTransient() {
		t.Error("caller cancellation classified as transient delivery failure")
	}
	for _, unsafe := range []string{"cancel-secret-token", "cancel-secret-payload"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("error %q exposes %q", err, unsafe)
		}
	}
}

func TestHookwiseClientSendClassifiesTransportFailures(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		kind  hookwiseErrorKind
		cause error
	}{
		{
			name: "network failure",
			err:  errors.New("network-secret-token private-payload response-body"),
			kind: hookwiseErrorNetwork,
		},
		{
			name: "transport timeout",
			err:  testTimeoutError("timeout-secret-token private-payload response-body"),
			kind: hookwiseErrorTimeout,
		},
		{
			name:  "context deadline",
			err:   context.DeadlineExceeded,
			kind:  hookwiseErrorTimeout,
			cause: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, tt.err
			})
			client := mustNewHookwiseClient(
				t,
				"https://hookwise.example/w/endpoint",
				"network-secret-token",
				&http.Client{Transport: transport},
			)

			_, err := client.send(t.Context(), "chain-id", []byte(`{"description":"private-payload"}`))
			hookErr := requireHookwiseError(t, err)
			if hookErr.Kind != tt.kind {
				t.Errorf("error kind = %v, want %v", hookErr.Kind, tt.kind)
			}
			if !hookErr.IsTransient() {
				t.Error("transport failure classified as persistent")
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Errorf("error %v does not wrap %v", err, tt.cause)
			}
			for _, unsafe := range []string{"secret-token", "private-payload", "response-body"} {
				if strings.Contains(err.Error(), unsafe) {
					t.Fatalf("error %q exposes %q", err, unsafe)
				}
			}
		})
	}
}

func TestHookwiseClientSendRejectsUnsafeRequestMetadata(t *testing.T) {
	client := mustNewHookwiseClient(
		t,
		"https://hookwise.example/w/endpoint",
		"token",
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("transport called for invalid request metadata")
			return nil, nil
		})},
	)

	tests := []struct {
		name          string
		correlationID string
		payload       []byte
	}{
		{name: "empty correlation id", correlationID: "", payload: []byte(`{}`)},
		{name: "unsafe correlation id", correlationID: "chain\r\nX-Unsafe: true", payload: []byte(`{}`)},
		{name: "empty payload", correlationID: "chain-id", payload: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.send(t.Context(), tt.correlationID, tt.payload)
			hookErr := requireHookwiseError(t, err)
			if hookErr.Kind != hookwiseErrorRequest || hookErr.IsTransient() {
				t.Fatalf("error = %+v, want persistent request error", hookErr)
			}
			if tt.correlationID != "" && strings.Contains(err.Error(), tt.correlationID) {
				t.Fatalf("error %q exposes correlation id", err)
			}
		})
	}
}

func mustNewHookwiseClient(
	t *testing.T,
	endpoint string,
	token string,
	httpClient *http.Client,
) *hookwiseClient {
	t.Helper()
	client, err := newHookwiseClient(endpoint, token, httpClient)
	if err != nil {
		t.Fatalf("newHookwiseClient() error = %v", err)
	}
	return client
}

func requireHookwiseError(t *testing.T, err error) *hookwiseError {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want *hookwiseError")
	}
	var hookErr *hookwiseError
	if !errors.As(err, &hookErr) {
		t.Fatalf("error type = %T, want *hookwiseError", err)
	}
	return hookErr
}

func hookwiseResponseServer(status int, retryAfter string, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type testTimeoutError string

func (e testTimeoutError) Error() string   { return string(e) }
func (e testTimeoutError) Timeout() bool   { return true }
func (e testTimeoutError) Temporary() bool { return true }
