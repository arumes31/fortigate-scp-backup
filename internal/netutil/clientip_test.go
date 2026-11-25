package netutil

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPUsesLastXForwardedForLine(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Add("X-Forwarded-For", "203.0.113.9, 203.0.113.10")
	r.Header.Add("X-Forwarded-For", "198.51.100.1, 198.51.100.7")
	if got := ClientIP(r, true); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want 198.51.100.7", got)
	}
}
