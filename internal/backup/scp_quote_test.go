package backup

import "testing"

// TestQuotePOSIXShell covers metacharacters and embedded single quotes.
func TestQuotePOSIXShell(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"/var/config":             "'/var/config'",
		"/var/config; reboot":     "'/var/config; reboot'",
		"/path/it's configured":   "'/path/it'\"'\"'s configured'",
		"$(touch /tmp/injection)": "'$(touch /tmp/injection)'",
	}
	for input, want := range tests {
		if got := quotePOSIXShell(input); got != want {
			t.Errorf("quotePOSIXShell(%q) = %q, want %q", input, got, want)
		}
	}
}
