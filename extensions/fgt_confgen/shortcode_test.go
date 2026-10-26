package fgt_confgen

import "testing"

// TestRandHexShortCodesAreLongAndUnique checks the 64-bit short-code space.
func TestRandHexShortCodesAreLongAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		code := randHex(shortCodeLength)
		if len(code) != 16 {
			t.Fatalf("short code %q has length %d, want 16", code, len(code))
		}
		if seen[code] {
			t.Fatalf("duplicate short code %q", code)
		}
		seen[code] = true
	}
	if got := randHex(6); len(got) != 6 {
		t.Fatalf("randHex(6) length = %d", len(got))
	}
}
