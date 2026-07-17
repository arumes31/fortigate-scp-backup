package fgt_confgen

import (
	"strings"
	"testing"
)

// TestIsValidTemplateName: the validator must keep accepting legacy names
// (anything without URL delimiters, header-breaking quotes or control
// characters — including spaces and non-ASCII), and reject only the
// characters that would break the URL path, short-URL matching or the
// Content-Disposition header.
func TestIsValidTemplateName(t *testing.T) {
	valid := []string{
		"basic",
		"with.dots-and_underscores",
		"branch office",    // legacy: spaces were always accepted
		"Zweigstelle Büro", // legacy: non-ASCII letters
		"テンプレート",           // non-Latin scripts
		"a (v2) [prod]!",
		strings.Repeat("x", 128), // exactly at the length cap
	}
	for _, name := range valid {
		if !isValidTemplateName(name) {
			t.Errorf("isValidTemplateName(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("x", 129), // over the length cap
		"a/b",                    // path delimiter
		"a?b",                    // query delimiter
		"a#b",                    // fragment delimiter
		"a%20b",                  // escape injection into stored URLs
		`a"b`,                    // breaks quoted Content-Disposition
		`a\b`,                    // escape in Content-Disposition
		"a\x00b",                 // control character
		"a\nb",                   // control character
		"a\x7fb",                 // DEL
	}
	for _, name := range invalid {
		if isValidTemplateName(name) {
			t.Errorf("isValidTemplateName(%q) = true, want false", name)
		}
	}
}
