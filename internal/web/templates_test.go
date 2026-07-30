package web

import "testing"

// TestParseTemplates proves every embedded template parses with the real
// funcMap — a malformed action would otherwise only surface at server start.
func TestParseTemplates(t *testing.T) {
	s := &Server{}
	if err := s.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	if len(s.pages) == 0 {
		t.Fatal("no templates parsed")
	}
	for _, name := range []string{"licenses.html", "ipam.html", "dashboard.html"} {
		if _, ok := s.pages[name]; !ok {
			t.Errorf("expected template %s missing", name)
		}
	}
}
