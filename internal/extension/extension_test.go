package extension

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

func TestDepsAcceptsTypedPageBaseStub(t *testing.T) {
	t.Parallel()

	var gotTitle, gotActive string
	deps := Deps{
		PageBase: func(_ *http.Request, title, active string) webui.BaseData {
			gotTitle = title
			gotActive = active
			return webui.BaseData{Title: title, Username: "fixture-reviewer"}
		},
	}

	base := deps.PageBase(httptest.NewRequest(http.MethodGet, "/fixture", nil), "Fixture", "audit")
	if gotTitle != "Fixture" || gotActive != "audit" {
		t.Fatalf("PageBase arguments = (%q, %q), want (%q, %q)", gotTitle, gotActive, "Fixture", "audit")
	}
	if base.Username != "fixture-reviewer" {
		t.Fatalf("PageBase username = %q, want fixture-reviewer", base.Username)
	}
}
