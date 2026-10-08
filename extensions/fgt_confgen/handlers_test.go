package fgt_confgen

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/extension"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

func performConfGenJSONRequest(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	return recorder
}

func decodeConfGenResponse[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var response T
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v; body=%q", err, recorder.Body.String())
	}
	return response
}

func TestValidatePolicyReturnsStableErrorsAndWarnings(t *testing.T) {
	e := &Extension{logger: slog.New(slog.DiscardHandler)}
	valid := minimalPolicy()
	valid.Services = []Service{{Type: "template", Name: "HTTPS"}}
	recorder := performConfGenJSONRequest(t, e.validatePolicies, policyRequest{Policies: []Policy{valid}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
	}
	response := decodeConfGenResponse[validationResponse](t, recorder)
	if !response.Valid || len(response.Errors) != 0 {
		t.Fatalf("valid response = %+v", response)
	}
	if len(response.Warnings) != 1 || response.Warnings[0].Code != "policy_comment_empty" {
		t.Fatalf("warnings = %+v, want policy_comment_empty", response.Warnings)
	}

	invalid := minimalPolicy()
	invalid.Action = "not-an-action"
	recorder = performConfGenJSONRequest(t, e.validatePolicies, policyRequest{Policies: []Policy{invalid}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("invalid validation status = %d, want 200", recorder.Code)
	}
	response = decodeConfGenResponse[validationResponse](t, recorder)
	if response.Valid || len(response.Errors) != 1 || response.Errors[0].Code != "invalid_action" {
		t.Fatalf("invalid response = %+v", response)
	}
}

func TestGeneratePolicyRejectsInvalidWithValidationContract(t *testing.T) {
	e := &Extension{logger: slog.New(slog.DiscardHandler)}
	invalid := minimalPolicy()
	invalid.Action = "SENSITIVE-invalid-action"
	recorder := performConfGenJSONRequest(t, e.generatePolicy, policyRequest{Policies: []Policy{invalid}})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%q", recorder.Code, recorder.Body.String())
	}
	response := decodeConfGenResponse[apiErrorResponse](t, recorder)
	if response.Code != "validation_failed" || response.Validation == nil || response.Validation.Errors[0].Code != "invalid_action" {
		t.Fatalf("response = %+v", response)
	}
	if strings.Contains(recorder.Body.String(), invalid.Action) {
		t.Fatal("validation response leaked the rejected field value")
	}
}

func TestGeneratePolicyAcceptsLegacyFormAndIncludesValidation(t *testing.T) {
	e := &Extension{logger: slog.New(slog.DiscardHandler)}
	policy := minimalPolicy()
	policy.Services = []Service{{Type: "template", Name: "HTTPS"}}
	encodedPolicies, err := json.Marshal([]Policy{policy})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"policies": {string(encodedPolicies)}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	e.generatePolicy(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
	}
	response := decodeConfGenResponse[generateResponse](t, recorder)
	if !response.Validation.Valid || len(response.Outputs) != 1 || response.Outputs[0].Output1 == "" {
		t.Fatalf("response = %+v", response)
	}
}

func TestValidatePolicyEnforcesRequestLimitAndTimeout(t *testing.T) {
	e := &Extension{logger: slog.New(slog.DiscardHandler)}
	oversized := strings.NewReader(`{"policies":[{"policy_comment":"` + strings.Repeat("x", int(maxPolicyRequestBytes)) + `"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/", oversized)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	e.validatePolicies(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413; body=%q", recorder.Code, recorder.Body.String())
	}
	if response := decodeConfGenResponse[apiErrorResponse](t, recorder); response.Code != "request_too_large" {
		t.Fatalf("oversized code = %q", response.Code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"policies":[]}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	e.validatePolicies(recorder, req)
	if recorder.Code != http.StatusRequestTimeout {
		t.Fatalf("timeout status = %d, want 408; body=%q", recorder.Code, recorder.Body.String())
	}
	if response := decodeConfGenResponse[apiErrorResponse](t, recorder); response.Code != "request_timeout" {
		t.Fatalf("timeout code = %q", response.Code)
	}
}

func TestIndexTemplateUsesSharedShell(t *testing.T) {
	e := &Extension{}
	if err := e.parseTemplates(); err != nil {
		t.Fatalf("parse shared page: %v", err)
	}
	data := indexContext{
		Base: webui.BaseData{
			Title: "Policy Generator", Username: "reviewer", Lang: "de", Active: "configgen", ReturnTo: "/fgt-confgen/",
			Shell:      webui.ShellText("de"),
			Navigation: webui.Navigation(webui.NavigationOptions{Lang: "de", Active: "configgen", ConfGen: true}),
		},
		Templates:           []string{"Synthetic baseline"},
		PreselectedTemplate: "Synthetic baseline",
	}
	var output bytes.Buffer
	if err := e.page.Render(&output, data); err != nil {
		t.Fatalf("render shared page: %v", err)
	}
	html := output.String()
	for _, want := range []string{
		`<html lang="de">`, `class="app-rail"`, `aria-current="page"`,
		`class="page confgen-page"`, `data-preselected-template="Synthetic baseline"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("shared ConfGen page missing %q", want)
		}
	}
	for _, asset := range []string{`/fgt-confgen/static/styles.css`, `/fgt-confgen/static/searchable.js`, `/fgt-confgen/static/scripts.js`} {
		if count := strings.Count(html, asset); count != 1 {
			t.Errorf("asset %q rendered %d times, want exactly once", asset, count)
		}
	}
	for _, unwanted := range []string{`class="topbar"`, `class="sysfooter"`, `window.preselectedTemplate =`} {
		if strings.Contains(html, unwanted) {
			t.Errorf("standalone ConfGen shell/bootstrap remains: %q", unwanted)
		}
	}
}

func TestMountRequiresSharedPageContext(t *testing.T) {
	e := New(&config.Config{}, slog.New(slog.DiscardHandler))
	if err := e.Mount(chi.NewRouter(), extension.Deps{}); err == nil || !strings.Contains(err.Error(), "page context") {
		t.Fatalf("Mount error = %v, want missing shared page context", err)
	}
}

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
