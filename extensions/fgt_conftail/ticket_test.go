package fgtconftail

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestBuildTicketPayloadProvidesHookwiseDisplayFields(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.September, 1, 8, 0, 0, 0, time.UTC)
	chain := chainRecord{
		ID:           "11111111-2222-3333-4444-555555555555",
		FirewallID:   9,
		FirewallName: "branch-fw.example",
		User:         "alice",
		FirstEventAt: startedAt,
		LastEventAt:  startedAt.Add(5 * time.Minute),
		EventCount:   1,
	}
	events := []Event{{
		EventAt:         startedAt,
		Source:          "branch-fw-a",
		DeviceName:      "branch-fw-a",
		DeviceID:        "FGT-TEST-0001",
		UserAttribution: attributionExact,
		Action:          "Edit",
		Path:            "firewall.policy",
		Object:          "17",
		LogID:           "0100044546",
		LogDescription:  "Attribute configured",
	}}

	payload, err := buildTicketPayload(chain, events, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Source != "FortiSafe ConfTail" {
		t.Fatalf("Hookwise source = %q, want %q", payload.Source, "FortiSafe ConfTail")
	}
	if want := "[FortiSafe ID 9 · CT-11111111] branch-fw.example / alice / 1 change"; payload.Summary != want {
		t.Fatalf("Hookwise summary = %q, want %q", payload.Summary, want)
	}
	if payload.Message == "" || payload.Message != payload.Description {
		t.Fatal("Hookwise message must contain the complete formatted description")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var hookwiseFields struct {
		Source  string `json:"source"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(encoded, &hookwiseFields); err != nil {
		t.Fatal(err)
	}
	if hookwiseFields.Source != payload.Source || hookwiseFields.Message != payload.Message {
		t.Fatal("encoded Hookwise payload lost source or message display fields")
	}
	for _, expected := range []string{
		"FortiGate configuration change session",
		"Firewall: branch-fw.example (FortiSafe ID 9)",
		"Administrator: alice",
		"Window: 2026-09-01T08:00:00Z to 2026-09-01T08:05:00Z",
		"Changes: 1",
		"Affected objects:",
		"* firewall.policy / 17",
		"Change excerpts (oldest first):",
		"- 2026-09-01T08:00:00Z | Edit | firewall.policy | Object: 17",
	} {
		if !strings.Contains(payload.Message, expected) {
			t.Fatalf("formatted Hookwise message does not contain %q:\n%s", expected, payload.Message)
		}
	}
	if strings.Contains(payload.Message, `\"description\"`) || strings.Contains(payload.Message, `\n`) {
		t.Fatalf("Hookwise description contains a JSON-escaped payload dump: %q", payload.Message)
	}
}

func TestTicketAffectedObjectsAreDeduplicatedAndBounded(t *testing.T) {
	t.Parallel()
	events := make([]Event, 0, maxTicketAffectedObjects+3)
	for index := 0; index < maxTicketAffectedObjects+2; index++ {
		events = append(events, Event{Path: fmt.Sprintf("firewall.policy.%02d", index), Object: fmt.Sprintf("%d", index)})
	}
	events = append(events, events[0])
	objects, omitted := ticketAffectedObjects(events)
	if len(objects) != maxTicketAffectedObjects || omitted != 2 {
		t.Fatalf("affected objects = %d / omitted %d", len(objects), omitted)
	}
	if objects[0] != "firewall.policy.00 / 0" || objects[1] != "firewall.policy.01 / 1" {
		t.Fatalf("affected object order = %+v", objects[:2])
	}
}

func TestTimelineLineFormatsConfigAttributeDiff(t *testing.T) {
	t.Parallel()

	line := timelineLine(Event{
		EventAt:         time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		ConfigAttribute: "type[fortimanager->normal]",
	})
	for _, want := range []string{
		"Attribute: type",
		"Before: fortimanager",
		"After: normal",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("timeline line does not contain %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "type[fortimanager->normal]") {
		t.Fatalf("timeline line kept the unstructured diff: %s", line)
	}
}

func TestBuildTicketPayloadFormatsUnattributedAdministrator(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.September, 1, 8, 0, 0, 0, time.UTC)
	payload, err := buildTicketPayload(chainRecord{
		ID:           "11111111-2222-3333-4444-555555555555",
		FirewallID:   9,
		FirewallName: "branch-fw.example",
		User:         "-",
		FirstEventAt: startedAt,
		LastEventAt:  startedAt,
		EventCount:   1,
		Unattributed: true,
	}, []Event{{EventAt: startedAt}}, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	const want = "Unknown (not uniquely attributed)"
	if payload.Admin != want || !strings.Contains(payload.Summary, want) ||
		!strings.Contains(payload.Message, "Administrator: "+want) {
		t.Fatalf("unattributed administrator was not formatted consistently: %+v", payload)
	}
}

func TestBuildTicketDescriptionRespectsByteLimit(t *testing.T) {
	t.Parallel()
	chain := chainRecord{
		ID:           "11111111-2222-3333-4444-555555555555",
		FirewallID:   9,
		FirewallName: strings.Repeat("🔥", maxIdentityRunes),
		User:         strings.Repeat("ü", maxIdentityRunes),
		Unattributed: true,
		Late:         true,
	}
	events := []Event{{
		EventAt:         time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		Path:            strings.Repeat("界", maxDetailRunes),
		ConfigAttribute: strings.Repeat("é", maxDetailRunes),
	}}
	for _, limit := range []int{1, 16, 1_024, 60_000} {
		description := buildTicketDescription(chain, events, limit)
		if len(description) > limit {
			t.Fatalf("description bytes = %d, want <= %d", len(description), limit)
		}
		if !utf8.ValidString(description) {
			t.Fatalf("description is not valid UTF-8 at byte limit %d", limit)
		}
	}
}

func TestBuildTicketDescriptionPreservesOmissionCountAndChainID(t *testing.T) {
	t.Parallel()
	const chainID = "11111111-2222-3333-4444-555555555555"
	chain := chainRecord{
		ID:           chainID,
		FirewallID:   9,
		FirewallName: strings.Repeat("firewall-name-", maxIdentityRunes),
		User:         strings.Repeat("administrator-name-", maxIdentityRunes),
		EventCount:   12_345,
		Unattributed: true,
		Late:         true,
	}
	events := []Event{{
		EventAt: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		Message: strings.Repeat("large-redacted-detail-", maxDetailRunes),
	}}
	description := buildTicketDescription(chain, events, 1_024)
	if len(description) > 1_024 || !utf8.ValidString(description) {
		t.Fatalf("description is not a valid 1,024-byte payload: bytes=%d", len(description))
	}
	if !strings.Contains(description, "12345 additional redacted change(s) omitted") {
		t.Fatalf("description lost the exact omission count: %q", description)
	}
	if !strings.Contains(description, chainID) {
		t.Fatalf("description lost the full chain ID: %q", description)
	}
}

func TestTimelineLineIncludesAvailableRedactedContext(t *testing.T) {
	t.Parallel()
	event := Event{
		EventAt:         time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		Source:          "fw-node-a",
		DeviceName:      "branch-node-a",
		DeviceID:        "FGT-TEST-0001",
		VDOM:            "root",
		UserAttribution: attributionUnattributed,
		UI:              "ssh",
		Action:          "Edit",
		TransactionID:   "42",
		Path:            "firewall.policy",
		Object:          "1",
		ConfigAttribute: "password=" + redactedValue,
		LogID:           "0100044546",
		LogDescription:  redactedValue,
		Message:         redactedValue,
		UUID:            "event-uuid",
	}
	line := timelineLine(event)
	for _, expected := range []string{
		"Device: branch-node-a | Serial: FGT-TEST-0001 | Source: fw-node-a",
		"Context: VDOM: root | Attribution: unattributed | Transaction: 42 | UI: ssh",
		"Attribute: password=" + redactedValue,
		"Log: 0100044546 | " + redactedValue,
		"Message: " + redactedValue,
		"Event UUID: event-uuid",
	} {
		if !strings.Contains(line, expected) {
			t.Fatalf("timeline line %q does not contain %q", line, expected)
		}
	}
}
