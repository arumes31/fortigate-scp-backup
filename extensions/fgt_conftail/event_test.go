package fgtconftail

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustRecoverMissingUsers(t *testing.T, events []Event, window time.Duration) {
	t.Helper()
	if err := recoverMissingUsers(context.Background(), events, window); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeRawEvent(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name            string
		logID           string
		configPath      string
		configObject    string
		configAttribute string
		wantErr         bool
	}{
		{
			name:       "path change",
			logID:      "0100044544",
			configPath: "system.settings",
		},
		{
			name:         "object change",
			logID:        "0100044545",
			configPath:   "firewall.address",
			configObject: "branch-host",
		},
		{
			name:            "attribute change",
			logID:           "0100044546",
			configPath:      "system.global",
			configAttribute: "hostname[old-name->new-name]",
		},
		{
			name:            "object attribute change",
			logID:           "0100044547",
			configPath:      "firewall.policy",
			configObject:    "100",
			configAttribute: "comments[before->after]",
		},
		{name: "read-only cli audit is excluded", logID: "0100044548", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := RawEvent{
				Timestamp:           now.Add(-time.Minute),
				MessageID:           "graylog-1",
				Type:                "event",
				Subtype:             "system",
				Source:              "fw-a-node1",
				User:                " admin ",
				ConfigTransactionID: "42",
				ConfigPath:          tt.configPath,
				ConfigObject:        tt.configObject,
				ConfigAttribute:     tt.configAttribute,
				LogID:               tt.logID,
			}

			got, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a.example"}, now)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizeRawEvent() unexpectedly succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeRawEvent() error = %v", err)
			}
			if got.FirewallID != 7 || got.FirewallName != "fw-a.example" || got.User != "admin" {
				t.Fatalf("unexpected normalized identity: %+v", got)
			}
			if got.UserAttribution != attributionExact {
				t.Fatalf("attribution = %q, want %q", got.UserAttribution, attributionExact)
			}
			if got.Path != tt.configPath || got.Object != tt.configObject || got.ConfigAttribute != tt.configAttribute {
				t.Fatalf("normalized shape = (%q, %q, %q), want (%q, %q, %q)",
					got.Path, got.Object, got.ConfigAttribute,
					tt.configPath, tt.configObject, tt.configAttribute)
			}
			if got.SemanticHash == "" {
				t.Fatal("semantic hash is empty")
			}
		})
	}
}

func TestNormalizeRawEventRedactsBeforePersistence(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	raw := RawEvent{
		Timestamp:           now,
		MessageID:           "graylog-secret",
		Type:                "event",
		Subtype:             "system",
		Source:              "fw-a",
		User:                "admin",
		ConfigTransactionID: "42",
		ConfigPath:          "system.admin",
		ConfigObject:        "admin",
		ConfigAttribute:     `password[old-value->ENC very-secret-ciphertext]`,
		LogID:               "0100044546",
		Message:             `administrator changed api-key="plain-secret"`,
	}

	got, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"old-value", "very-secret-ciphertext", "plain-secret"} {
		if strings.Contains(got.ConfigAttribute+got.Message, secret) {
			t.Fatalf("normalized event leaked %q: %+v", secret, got)
		}
	}
	if !strings.Contains(got.ConfigAttribute, redactedValue) || got.Message != redactedValue {
		t.Fatalf("redaction markers missing: attribute=%q message=%q", got.ConfigAttribute, got.Message)
	}
}

func TestNormalizeRawEventPreservesLegitimateSensitiveLookingNames(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	raw := RawEvent{
		Timestamp:  now,
		MessageID:  "token-operator-id",
		Type:       "event",
		Subtype:    "system",
		Source:     "secretariat-node",
		DeviceName: "community-gateway",
		VDOM:       "community-zone",
		User:       "token-operator",
		LogID:      "0100044545",
	}

	event, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "secret-fw"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if event.GraylogID != raw.MessageID || event.FirewallName != "secret-fw" ||
		event.Source != raw.Source || event.DeviceName != raw.DeviceName ||
		event.VDOM != raw.VDOM || event.User != raw.User {
		t.Fatalf("legitimate identities were redacted: %+v", event)
	}
}

func TestNormalizeRawEventRedactsComparableSecretAttributes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	for _, attribute := range []string{
		"key[old->new]",
		"passphrase[old->new]",
		"auth-pwd[old->new]",
		"priv-pwd[old->new]",
		"radius-key[old->new]",
	} {
		raw := RawEvent{
			Timestamp:       now,
			MessageID:       attribute,
			Type:            "event",
			Subtype:         "system",
			Source:          "fw-a",
			User:            "admin",
			ConfigAttribute: attribute,
			LogID:           "0100044546",
		}
		event, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a"}, now)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(event.ConfigAttribute, redactedValue) || strings.Contains(event.ConfigAttribute, "old") {
			t.Fatalf("attribute %q was not redacted: %q", attribute, event.ConfigAttribute)
		}
	}
}

func TestNormalizeRawEventRedactsBareKeyAssignmentsInFreeText(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	for _, message := range []string{
		"key[old->new]",
		"administrator changed key = old->new",
		"updated key: plain-secret",
	} {
		raw := RawEvent{
			Timestamp: now,
			MessageID: "bare-key-message",
			Type:      "event",
			Subtype:   "system",
			Source:    "fw-a",
			User:      "admin",
			LogID:     "0100044546",
			Message:   message,
		}
		event, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a"}, now)
		if err != nil {
			t.Fatal(err)
		}
		if event.Message != redactedValue {
			t.Fatalf("message %q was not redacted: %q", message, event.Message)
		}
	}

	for _, message := range []string{"monkey[old->new]", "keyboard=updated", "keynote: changed"} {
		if got := redactFreeText(message); got != message {
			t.Fatalf("non-key field %q was redacted: %q", message, got)
		}
	}
}

func TestNormalizeRawEventRemovesControlCharacters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	raw := RawEvent{
		Timestamp:       now,
		MessageID:       "message\r\nforged",
		Type:            "event",
		Subtype:         "system",
		Source:          "fw-a",
		User:            "admin\tname",
		ConfigAttribute: "name[old\x00->new]",
		LogID:           "0100044546",
	}
	event, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{event.GraylogID, event.User, event.ConfigAttribute} {
		if strings.ContainsAny(value, "\r\n\t\x00") {
			t.Fatalf("normalized field retained a control character: %q", value)
		}
	}
}

func TestNormalizeRawEventRetainsControlOnlyUserAsUnattributed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	event, err := normalizeRawEvent(RawEvent{
		Timestamp: now,
		MessageID: "message-control-user",
		Type:      "event",
		Subtype:   "system",
		Source:    "fw-a",
		User:      "\x00\r\n\t",
		LogID:     "0100044545",
	}, firewallRef{ID: 7, Name: "fw-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if event.User != "" || !event.UserWasMissing || event.UserAttribution != "" {
		t.Fatalf("control-only user was treated as exact: %+v", event)
	}
	events := []Event{event}
	mustRecoverMissingUsers(t, events, 5*time.Minute)
	if events[0].User != unattributedUser ||
		events[0].UserAttribution != attributionUnattributed {
		t.Fatalf("control-only user was not retained as unattributed: %+v", events[0])
	}
}

func TestNormalizeRawEventBoundsExternalFields(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	raw := RawEvent{
		Timestamp:       now,
		MessageID:       "graylog-large",
		Type:            "event",
		Subtype:         "system",
		Source:          "fw-a",
		User:            "admin",
		ConfigAttribute: strings.Repeat("x", maxDetailRunes+100),
		LogID:           "0100044546",
	}

	got, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(got.ConfigAttribute)) > maxDetailRunes || !strings.Contains(got.ConfigAttribute, truncatedMarker) {
		t.Fatalf("attribute was not bounded: runes=%d", len([]rune(got.ConfigAttribute)))
	}
}

func TestNormalizeRawEventRejectsTimestampOutsideUnixNanosecondRange(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	raw := RawEvent{
		Timestamp:       time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
		MessageID:       "graylog-out-of-range",
		Type:            "event",
		Subtype:         "system",
		Source:          "fw-a",
		User:            "admin",
		ConfigAttribute: "name[old->new]",
		LogID:           "0100044546",
	}
	if _, err := normalizeRawEvent(raw, firewallRef{ID: 7, Name: "fw-a"}, now); err == nil {
		t.Fatal("normalizeRawEvent() accepted a timestamp that cannot be stored as Unix nanoseconds")
	}
}

func TestRecoverMissingUsers(t *testing.T) {
	base := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	events := []Event{
		{FirewallID: 1, TransactionID: "100", User: "alice", UserAttribution: attributionExact, EventAt: base},
		{FirewallID: 1, TransactionID: "100", EventAt: base.Add(time.Minute)},
		{FirewallID: 2, TransactionID: "100", User: "bob", UserAttribution: attributionExact, EventAt: base},
		{FirewallID: 2, TransactionID: "100", EventAt: base.Add(time.Minute)},
		{FirewallID: 1, TransactionID: "200", User: "alice", UserAttribution: attributionExact, EventAt: base},
		{FirewallID: 1, TransactionID: "200", User: "bob", UserAttribution: attributionExact, EventAt: base.Add(time.Minute)},
		{FirewallID: 1, TransactionID: "200", EventAt: base.Add(2 * time.Minute)},
		{FirewallID: 1, TransactionID: "300", EventAt: base},
		{FirewallID: 1, TransactionID: "400", User: "carol", UserAttribution: attributionExact, EventAt: base.Add(-10 * time.Minute)},
		{FirewallID: 1, TransactionID: "400", EventAt: base},
	}

	mustRecoverMissingUsers(t, events, 5*time.Minute)

	assertUser := func(index int, user, attribution string) {
		t.Helper()
		if events[index].User != user || events[index].UserAttribution != attribution {
			t.Fatalf("event %d = user %q attribution %q, want %q/%q",
				index, events[index].User, events[index].UserAttribution, user, attribution)
		}
	}
	assertUser(1, "alice", attributionRecovered)
	assertUser(3, "bob", attributionRecovered)
	assertUser(6, unattributedUser, attributionUnattributed)
	assertUser(7, unattributedUser, attributionUnattributed)
	assertUser(9, unattributedUser, attributionUnattributed)
}

func TestRecoverMissingUsersHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := recoverMissingUsers(ctx, []Event{{TransactionID: "100"}}, 5*time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recoverMissingUsers() error = %v, want context cancellation", err)
	}
}

func TestRecoverMissingUsersAtPollLimit(t *testing.T) {
	const eventCount = maxPollEvents
	base := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	events := make([]Event, eventCount)
	for i := range events {
		events[i] = Event{FirewallID: 1, TransactionID: "100", EventAt: base}
		if i%2 == 0 {
			events[i].User = "alice"
			events[i].UserAttribution = attributionExact
		}
	}

	mustRecoverMissingUsers(t, events, 5*time.Minute)
	for i := 1; i < len(events); i += 2 {
		if events[i].User != "alice" || events[i].UserAttribution != attributionRecovered {
			t.Fatalf("event %d was not recovered: %+v", i, events[i])
		}
	}
}

func TestSemanticHashIgnoresGraylogIdentity(t *testing.T) {
	event := Event{
		FirewallID: 1,
		User:       "alice",
		LogID:      "0100044545",
		EventAt:    time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC),
		Object:     "policy-1",
	}
	event.GraylogID = "first"
	first := semanticHash(event)
	correlation := attributionCorrelationHash(event)
	event.GraylogID = "duplicate-ingest-id"
	second := semanticHash(event)
	if first != second {
		t.Fatalf("semantic hashes differ across Graylog IDs: %q != %q", first, second)
	}
	event.User = "bob"
	if semanticHash(event) == first {
		t.Fatal("semantic hash did not keep exact users distinct")
	}
	if attributionCorrelationHash(event) != correlation {
		t.Fatal("attribution correlation hash changed with user evidence")
	}
	event.FirewallID = 2
	if semanticHash(event) == first {
		t.Fatal("semantic hash did not include logical firewall")
	}
}
