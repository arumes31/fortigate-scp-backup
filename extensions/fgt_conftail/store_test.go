package fgtconftail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreAndOutboxNeverPersistRawSecrets(t *testing.T) {
	t.Parallel()
	const rawSecret = "do-not-persist-this-value"
	base := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	event, err := normalizeRawEvent(RawEvent{
		Timestamp:           base,
		MessageID:           "ENC " + rawSecret,
		Type:                "event",
		Subtype:             "system",
		Source:              "fw-a",
		User:                "admin-a",
		DeviceName:          "ENC " + rawSecret,
		DeviceID:            "api-token=" + rawSecret,
		VDOM:                "ENC " + rawSecret,
		UI:                  "api-token=" + rawSecret,
		Action:              "secret: " + rawSecret,
		ConfigTransactionID: "ENC " + rawSecret,
		ConfigPath:          "ENC " + rawSecret,
		ConfigObject:        "ENC " + rawSecret,
		ConfigAttribute:     "password[old->" + rawSecret + "]",
		Message:             "set api-token " + rawSecret,
		UUID:                "ENC " + rawSecret,
		LogID:               "0100044546",
	}, firewallRef{ID: 1, Name: "ENC " + rawSecret}, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	var graylogID, firewallName, deviceName, deviceID, vdom, ui, action string
	var transactionID, path, object, attribute, message, eventUUID string
	if err := s.db.QueryRow(`SELECT
		graylog_id, firewall_name, device_name, device_id, vdom, ui, action,
		transaction_id, config_path, config_object, config_attribute, message, uuid
		FROM events LIMIT 1`).Scan(
		&graylogID,
		&firewallName,
		&deviceName,
		&deviceID,
		&vdom,
		&ui,
		&action,
		&transactionID,
		&path,
		&object,
		&attribute,
		&message,
		&eventUUID,
	); err != nil {
		t.Fatal(err)
	}
	payload := onlyPayload(t, s)
	persisted := strings.Join([]string{
		graylogID,
		firewallName,
		deviceName,
		deviceID,
		vdom,
		ui,
		action,
		transactionID,
		path,
		object,
		attribute,
		message,
		eventUUID,
		string(payload),
	}, "\n")
	if strings.Contains(persisted, rawSecret) {
		t.Fatalf("raw secret reached SQLite or the frozen outbox payload")
	}
	if !strings.Contains(persisted, redactedValue) {
		t.Fatal("persisted event and payload do not carry a redaction marker")
	}
}

func TestOpenStoreInitializesActivationWatermarkOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conftail.db")
	activation := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s, err := openStore(context.Background(), path, activation)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.ActivationAt.Equal(activation) || !state.Watermark.Equal(activation) {
		t.Fatalf("initial state = %+v, want activation/watermark %s", state, activation)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}

	reopenedAt := activation.Add(24 * time.Hour)
	s, err = openStore(context.Background(), path, reopenedAt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	state, err = s.pollState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.ActivationAt.Equal(activation) || !state.Watermark.Equal(activation) {
		t.Fatalf("restart reset state: %+v", state)
	}
}

func TestApplyPollDeduplicatesAndSeparatesFirewallUserKeys(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)

	events := []Event{
		testEvent(1, "fw-a", "alice", "graylog-1", base.Add(time.Minute)),
		testEvent(1, "fw-a", "alice", "graylog-copy", base.Add(time.Minute)),
		testEvent(2, "fw-b", "alice", "graylog-2", base.Add(2*time.Minute)),
		testEvent(1, "fw-a", "bob", "graylog-3", base.Add(3*time.Minute)),
	}
	// Simulate duplicate syslog ingestion under a different Graylog message ID.
	events[1].SemanticHash = events[0].SemanticHash

	result, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(10 * time.Minute),
		Pages:   2,
		Fetched: len(events),
		Events:  events,
	}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 3 || result.Duplicates != 1 {
		t.Fatalf("result = %+v, want 3 inserted and 1 duplicate", result)
	}
	if got := countRows(t, s, "events"); got != 3 {
		t.Fatalf("events = %d, want 3", got)
	}
	if got := countRows(t, s, "chains"); got != 3 {
		t.Fatalf("chains = %d, want 3 firewall/user sessions", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'active'"); got != 3 {
		t.Fatalf("active chains = %d, want 3", got)
	}
}

func TestApplyPollKeepsOtherwiseIdenticalExactUsersSeparate(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	alice := testEvent(1, "fw-a", "alice", "graylog-alice", base)
	bob := testEvent(1, "fw-a", "bob", "graylog-bob", base)
	if alice.SemanticHash == bob.SemanticHash {
		t.Fatal("test setup produced the same semantic identity for two exact users")
	}
	if alice.CorrelationHash != bob.CorrelationHash {
		t.Fatal("test setup did not isolate the user-independent attribution correlation key")
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(10 * time.Minute),
		Events:  []Event{alice, bob},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s, "events"); got != 2 {
		t.Fatalf("events = %d, want both exact-user events", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'active'"); got != 2 {
		t.Fatalf("active chains = %d, want one per exact user", got)
	}
}

func TestApplyPollReattributesActiveEventWhenOverlapAddsExactEvidence(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)

	missing := testEvent(1, "fw-a", "", "graylog-missing-user", base)
	missing.UserAttribution = ""
	missing.SemanticHash = semanticHash(missing)
	initial := []Event{missing}
	mustRecoverMissingUsers(t, initial, 5*time.Minute)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(10 * time.Minute),
		Events:  initial,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	replayed := testEvent(1, "fw-a", "", "graylog-missing-user-reingested", base)
	replayed.UserAttribution = ""
	replayed.SemanticHash = semanticHash(replayed)
	evidence := testEvent(1, "fw-a", "alice", "graylog-exact-user", base.Add(time.Minute))
	overlap := []Event{replayed, evidence}
	mustRecoverMissingUsers(t, overlap, 5*time.Minute)
	result, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(15 * time.Minute),
		Events:  overlap,
	}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}

	if result.Inserted != 1 || result.Duplicates != 1 {
		t.Fatalf("second result = %+v, want one exact insertion and one reconciled replay", result)
	}
	if got := countRowsWhere(t, s, "chains", "user = '[unattributed]'"); got != 0 {
		t.Fatalf("unattributed chains = %d, want delayed exact evidence to reconcile the active chain", got)
	}
	if got := countRowsWhere(t, s, "events", "user_attribution = 'unattributed'"); got != 0 {
		t.Fatalf("unattributed events = %d, want delayed exact evidence to reattribute the replay", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'alice' AND event_count = 2"); got != 1 {
		t.Fatalf("alice two-event chains = %d, want 1", got)
	}
	if got := countRowsWhere(t, s, "events", "user_attribution = 'recovered'"); got != 1 {
		t.Fatalf("recovered events = %d, want 1", got)
	}
}

func TestApplyPollRevokesRecoveredUserWhenOverlapBecomesAmbiguous(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)

	missing := testEvent(1, "fw-a", "", "graylog-missing-user", base)
	missing.UserAttribution = ""
	missing.SemanticHash = semanticHash(missing)
	alice := testEvent(1, "fw-a", "alice", "graylog-alice", base.Add(time.Minute))
	initial := []Event{missing, alice}
	mustRecoverMissingUsers(t, initial, 5*time.Minute)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(10 * time.Minute),
		Events:  initial,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if got := countRowsWhere(t, s, "events", "user_attribution = 'recovered'"); got != 1 {
		t.Fatalf("initial recovered events = %d, want 1", got)
	}

	replayed := testEvent(1, "fw-a", "", "graylog-missing-user-reingested", base)
	replayed.UserAttribution = ""
	replayed.SemanticHash = semanticHash(replayed)
	bob := testEvent(1, "fw-a", "bob", "graylog-bob", base.Add(2*time.Minute))
	overlap := []Event{replayed, alice, bob}
	mustRecoverMissingUsers(t, overlap, 5*time.Minute)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(15 * time.Minute),
		Events:  overlap,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	if got := countRowsWhere(t, s, "events", "user_attribution = 'recovered'"); got != 0 {
		t.Fatalf("recovered events = %d, want ambiguous evidence to revoke the inference", got)
	}
	if got := countRowsWhere(t, s, "events", "user = '[unattributed]' AND user_attribution = 'unattributed'"); got != 1 {
		t.Fatalf("unattributed events = %d, want 1", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = '[unattributed]' AND state = 'active'"); got != 1 {
		t.Fatalf("active unattributed chains = %d, want 1", got)
	}
}

func TestApplyPollSplitsActiveChainWhenReattributionRemovesItsBridge(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	first := testEvent(1, "fw-a", "alice", "graylog-first", base)
	bridge := testEvent(1, "fw-a", "", "graylog-bridge", base.Add(20*time.Minute))
	bridge.User = "alice"
	bridge.UserAttribution = attributionRecovered
	bridge.SemanticHash = semanticHash(bridge)
	last := testEvent(1, "fw-a", "alice", "graylog-last", base.Add(40*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(45 * time.Minute),
		Events:  []Event{first, bridge, last},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	replayed := testEvent(1, "fw-a", "", "graylog-bridge-reingested", base.Add(20*time.Minute))
	replayed.UserAttribution = ""
	overlap := []Event{replayed}
	mustRecoverMissingUsers(t, overlap, 5*time.Minute)
	result, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(45 * time.Minute),
		Events:  overlap,
	}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Duplicates != 1 || result.Sealed != 1 {
		t.Fatalf("reconciliation result = %+v, want one reconciled replay and one split seal", result)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'alice' AND state = 'sealed' AND event_count = 1"); got != 1 {
		t.Fatalf("sealed Alice segments = %d, want the pre-gap event sealed", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'alice' AND state = 'active' AND event_count = 1"); got != 1 {
		t.Fatalf("active Alice segments = %d, want the post-gap event active", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = '[unattributed]' AND state = 'active' AND event_count = 1"); got != 1 {
		t.Fatalf("active unattributed segments = %d, want the bridge preserved separately", got)
	}
	if got := countRows(t, s, "outbox"); got != 1 {
		t.Fatalf("outbox rows = %d, want the newly sealed pre-gap segment", got)
	}
}

func TestApplyPollDoesNotDuplicateSealedEventWhenAttributionImproves(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	missing := testEvent(1, "fw-a", "", "graylog-missing", base)
	missing.UserAttribution = ""
	initial := []Event{missing}
	mustRecoverMissingUsers(t, initial, 5*time.Minute)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  initial,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	replayed := testEvent(1, "fw-a", "", "graylog-missing-reingested", base)
	replayed.UserAttribution = ""
	evidence := testEvent(1, "fw-a", "alice", "graylog-evidence", base.Add(time.Minute))
	overlap := []Event{replayed, evidence}
	mustRecoverMissingUsers(t, overlap, 5*time.Minute)
	result, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(31 * time.Minute),
		Events:  overlap,
	}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Duplicates != 1 || result.Inserted != 1 {
		t.Fatalf("overlap result = %+v, want one sealed duplicate and one evidence row", result)
	}
	if got := countRows(t, s, "events"); got != 2 {
		t.Fatalf("events = %d, want the original change and its exact evidence only", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'alice' AND event_count = 1"); got != 1 {
		t.Fatalf("Alice chains = %d, want no duplicated reattributed change", got)
	}
	if got := countRows(t, s, "outbox"); got != 2 {
		t.Fatalf("outbox rows = %d, want one immutable ticket per actual sealed chain", got)
	}
}

func TestApplyPollUsesExactIdleBoundary(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 123_456_789, time.UTC)
	s := newTestStore(t, base)

	first := testEvent(1, "fw-a", "alice", "graylog-1", base)
	second := testEvent(1, "fw-a", "alice", "graylog-2", base.Add(30*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(31 * time.Minute),
		Events:  []Event{first, second},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, s, "chains"); got != 2 {
		t.Fatalf("chains = %d, want 2 at an exact 30-minute gap", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'sealed'"); got != 1 {
		t.Fatalf("sealed chains = %d, want 1", got)
	}
	if got := countRows(t, s, "outbox"); got != 1 {
		t.Fatalf("outbox rows = %d, want 1", got)
	}
}

func TestApplyPollKeepsSubMillisecondGapBelowIdleBoundaryTogether(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 123_456_789, time.UTC)
	s := newTestStore(t, base)

	first := testEvent(1, "fw-a", "alice", "graylog-1", base)
	second := testEvent(
		1,
		"fw-a",
		"alice",
		"graylog-2",
		base.Add(30*time.Minute-500*time.Microsecond),
	)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(31 * time.Minute),
		Events:  []Event{first, second},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, s, "chains"); got != 1 {
		t.Fatalf("chains = %d, want one session below the exact idle boundary", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'active'"); got != 1 {
		t.Fatalf("active chains = %d, want 1", got)
	}
}

func TestApplyPollDoesNotMarkExactPostSealBoundaryLate(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 321_654_987, time.UTC)
	s := newTestStore(t, base)
	first := testEvent(1, "fw-a", "alice", "graylog-1", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{first},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	boundary := testEvent(1, "fw-a", "alice", "graylog-2", base.Add(30*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(31 * time.Minute),
		Events:  []Event{boundary},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	if got := countRowsWhere(t, s, "chains", "late = 1"); got != 0 {
		t.Fatalf("late chains = %d, want none at the exact new-session boundary", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'active'"); got != 1 {
		t.Fatalf("active chains = %d, want the boundary event in a normal new session", got)
	}
}

func TestApplyPollKeepsDelayedSealedSessionEventOutOfNewActiveChain(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	old := testEvent(1, "fw-a", "alice", "graylog-old", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{old},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	newSession := testEvent(1, "fw-a", "alice", "graylog-new", base.Add(50*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(55 * time.Minute),
		Events:  []Event{newSession},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	delayed := testEvent(1, "fw-a", "alice", "graylog-delayed", base.Add(25*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(60 * time.Minute),
		Events:  []Event{delayed},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	if got := countRowsWhere(t, s, "chains", "state = 'active' AND event_count = 1"); got != 1 {
		t.Fatalf("one-event active chains = %d, want the new session to remain unchanged", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'sealed' AND late = 1 AND event_count = 1"); got != 1 {
		t.Fatalf("isolated late chains = %d, want 1", got)
	}
}

func TestApplyPollGroupsSameBatchLateRowsIntoOneImmutableTicket(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	old := testEvent(1, "fw-a", "alice", "graylog-old", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{old},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	newSession := testEvent(1, "fw-a", "alice", "graylog-new", base.Add(50*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(55 * time.Minute),
		Events:  []Event{newSession},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	result, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(60 * time.Minute),
		Events: []Event{
			testEvent(1, "fw-a", "alice", "graylog-delayed-1", base.Add(20*time.Minute)),
			testEvent(1, "fw-a", "alice", "graylog-delayed-2", base.Add(25*time.Minute)),
		},
	}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 2 || result.Sealed != 1 {
		t.Fatalf("late batch result = %+v, want two rows in one sealed session", result)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'staging'"); got != 0 {
		t.Fatalf("staging chains after commit = %d, want none", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'sealed' AND late = 1 AND event_count = 2"); got != 1 {
		t.Fatalf("grouped late chains = %d, want one two-event chain", got)
	}
	if got := countRowsWhere(t, s, "chains", "state = 'active' AND event_count = 1"); got != 1 {
		t.Fatalf("active new-session chains = %d, want the new session unchanged", got)
	}
	if got := countRows(t, s, "outbox"); got != 2 {
		t.Fatalf("outbox rows = %d, want old and grouped-late immutable tickets", got)
	}
	var payload ticketPayload
	latePayload := []byte{}
	if err := s.db.QueryRow(`SELECT payload_json FROM outbox
		JOIN chains ON chains.id = outbox.chain_id WHERE chains.late = 1`).Scan(&latePayload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(latePayload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ChangeCount != 2 {
		t.Fatalf("late ticket change count = %d, want 2", payload.ChangeCount)
	}
}

func TestApplyPollSealsAtQuietBoundaryAndKeepsPayloadImmutable(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	first := testEvent(1, "fw-a", "alice", "graylog-1", base)

	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{first},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	payloadBefore := onlyPayload(t, s)
	var decoded ticketPayload
	if err := json.Unmarshal(payloadBefore, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ChangeCount != 1 || decoded.Status != "OPEN" || decoded.ChainID == "" {
		t.Fatalf("unexpected payload: %+v", decoded)
	}

	late := testEvent(1, "fw-a", "alice", "graylog-late", base.Add(10*time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(45 * time.Minute),
		Events:  []Event{late},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if payloadAfter := payloadForChain(t, s, decoded.ChainID); string(payloadAfter) != string(payloadBefore) {
		t.Fatal("sealed payload changed after a late event")
	}
	if got := countRowsWhere(t, s, "chains", "late = 1"); got != 1 {
		t.Fatalf("late chains = %d, want 1", got)
	}
}

func TestApplyPollFailureDoesNotAdvanceWatermark(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	event := testEvent(1, "fw-a", "alice", "graylog-1", base.Add(time.Minute))
	event.SemanticHash = ""

	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(15 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err == nil {
		t.Fatal("invalid event unexpectedly committed")
	}
	state, err := s.pollState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Watermark.Equal(base) {
		t.Fatalf("watermark advanced to %s after failed batch", state.Watermark)
	}
	if got := countRows(t, s, "events"); got != 0 {
		t.Fatalf("events committed after failed batch: %d", got)
	}
}

func TestPruneRetentionKeepsActiveAndUnacceptedWork(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)

	accepted := testEvent(1, "fw-a", "accepted", "accepted", base)
	pending := testEvent(1, "fw-a", "pending", "pending", base)
	active := testEvent(1, "fw-a", "active", "active", base.Add(40*24*time.Hour))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(40 * 24 * time.Hour),
		Events:  []Event{accepted, pending, active},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	acceptedChain := chainIDForUser(t, s, "accepted")
	if err := s.markAccepted(context.Background(), acceptedChain, "hookwise-request", base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.prune(context.Background(), base.Add(40*24*time.Hour), 30)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("pruned chains = %d, want only the accepted chain", deleted)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'accepted'"); got != 0 {
		t.Fatalf("accepted old chain remains: %d", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'pending'"); got != 1 {
		t.Fatalf("pending chain was pruned: %d", got)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'active'"); got != 1 {
		t.Fatalf("active chain was pruned: %d", got)
	}
}

func TestDueDeliveriesFollowRetryAndAcceptanceState(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	event := testEvent(1, "fw-a", "alice", "graylog-1", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}

	due, err := s.dueDeliveries(context.Background(), base.Add(30*time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].Attempts != 0 || len(due[0].Payload) == 0 {
		t.Fatalf("initial due deliveries = %+v", due)
	}
	retryAt := base.Add(40 * time.Minute)
	if err := s.markDeliveryFailure(
		context.Background(),
		due[0].ChainID,
		deliveryStateRetry,
		retryAt,
		context.DeadlineExceeded,
		base.Add(31*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	beforeRetry, err := s.dueDeliveries(context.Background(), retryAt.Add(-time.Millisecond), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeRetry) != 0 {
		t.Fatalf("delivery became due early: %+v", beforeRetry)
	}
	due, err = s.dueDeliveries(context.Background(), retryAt, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].Attempts != 1 || due[0].State != deliveryStateRetry {
		t.Fatalf("retry delivery = %+v", due)
	}
	if err := s.markAccepted(context.Background(), due[0].ChainID, "request-1", retryAt); err != nil {
		t.Fatal(err)
	}
	due, err = s.dueDeliveries(context.Background(), retryAt.Add(time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Fatalf("accepted delivery remained due: %+v", due)
	}
}

func TestStoreRestartPreservesChainsOutboxStatesAndFrozenRetryPayload(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "conftail.db")
	s, err := openStore(context.Background(), path, base)
	if err != nil {
		t.Fatal(err)
	}
	events := []Event{
		testEvent(1, "fw-a", "pending", "graylog-pending", base),
		testEvent(1, "fw-a", "retry", "graylog-retry", base),
		testEvent(1, "fw-a", "failed", "graylog-failed", base),
		testEvent(1, "fw-a", "accepted", "graylog-accepted", base),
		testEvent(1, "fw-a", "active", "graylog-active", base.Add(29*time.Minute)),
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  events,
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	pendingChain := chainIDForUser(t, s, "pending")
	retryChain := chainIDForUser(t, s, "retry")
	failedChain := chainIDForUser(t, s, "failed")
	acceptedChain := chainIDForUser(t, s, "accepted")
	frozenPending := payloadForChain(t, s, pendingChain)
	if err := s.markDeliveryFailure(
		context.Background(),
		retryChain,
		deliveryStateRetry,
		base.Add(40*time.Minute),
		context.DeadlineExceeded,
		base.Add(31*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.markDeliveryFailure(
		context.Background(),
		failedChain,
		deliveryStateFailed,
		base.Add(6*time.Hour),
		context.Canceled,
		base.Add(31*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.markAccepted(
		context.Background(),
		acceptedChain,
		"hookwise-request",
		base.Add(31*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}

	s, err = openStore(context.Background(), path, base.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := countRowsWhere(t, s, "chains", "user = 'active' AND state = 'active'"); got != 1 {
		t.Fatalf("active chains after restart = %d, want 1", got)
	}
	for user, wantState := range map[string]string{
		"pending":  deliveryStatePending,
		"retry":    deliveryStateRetry,
		"failed":   deliveryStateFailed,
		"accepted": deliveryStateAccepted,
	} {
		var state string
		var payload []byte
		if err := s.db.QueryRow(`SELECT outbox.state, outbox.payload_json
			FROM outbox JOIN chains ON chains.id = outbox.chain_id WHERE chains.user = ?`, user).Scan(
			&state,
			&payload,
		); err != nil {
			t.Fatal(err)
		}
		if state != wantState || len(payload) == 0 {
			t.Fatalf("%s outbox after restart = %q/%d bytes, want %q/nonempty", user, state, len(payload), wantState)
		}
	}

	failedSend := &scriptedTicketSender{err: &hookwiseError{Kind: hookwiseErrorNetwork}}
	if _, err := dispatchDeliveries(
		context.Background(),
		s,
		failedSend,
		func() time.Time { return base.Add(31 * time.Minute) },
		func(time.Duration) time.Duration { return 0 },
	); err != nil {
		t.Fatal(err)
	}
	if len(failedSend.ids) != 1 || failedSend.ids[0] != pendingChain ||
		!bytes.Equal(failedSend.payloads[0], frozenPending) {
		t.Fatal("first ambiguous send did not use the original frozen pending payload")
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}

	s, err = openStore(context.Background(), path, base.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	successfulRetry := &scriptedTicketSender{requestID: "hookwise-retry"}
	if _, err := dispatchDeliveries(
		context.Background(),
		s,
		successfulRetry,
		func() time.Time { return base.Add(2 * time.Hour) },
		func(time.Duration) time.Duration { return 0 },
	); err != nil {
		t.Fatal(err)
	}
	for index, chainID := range successfulRetry.ids {
		if chainID == pendingChain && bytes.Equal(successfulRetry.payloads[index], frozenPending) {
			return
		}
	}
	t.Fatal("retry after the second restart did not reuse the identical frozen payload")
}

func TestTicketMaterializationBoundsTimelineWorkAndPreservesCount(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	const eventCount = 500
	events := make([]Event, 0, eventCount)
	for index := range eventCount {
		events = append(events, testEvent(
			1,
			"fw-a",
			"alice",
			fmt.Sprintf("graylog-%04d", index),
			base.Add(time.Duration(index)*time.Minute),
		))
	}
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add((eventCount-1)*time.Minute + 30*time.Minute),
		Events:  events,
	}, 30*time.Minute, 1_024); err != nil {
		t.Fatal(err)
	}
	var payload ticketPayload
	if err := json.Unmarshal(onlyPayload(t, s), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ChangeCount != eventCount || len(payload.Description) > 1_024 {
		t.Fatalf("bounded ticket = %d changes/%d bytes, want %d/<=1024", payload.ChangeCount, len(payload.Description), eventCount)
	}
	if !strings.Contains(payload.Description, payload.ChainID) ||
		!strings.Contains(payload.Description, "additional redacted change(s) omitted") {
		t.Fatalf("bounded ticket lost stable footer: %q", payload.Description)
	}
}

func TestTicketMaterializationDoesNotApplyAnEventCountCapBeforeByteLimit(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	const eventCount = 4_200
	const chainID = "11111111-2222-3333-4444-555555555555"
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	sealedAt := base.Add(30 * time.Minute)
	if _, err := tx.ExecContext(ctx, `INSERT INTO chains (
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed, sealed_at_ns, created_at_ns
	) VALUES (?, 1, 'f', 'u', ?, ?, ?, 'sealed', 0, 0, ?, ?)`,
		chainID,
		unixNanos(base),
		unixNanos(base.Add(eventCount-1)),
		eventCount,
		unixNanos(sealedAt),
		unixNanos(base),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `WITH RECURSIVE sequence(index_value) AS (
		SELECT 0
		UNION ALL
		SELECT index_value + 1 FROM sequence WHERE index_value + 1 < ?
	) INSERT INTO events (
		graylog_id, semantic_hash, correlation_hash, chain_id, firewall_id,
		firewall_name, source, user, user_attribution, user_was_missing,
		log_id, event_at_ns, ingested_at_ns
	) SELECT
		printf('g-%04d', index_value), printf('s-%04d', index_value),
		printf('c-%04d', index_value), ?, 1, 'f', 'f', 'u', 'exact', 0,
		'0100044545', ? + index_value, ? + index_value
	FROM sequence`, eventCount, chainID, unixNanos(base), unixNanos(base.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := freezeOutbox(ctx, tx, chainID, sealedAt, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var payload ticketPayload
	if err := json.Unmarshal(onlyPayload(t, s), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ChangeCount != eventCount || len(payload.Description) > 1<<20 {
		t.Fatalf(
			"large ticket = %d changes/%d bytes, want %d/<=1MiB",
			payload.ChangeCount,
			len(payload.Description),
			eventCount,
		)
	}
	if got := strings.Count(payload.Description, "\n- "); got != eventCount {
		t.Fatalf("materialized timeline rows = %d, want all %d rows before the byte limit", got, eventCount)
	}
	if strings.Contains(payload.Description, "additional redacted change(s) omitted") {
		t.Fatal("ticket reported an omission before reaching its byte limit")
	}
}

func TestStorePragmasSurviveConnectionTurnoverAndCascade(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	event := testEvent(1, "fw-a", "alice", "cascade-event", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	chainID := chainIDForUser(t, s, "alice")

	// Drop the initialized idle connection so the following assertions and
	// delete execute on a fresh driver connection.
	s.db.SetMaxIdleConns(0)
	if err := s.db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.db.SetMaxIdleConns(1)

	pragmas := []struct {
		name string
		want any
	}{
		{name: "foreign_keys", want: 1},
		{name: "busy_timeout", want: 5000},
		{name: "synchronous", want: 1},
		{name: "journal_mode", want: "wal"},
		{name: "auto_vacuum", want: 2},
	}
	for _, pragma := range pragmas {
		var got any
		if err := s.db.QueryRow("PRAGMA " + pragma.name).Scan(&got); err != nil {
			t.Fatalf("read PRAGMA %s: %v", pragma.name, err)
		}
		if fmt.Sprint(got) != fmt.Sprint(pragma.want) {
			t.Errorf("PRAGMA %s = %v, want %v", pragma.name, got, pragma.want)
		}
	}

	if _, err := s.db.Exec("DELETE FROM chains WHERE id = ?", chainID); err != nil {
		t.Fatal(err)
	}
	if got := countRowsWhere(t, s, "events", "chain_id = '"+chainID+"'"); got != 0 {
		t.Fatalf("events remaining after cascade = %d", got)
	}
	if got := countRowsWhere(t, s, "outbox", "chain_id = '"+chainID+"'"); got != 0 {
		t.Fatalf("outbox rows remaining after cascade = %d", got)
	}
	var searchMatches int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM event_search WHERE event_search MATCH 'Edit'`).Scan(&searchMatches); err != nil {
		t.Fatal(err)
	}
	if searchMatches != 0 {
		t.Fatalf("full-text rows remaining after cascade = %d", searchMatches)
	}
}

func newTestStore(t *testing.T, activation time.Time) *store {
	t.Helper()
	s, err := openStore(context.Background(), filepath.Join(t.TempDir(), "conftail.db"), activation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.close() })
	return s
}

func TestStoreMigratesVersionOneAndRebuildsRedactedSearchIndex(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	event := testEvent(1, "fw-search", "alice", "search-migration", base.Add(time.Minute))
	event.Message = "urgent vpn migration"
	event.SemanticHash = semanticHash(event)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(time.Hour),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE event_search`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE schema_meta SET version = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := s.initSchema(context.Background(), base); err != nil {
		t.Fatal(err)
	}

	var version int
	if err := s.db.QueryRow(`SELECT version FROM schema_meta WHERE id = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != conftailSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, conftailSchemaVersion)
	}
	var matches int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM event_search WHERE event_search MATCH ?`, `"urgent" AND "vpn"`).Scan(&matches); err != nil {
		t.Fatal(err)
	}
	if matches != 1 {
		t.Fatalf("rebuilt search matches = %d, want 1", matches)
	}
}

func TestStoreMigratesVersionTwoAndCreatesGlobalIgnoreTables(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	if _, err := s.db.Exec(`DROP TABLE ignored_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE global_ignore_rules`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE schema_meta SET version = 2 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := s.initSchema(context.Background(), base); err != nil {
		t.Fatal(err)
	}

	var version int
	if err := s.db.QueryRow(`SELECT version FROM schema_meta WHERE id = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != conftailSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, conftailSchemaVersion)
	}
	event := testEvent(1, "fw-migration.example.test", "operator", "global-ignore-migration", base.Add(time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(2 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.createGlobalIgnoreRule(
		context.Background(),
		storedEventID(t, s, event.GraylogID),
		ignoreRuleKindAttribute,
		"operator",
		base.Add(3*time.Minute),
	); err != nil || !created {
		t.Fatalf("create rule after v2 migration: created=%t err=%v", created, err)
	}
}

func testEvent(firewallID int, firewallName, user, graylogID string, eventAt time.Time) Event {
	event := Event{
		GraylogID:       graylogID,
		FirewallID:      firewallID,
		FirewallName:    firewallName,
		Source:          firewallName,
		User:            user,
		UserAttribution: attributionExact,
		UserWasMissing:  user == "",
		Action:          "Edit",
		TransactionID:   "42",
		Path:            "firewall.policy",
		Object:          "100",
		ConfigAttribute: "comments[before->after]",
		LogID:           "0100044547",
		EventAt:         eventAt,
		IngestedAt:      eventAt.Add(time.Minute),
	}
	event.CorrelationHash = attributionCorrelationHash(event)
	event.SemanticHash = semanticHash(event)
	return event
}

func countRows(t *testing.T, s *store, table string) int {
	t.Helper()
	return countRowsWhere(t, s, table, "1 = 1")
}

func countRowsWhere(t *testing.T, s *store, table, where string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE " + where).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func onlyPayload(t *testing.T, s *store) []byte {
	t.Helper()
	var payload []byte
	if err := s.db.QueryRow("SELECT payload_json FROM outbox").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func payloadForChain(t *testing.T, s *store, chainID string) []byte {
	t.Helper()
	var payload []byte
	if err := s.db.QueryRow("SELECT payload_json FROM outbox WHERE chain_id = ?", chainID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func chainIDForUser(t *testing.T, s *store, user string) string {
	t.Helper()
	var chainID string
	if err := s.db.QueryRow("SELECT id FROM chains WHERE user = ?", user).Scan(&chainID); err != nil {
		t.Fatal(err)
	}
	return chainID
}
