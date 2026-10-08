package fgtconftail

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scriptedTicketSender struct {
	requestID string
	err       error
	payloads  [][]byte
	ids       []string
	onSend    func()
}

func (s *scriptedTicketSender) send(
	_ context.Context,
	correlationID string,
	payload []byte,
) (string, error) {
	s.ids = append(s.ids, correlationID)
	s.payloads = append(s.payloads, append([]byte{}, payload...))
	if s.onSend != nil {
		s.onSend()
	}
	return s.requestID, s.err
}

func TestDispatchDeliveriesAcceptsHookwiseHandoff(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := sealedTestStore(t, base)
	sender := &scriptedTicketSender{requestID: "hookwise-request-1"}

	stats, err := dispatchDeliveries(
		context.Background(),
		s,
		sender,
		func() time.Time { return base.Add(30 * time.Minute) },
		func(time.Duration) time.Duration { return 0 },
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Accepted != 1 || stats.Failed != 0 {
		t.Fatalf("delivery stats = %+v", stats)
	}
	if len(sender.ids) != 1 || sender.ids[0] == "" || len(sender.payloads[0]) == 0 {
		t.Fatalf("sender received invalid request: ids=%v payloads=%d", sender.ids, len(sender.payloads))
	}
	if got := countRowsWhere(t, s, "outbox", "state = 'accepted' AND request_id = 'hookwise-request-1'"); got != 1 {
		t.Fatalf("accepted outbox rows = %d, want 1", got)
	}
}

func TestDispatchDeliveriesPersistsAcceptanceAfterParentCancellation(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := sealedTestStore(t, base)
	ctx, cancel := context.WithCancel(context.Background())
	sender := &scriptedTicketSender{
		requestID: "hookwise-request-before-shutdown",
		onSend:    cancel,
	}

	stats, err := dispatchDeliveries(
		ctx,
		s,
		sender,
		func() time.Time { return base.Add(30 * time.Minute) },
		func(time.Duration) time.Duration { return 0 },
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Accepted != 1 || stats.Failed != 0 {
		t.Fatalf("delivery stats = %+v", stats)
	}
	if got := countRowsWhere(
		t,
		s,
		"outbox",
		"state = 'accepted' AND request_id = 'hookwise-request-before-shutdown'",
	); got != 1 {
		t.Fatalf("accepted outbox rows after cancellation = %d, want 1", got)
	}
}

func TestDispatchDeliveriesRetriesTransientFailureWithSamePayload(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := sealedTestStore(t, base)
	sender := &scriptedTicketSender{err: &hookwiseError{Kind: hookwiseErrorServer, StatusCode: 503}}
	now := base.Add(30 * time.Minute)

	stats, err := dispatchDeliveries(
		context.Background(),
		s,
		sender,
		func() time.Time { return now },
		func(time.Duration) time.Duration { return 0 },
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 || stats.Accepted != 0 {
		t.Fatalf("delivery stats = %+v", stats)
	}
	due, err := s.dueDeliveries(context.Background(), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].State != deliveryStateRetry || due[0].Attempts != 1 {
		t.Fatalf("retry state = %+v", due)
	}

	sender.err = nil
	sender.requestID = "hookwise-request-2"
	if _, err := dispatchDeliveries(
		context.Background(),
		s,
		sender,
		func() time.Time { return now.Add(time.Minute) },
		func(time.Duration) time.Duration { return 0 },
	); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 2 || string(sender.payloads[0]) != string(sender.payloads[1]) {
		t.Fatal("retry did not send the identical frozen payload")
	}
	if sender.ids[0] != sender.ids[1] {
		t.Fatalf("correlation ID changed across retry: %v", sender.ids)
	}
}

func TestDispatchDeliveriesHonorsRetryAfter(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := sealedTestStore(t, base)
	now := base.Add(30 * time.Minute)
	sender := &scriptedTicketSender{err: &hookwiseError{
		Kind:       hookwiseErrorRateLimited,
		StatusCode: 429,
		RetryAfter: 10 * time.Minute,
	}}

	if _, err := dispatchDeliveries(
		context.Background(),
		s,
		sender,
		func() time.Time { return now },
		func(time.Duration) time.Duration { return 0 },
	); err != nil {
		t.Fatal(err)
	}
	if due, err := s.dueDeliveries(context.Background(), now.Add(10*time.Minute-time.Millisecond), 10); err != nil {
		t.Fatal(err)
	} else if len(due) != 0 {
		t.Fatalf("delivery ignored Retry-After: %+v", due)
	}
	if due, err := s.dueDeliveries(context.Background(), now.Add(10*time.Minute), 10); err != nil {
		t.Fatal(err)
	} else if len(due) != 1 {
		t.Fatalf("delivery not due after Retry-After: %+v", due)
	}
}

func TestDispatchDeliveriesSlowRetriesPersistentFailure(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := sealedTestStore(t, base)
	now := base.Add(30 * time.Minute)
	sender := &scriptedTicketSender{err: &hookwiseError{Kind: hookwiseErrorRejected, StatusCode: 401}}

	if _, err := dispatchDeliveries(
		context.Background(),
		s,
		sender,
		func() time.Time { return now },
		func(time.Duration) time.Duration { return 0 },
	); err != nil {
		t.Fatal(err)
	}
	if got := countRowsWhere(t, s, "outbox", "state = 'failed' AND attempt_count = 1"); got != 1 {
		t.Fatalf("persistent failed rows = %d, want 1", got)
	}
	if due, err := s.dueDeliveries(context.Background(), now.Add(persistentRetryDelay-time.Millisecond), 10); err != nil {
		t.Fatal(err)
	} else if len(due) != 0 {
		t.Fatalf("persistent failure retried too early: %+v", due)
	}
}

func TestDeliveryDecisionTreatsUnknownErrorsAsTransient(t *testing.T) {
	now := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	state, next := deliveryDecision(
		now,
		0,
		errors.New("opaque transport failure"),
		func(time.Duration) time.Duration { return 0 },
	)
	if state != deliveryStateRetry || !next.Equal(now.Add(transientRetryBase)) {
		t.Fatalf("decision = %q/%s", state, next)
	}
}

func TestDispatchDeliveriesAnchorsRetryAfterEachAttempt(t *testing.T) {
	base := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	s := sealedTestStore(t, base)
	now := base.Add(30 * time.Minute)
	sender := &scriptedTicketSender{
		err: &hookwiseError{
			Kind:       hookwiseErrorRateLimited,
			StatusCode: 429,
			RetryAfter: 10 * time.Minute,
		},
		onSend: func() { now = now.Add(5 * time.Minute) },
	}
	if _, err := dispatchDeliveries(
		context.Background(),
		s,
		sender,
		func() time.Time { return now },
		func(time.Duration) time.Duration { return 0 },
	); err != nil {
		t.Fatal(err)
	}
	if due, err := s.dueDeliveries(context.Background(), now.Add(10*time.Minute-time.Nanosecond), 10); err != nil {
		t.Fatal(err)
	} else if len(due) != 0 {
		t.Fatalf("delivery became due before Retry-After elapsed from the completed attempt: %+v", due)
	}
}

func TestDeliveryDecisionCapsRetryAfter(t *testing.T) {
	now := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	state, next := deliveryDecision(
		now,
		0,
		&hookwiseError{
			Kind:       hookwiseErrorRateLimited,
			StatusCode: 429,
			RetryAfter: 30 * 24 * time.Hour,
		},
		func(time.Duration) time.Duration { return time.Hour },
	)
	if state != deliveryStateRetry || !next.Equal(now.Add(transientRetryMax)) {
		t.Fatalf("decision = %q/%s, want retry capped at %s", state, next, transientRetryMax)
	}
}

func sealedTestStore(t *testing.T, base time.Time) *store {
	t.Helper()
	s := newTestStore(t, base)
	event := testEvent(1, "fw-a", "alice", "graylog-1", base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	return s
}
