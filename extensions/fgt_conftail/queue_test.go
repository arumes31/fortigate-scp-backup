package fgtconftail

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClearHookwiseQueueClearsUnacceptedDeliveriesAndAuditsAction(t *testing.T) {
	base := time.Date(2026, time.September, 9, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(30 * time.Minute),
		Events: []Event{
			testEvent(1, "fw-a", "pending", "handler-pending", base),
			testEvent(1, "fw-a", "accepted", "handler-accepted", base),
		},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	if err := s.markAccepted(
		context.Background(),
		chainIDForUser(t, s, "accepted"),
		"hookwise-request",
		base.Add(31*time.Minute),
	); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	var activity string
	extension := &Extension{
		store:       s,
		logger:      slog.New(slog.NewJSONHandler(&logs, nil)),
		currentUser: func(*http.Request) string { return "operator" },
		logActivity: func(username, action, details string) {
			activity = username + " " + action + " " + details
		},
	}
	response := httptest.NewRecorder()
	extension.clearHookwiseQueue(
		response,
		httptest.NewRequest(http.MethodPost, "/hookwise-queue/clear", nil),
	)

	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/fgt-conftail/?queue=cleared#ct-hookwise-delivery" {
		t.Fatalf("response = %d / %q", response.Code, response.Header().Get("Location"))
	}
	if got := countRowsWhere(t, s, "outbox", "state = 'cleared'"); got != 1 {
		t.Fatalf("cleared deliveries = %d, want 1", got)
	}
	if got := countRowsWhere(t, s, "outbox", "state = 'accepted'"); got != 1 {
		t.Fatalf("accepted deliveries = %d, want 1", got)
	}
	for _, want := range []string{
		`"msg":"conftail Hookwise queue cleared"`,
		`"code":"CT-UI-008"`,
		`"actor":"operator"`,
		`"cleared":1`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("queue audit log does not contain %q: %s", want, logs.String())
		}
	}
	if activity != "operator ConfTail Hookwise Queue Cleared cleared=1" {
		t.Fatalf("activity = %q", activity)
	}
}

func TestClearHookwiseQueueFailsClosedWithoutStore(t *testing.T) {
	response := httptest.NewRecorder()
	(&Extension{}).clearHookwiseQueue(
		response,
		httptest.NewRequest(http.MethodPost, "/hookwise-queue/clear", nil),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}
