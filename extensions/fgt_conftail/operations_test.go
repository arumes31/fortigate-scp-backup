package fgtconftail

import (
	"context"
	"testing"
	"time"
)

func TestAdaptivePollIntervalUsesActivityBands(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		state          PollState
		lastIngestedAt time.Time
		want           time.Duration
	}{
		{
			name: "current failure retries quickly",
			state: PollState{
				LastSuccessAt: now.Add(-time.Hour),
				LastFailureAt: now.Add(-time.Minute),
			},
			want: time.Minute,
		},
		{name: "active changes", lastIngestedAt: now.Add(-4 * time.Minute), want: time.Minute},
		{name: "recent changes", lastIngestedAt: now.Add(-20 * time.Minute), want: 5 * time.Minute},
		{name: "idle", lastIngestedAt: now.Add(-time.Hour), want: 15 * time.Minute},
		{name: "no events", want: 15 * time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := adaptivePollInterval(test.state, test.lastIngestedAt, now); got != test.want {
				t.Fatalf("adaptivePollInterval() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestAdaptivePollDueUsesLastStartAndSelectedInterval(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	state := PollState{LastStartedAt: now.Add(-4 * time.Minute)}
	if adaptivePollDue(state, now.Add(-20*time.Minute), now) {
		t.Fatal("recent activity poll became due before its five-minute interval")
	}
	if !adaptivePollDue(state, now.Add(-20*time.Minute), now.Add(time.Minute)) {
		t.Fatal("recent activity poll was not due after five minutes")
	}
	if !adaptivePollDue(PollState{}, time.Time{}, now) {
		t.Fatal("first poll must always be due")
	}
}

func TestConfTailDiagnosticCodesAreStableAndBounded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code diagnosticCode
		want string
	}{
		{code: codeGraylogPollFailed, want: "CT-GL-001"},
		{code: codeDashboardQueryFailed, want: "CT-DB-002"},
		{code: codeHookwiseDeliveryFailed, want: "CT-HW-001"},
		{code: codeMaintenanceFailed, want: "CT-MAINT-001"},
		{code: codeIndexMaintenanceFailed, want: "CT-IDX-001"},
		{code: codeSessionExported, want: "CT-UI-007"},
	}
	for _, test := range tests {
		if got := test.code.String(); got != test.want {
			t.Errorf("diagnostic code = %q, want %q", got, test.want)
		}
	}
}

func TestStorePollScheduleStateTracksLatestIngestion(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	s := newTestStore(t, base)
	if _, lastIngestedAt, err := s.pollScheduleState(context.Background()); err != nil {
		t.Fatal(err)
	} else if !lastIngestedAt.IsZero() {
		t.Fatalf("empty store last ingestion = %s, want zero", lastIngestedAt)
	}
	event := testEvent(1, "fw-a", "alice", "graylog-1", base.Add(time.Minute))
	if _, err := s.applyPoll(context.Background(), pollBatch{
		EndedAt: base.Add(5 * time.Minute),
		Events:  []Event{event},
	}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	state, lastIngestedAt, err := s.pollScheduleState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.LastSuccessAt.Equal(base.Add(5*time.Minute)) || !lastIngestedAt.Equal(event.IngestedAt) {
		t.Fatalf("schedule state = %+v / %s", state, lastIngestedAt)
	}
}
