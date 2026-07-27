package web

import (
	"testing"
	"time"
)

func TestBlockedPortIsToday(t *testing.T) {
	vienna, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		t.Fatalf("load Europe/Vienna: %v", err)
	}
	// "Now" is 2026-07-27 08:00 UTC == 10:00 in Vienna (CEST, UTC+2).
	now := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		says string
		tz   *time.Location
		want bool
	}{
		{"earlier today, UTC", "2026-07-27T02:00:00.000Z", time.UTC, true},
		{"yesterday, UTC", "2026-07-26T23:59:59.000Z", time.UTC, false},
		{"empty timestamp", "", time.UTC, false},
		{"unparsable timestamp", "not-a-timestamp", time.UTC, false},
		{
			// 2026-07-27T22:30:00Z is still July 27 in UTC but already
			// July 28 in Vienna (UTC+2) -- proves the day boundary is
			// computed in the configured zone, not raw UTC.
			"UTC day matches but Vienna day does not", "2026-07-27T22:30:00.000Z", vienna, false,
		},
		{
			// Inverse of the case above: 2026-07-26T22:30:00Z is "yesterday"
			// in raw UTC terms, but shifting +2h into Vienna lands it at
			// 2026-07-27 00:30, matching now's Vienna calendar day -- proves
			// the flip genuinely happens both directions, not just UTC->false.
			"UTC day differs but Vienna day matches", "2026-07-26T22:30:00.000Z", vienna, true,
		},
		{
			// A nil location must fall back to UTC (the function's documented
			// default), not panic or silently misclassify.
			"nil tz falls back to UTC", "2026-07-27T02:00:00.000Z", nil, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := blockedPortIsToday(tt.says, now, tt.tz); got != tt.want {
				t.Errorf("blockedPortIsToday(%q) = %v, want %v", tt.says, got, tt.want)
			}
		})
	}
}
