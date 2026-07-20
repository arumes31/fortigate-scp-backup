package fgt_polsplit

import (
	"testing"
	"time"
)

// TestAppISDBMatches: application-control names map to ISDB objects via
// normalized (lowercase, alphanumeric-only) exact-or-prefix matching; short
// generic names never match.
func TestAppISDBMatches(t *testing.T) {
	isdb := []string{"Amazon-AWS", "Google-Gmail", "Microsoft-Azure", "Microsoft-Office365"}
	if got := appISDBMatches("Microsoft.Azure", isdb); len(got) != 1 || got[0] != "Microsoft-Azure" {
		t.Errorf("Microsoft.Azure = %v", got)
	}
	if got := appISDBMatches("Microsoft.Office.365", isdb); len(got) != 1 || got[0] != "Microsoft-Office365" {
		t.Errorf("Microsoft.Office.365 = %v", got)
	}
	if got := appISDBMatches("SSL", isdb); got != nil {
		t.Errorf("short generic names must not match: %v", got)
	}
	if got := appISDBMatches("Zoom", isdb); got != nil {
		t.Errorf("Zoom = %v", got)
	}
}

// TestMarkRecommended: fewest policies wins, but ineligible strategies (e.g.
// a scope-widening hybrid) never get the badge.
func TestMarkRecommended(t *testing.T) {
	mk := func(key string, pols int) Strategy {
		return Strategy{Key: key, Policies: make([]RecPolicy, pols)}
	}

	strategies := []Strategy{mk("per_service", 4), mk("per_destination", 5), mk("hybrid", 2)}
	markRecommended(strategies, nil)
	if !strategies[2].Recommended {
		t.Errorf("hybrid (fewest policies) should be recommended: %+v", strategies)
	}

	// A widened hybrid is ineligible — the badge falls to the next best.
	strategies = []Strategy{mk("per_service", 4), mk("per_destination", 5), mk("hybrid", 2)}
	markRecommended(strategies, map[string]bool{"hybrid": true})
	if strategies[2].Recommended {
		t.Error("ineligible hybrid must not be recommended")
	}
	if !strategies[0].Recommended {
		t.Errorf("per_service should be recommended instead: %+v", strategies)
	}

	// Empty strategies never win either.
	strategies = []Strategy{mk("per_service", 0), mk("per_destination", 3), mk("hybrid", 0)}
	markRecommended(strategies, nil)
	if !strategies[1].Recommended {
		t.Errorf("only non-empty strategy should be recommended: %+v", strategies)
	}
}

// TestBaselineWindows: the baseline is the compare-duration window immediately
// PRECEDING the analysis window — "Previous 7 days" on a 24h analysis compares
// against days 1–8 back ([now-8d, now-24h]), butting exactly against the
// analysis window with neither overlap nor gap.
func TestBaselineWindows(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	tr, baseTr := baselineWindows(now, 86400, 7*86400)

	if tr.From != "2026-07-16T12:00:00.000Z" || tr.To != "2026-07-17T12:00:00.000Z" {
		t.Errorf("analysis window = %s .. %s", tr.From, tr.To)
	}
	if baseTr.From != "2026-07-09T12:00:00.000Z" {
		t.Errorf("baseline must start range+compare back: %s", baseTr.From)
	}
	if baseTr.To != tr.From {
		t.Errorf("baseline must butt against the analysis window: %s != %s", baseTr.To, tr.From)
	}

	// A baseline SHORTER than the analysis window is valid under these
	// semantics (30d analysis, 7d baseline).
	tr, baseTr = baselineWindows(now, 30*86400, 7*86400)
	if baseTr.To != tr.From || baseTr.From != "2026-06-10T12:00:00.000Z" {
		t.Errorf("short baseline windows wrong: base %s .. %s, analysis from %s", baseTr.From, baseTr.To, tr.From)
	}
}
