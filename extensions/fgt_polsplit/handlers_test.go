package fgt_polsplit

import "testing"

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
