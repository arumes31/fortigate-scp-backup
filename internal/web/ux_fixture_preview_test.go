package web

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"testing"
)

// TestUXAuditPreview exposes the deterministic UX fixture to a real browser.
// Start it with FORTISAFE_UX_FIXTURE=1 and stop it with Ctrl+C or a local
// POST to /__fixture/shutdown. The legacy opt-in variable remains accepted so
// existing reviewer commands keep working.
func TestUXAuditPreview(t *testing.T) {
	if os.Getenv("FORTISAFE_UX_FIXTURE") != "1" && os.Getenv("FORTISAFE_UX_AUDIT_PREVIEW") != "1" {
		t.Skip("UX fixture preview is opt-in")
	}
	address := os.Getenv("FORTISAFE_UX_FIXTURE_ADDRESS")
	if address == "" {
		address = "127.0.0.1:18901"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fixture, err := startUXFixture(ctx, uxFixtureOptions{Address: address, DefaultScenario: uxScenarioFull})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("FORTISAFE_UX_FIXTURE=%s/dashboard\n", fixture.URL())

	if err := <-fixture.Done(); err != nil {
		t.Fatal(err)
	}
}
