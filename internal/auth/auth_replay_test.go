package auth

import (
	"log/slog"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

// TestVerifyTOTPReturnsMatchedTimeStep covers current and skewed counters.
func TestVerifyTOTPReturnsMatchedTimeStep(t *testing.T) {
	_ = New(&config.Config{}, slog.Default())
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "x", AccountName: "a"})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()
	now := time.Unix(1_725_000_000, 0).UTC()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	step, ok := verifyTOTPAt(secret, code, now)
	if !ok {
		t.Fatal("valid code must succeed")
	}
	if want := now.Unix() / totpPeriod; step != want {
		t.Fatalf("time step = %d, want %d", step, want)
	}
	previousCode, err := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	previousStep, ok := verifyTOTPAt(secret, previousCode, now)
	if !ok || previousStep != step-1 {
		t.Fatalf("skewed time step = %d, %v; want %d, true", previousStep, ok, step-1)
	}
	if _, ok := verifyTOTPAt(secret, "000000", now); ok && code != "000000" && previousCode != "000000" {
		t.Fatal("invalid code must not authenticate")
	}
}
