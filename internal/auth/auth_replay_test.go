package auth

import (
	"log/slog"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestTOTPReplayRejected(t *testing.T) {
	a := New(&config.Config{}, slog.Default())
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "x", AccountName: "a"})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !a.VerifyTOTP(secret, code) {
		t.Fatal("first use of a valid code must succeed")
	}
	if a.VerifyTOTP(secret, code) {
		t.Fatal("replay of the same code within its window must be rejected")
	}
	// A fresh (different) code must still work.
	code2, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !a.VerifyTOTP(secret, code2) {
		t.Fatal("a new code must still be accepted")
	}
	// Wrong codes still fail.
	if a.VerifyTOTP(secret, "000000") && code != "000000" && code2 != "000000" {
		t.Fatal("invalid code must not authenticate")
	}
}
