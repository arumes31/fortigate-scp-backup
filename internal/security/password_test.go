package security

import "testing"

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("changeme")
	if err != nil {
		t.Fatal(err)
	}
	if !IsHashed(hash) {
		t.Fatal("expected a bcrypt hash")
	}
	if !VerifyPassword(hash, "changeme") {
		t.Fatal("correct password should verify")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password must not verify")
	}
	if NeedsUpgrade(hash) {
		t.Fatal("a hash should not need upgrading")
	}
}

func TestVerifyLegacyPlaintext(t *testing.T) {
	// Existing databases store plaintext; verification must still work.
	if !VerifyPassword("changeme", "changeme") {
		t.Fatal("legacy plaintext should verify")
	}
	if VerifyPassword("changeme", "nope") {
		t.Fatal("wrong plaintext must not verify")
	}
	if !NeedsUpgrade("changeme") {
		t.Fatal("plaintext should be flagged for upgrade")
	}
}
