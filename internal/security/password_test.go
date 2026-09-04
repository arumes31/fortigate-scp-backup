package security

import (
	"errors"
	"strings"
	"testing"
)

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

func TestValidateNewPasswordPolicy(t *testing.T) {
	valid16Bytes := "0123456789abcdef"
	validUnicode16Bytes := strings.Repeat("ä", 8)
	tests := []struct {
		name    string
		old     string
		new     string
		confirm string
		wantErr error
	}{
		{name: "valid ASCII", old: "old-password-value", new: valid16Bytes, confirm: valid16Bytes},
		{name: "valid Unicode bytes", old: "old-password-value", new: validUnicode16Bytes, confirm: validUnicode16Bytes},
		{name: "empty", old: "old-password-value", wantErr: ErrPasswordRequired},
		{name: "invalid UTF-8", old: "old-password-value", new: string([]byte{0xff, 0xfe}), confirm: string([]byte{0xff, 0xfe}), wantErr: ErrPasswordInvalidUTF8},
		{name: "15 bytes", old: "old-password-value", new: "0123456789abcde", confirm: "0123456789abcde", wantErr: ErrPasswordTooShort},
		{name: "73 bytes", old: "old-password-value", new: strings.Repeat("a", 73), confirm: strings.Repeat("a", 73), wantErr: ErrPasswordTooLong},
		{name: "unchanged", old: valid16Bytes, new: valid16Bytes, confirm: valid16Bytes, wantErr: ErrPasswordUnchanged},
		{name: "mismatch", old: "old-password-value", new: valid16Bytes, confirm: "fedcba9876543210", wantErr: ErrPasswordMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNewPassword(tt.old, tt.new, tt.confirm)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
