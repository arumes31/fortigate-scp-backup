// Package security holds password hashing helpers shared by the store and the
// web layer. Verification accepts both bcrypt hashes and legacy plaintext so an
// existing database (whose passwords were stored in the clear) keeps working;
// callers upgrade a matched plaintext to a hash on the next successful use.
package security

import (
	"crypto/subtle"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	// MinPasswordBytes is the minimum accepted local-password length.
	MinPasswordBytes = 16
	// MaxPasswordBytes matches bcrypt's maximum useful input length.
	MaxPasswordBytes = 72
)

type passwordValidationError string

func (e passwordValidationError) Error() string { return string(e) }

var (
	ErrPasswordRequired    error = passwordValidationError("Enter a new password.")
	ErrPasswordInvalidUTF8 error = passwordValidationError("New password must be valid UTF-8.")
	ErrPasswordTooShort    error = passwordValidationError("New password must contain at least 16 UTF-8 bytes.")
	ErrPasswordTooLong     error = passwordValidationError("New password must contain at most 72 UTF-8 bytes.")
	ErrPasswordUnchanged   error = passwordValidationError("New password must be different from your current password.")
	ErrPasswordMismatch    error = passwordValidationError("New password confirmation does not match.")
)

// ValidateNewPassword applies the complete local-password change policy. Byte
// length is intentional: bcrypt accepts at most 72 bytes, and a Unicode code
// point may occupy more than one UTF-8 byte. Clients may mirror these checks for
// feedback, but callers must always enforce this function server-side.
func ValidateNewPassword(oldPassword, newPassword, confirmation string) error {
	if newPassword == "" {
		return ErrPasswordRequired
	}
	if !utf8.ValidString(newPassword) {
		return ErrPasswordInvalidUTF8
	}
	length := len([]byte(newPassword))
	if length < MinPasswordBytes {
		return ErrPasswordTooShort
	}
	if length > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	if subtle.ConstantTimeCompare([]byte(oldPassword), []byte(newPassword)) == 1 {
		return ErrPasswordUnchanged
	}
	if newPassword != confirmation {
		return ErrPasswordMismatch
	}
	return nil
}

// HashPassword returns a bcrypt hash of the given plaintext.
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

// IsHashed reports whether a stored value is already a bcrypt hash.
func IsHashed(stored string) bool {
	return strings.HasPrefix(stored, "$2a$") ||
		strings.HasPrefix(stored, "$2b$") ||
		strings.HasPrefix(stored, "$2y$")
}

// VerifyPassword checks a provided plaintext against a stored value that may be
// either a bcrypt hash or legacy plaintext.
//
// An empty stored or provided password never authenticates: RADIUS users are
// seeded with an empty local password (they authenticate via RADIUS, not the
// local check), and an empty-vs-empty comparison would otherwise let anyone log
// in as such a user with a blank password, bypassing RADIUS entirely.
func VerifyPassword(stored, provided string) bool {
	if stored == "" || provided == "" {
		return false
	}
	if IsHashed(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}

// NeedsUpgrade reports whether a verified stored value should be re-hashed
// (i.e. it is still plaintext).
func NeedsUpgrade(stored string) bool { return !IsHashed(stored) }
