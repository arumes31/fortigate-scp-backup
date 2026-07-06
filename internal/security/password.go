// Package security holds password hashing helpers shared by the store and the
// web layer. Verification accepts both bcrypt hashes and legacy plaintext so an
// existing database (whose passwords were stored in the clear) keeps working;
// callers upgrade a matched plaintext to a hash on the next successful use.
package security

import (
	"crypto/subtle"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

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
func VerifyPassword(stored, provided string) bool {
	if IsHashed(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}

// NeedsUpgrade reports whether a verified stored value should be re-hashed
// (i.e. it is still plaintext).
func NeedsUpgrade(stored string) bool { return !IsHashed(stored) }
