// Package crypto provides authenticated encryption at rest (AES-256-GCM) for
// firewall credentials and backup files.
//
// It is deliberately backwards-compatible: when no key is configured the cipher
// is a pass-through, and Decrypt transparently returns any data that lacks the
// FortiSafe magic header (i.e. legacy plaintext written by the Python app or by
// a prior unencrypted run). New data is only encrypted when a key is present.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// magic marks a ciphertext blob: 6-byte header followed by nonce + ciphertext.
var magic = []byte("FSENC1")

const stringPrefix = "enc:"

// Cipher performs optional AES-256-GCM encryption.
type Cipher struct {
	gcm     cipher.AEAD
	enabled bool
}

// New builds a Cipher. A nil/short key disables encryption (pass-through).
func New(key []byte) (*Cipher, error) {
	if len(key) == 0 {
		return &Cipher{enabled: false}, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{gcm: gcm, enabled: true}, nil
}

// Enabled reports whether encryption is active.
func (c *Cipher) Enabled() bool { return c.enabled }

// HasHeader reports whether data was written by Encrypt (i.e. is ciphertext).
func HasHeader(data []byte) bool { return bytes.HasPrefix(data, magic) }

// Encrypt returns ciphertext (magic|nonce|sealed) when enabled, otherwise the
// plaintext unchanged so callers need no branching.
func (c *Cipher) Encrypt(plain []byte) ([]byte, error) {
	if !c.enabled {
		return plain, nil
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(magic)+len(nonce)+len(plain)+c.gcm.Overhead())
	out = append(out, magic...)
	out = append(out, nonce...)
	return c.gcm.Seal(out, nonce, plain, nil), nil
}

// Decrypt reverses Encrypt. Data without the magic header is returned as-is
// (legacy plaintext). Encrypted data requires an enabled cipher.
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	if !HasHeader(data) {
		return data, nil
	}
	if !c.enabled {
		return nil, errors.New("crypto: encrypted data found but no key configured")
	}
	body := data[len(magic):]
	ns := c.gcm.NonceSize()
	if len(body) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce, ct := body[:ns], body[ns:]
	return c.gcm.Open(nil, nonce, ct, nil)
}

// EncryptString encrypts a small secret to an "enc:"-prefixed base64 token, or
// returns it unchanged when encryption is disabled.
func (c *Cipher) EncryptString(s string) (string, error) {
	if !c.enabled {
		return s, nil
	}
	b, err := c.Encrypt([]byte(s))
	if err != nil {
		return "", err
	}
	return stringPrefix + base64.StdEncoding.EncodeToString(b), nil
}

// DecryptString reverses EncryptString. Values without the "enc:" prefix are
// treated as legacy plaintext and returned unchanged.
func (c *Cipher) DecryptString(s string) (string, error) {
	if !strings.HasPrefix(s, stringPrefix) {
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, stringPrefix))
	if err != nil {
		return "", err
	}
	out, err := c.Decrypt(raw)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
