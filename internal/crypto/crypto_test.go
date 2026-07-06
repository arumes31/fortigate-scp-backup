package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDisabledCipherIsPassthrough(t *testing.T) {
	c, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled() {
		t.Fatal("expected disabled cipher")
	}
	plain := []byte("config data")
	enc, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, plain) {
		t.Fatal("disabled cipher must not transform data")
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	c, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("secret firewall config with PSK")
	enc, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, plain) {
		t.Fatal("ciphertext must differ from plaintext")
	}
	if !HasHeader(enc) {
		t.Fatal("ciphertext must carry the magic header")
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("roundtrip mismatch: %q != %q", dec, plain)
	}
}

func TestDecryptLegacyPlaintext(t *testing.T) {
	c, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// Data without the magic header is treated as legacy plaintext.
	legacy := []byte("plaintext written before encryption was enabled")
	out, err := c.Decrypt(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, legacy) {
		t.Fatal("legacy plaintext must pass through unchanged")
	}
}

func TestEncryptedDataWithoutKeyFails(t *testing.T) {
	c, _ := New(newKey(t))
	enc, _ := c.Encrypt([]byte("x"))
	disabled, _ := New(nil)
	if _, err := disabled.Decrypt(enc); err == nil {
		t.Fatal("expected error decrypting without a key")
	}
}

func TestStringRoundtrip(t *testing.T) {
	c, _ := New(newKey(t))
	tok, err := c.EncryptString("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if tok == "hunter2" {
		t.Fatal("expected encrypted token")
	}
	got, err := c.DecryptString(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Fatalf("got %q", got)
	}
	// Legacy plaintext (no prefix) passes through.
	if v, _ := c.DecryptString("legacy"); v != "legacy" {
		t.Fatalf("legacy passthrough failed: %q", v)
	}
}

func TestBadKeyLength(t *testing.T) {
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
}
