package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"testing/iotest"
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

func TestStrictModeRejectsPlaintext(t *testing.T) {
	c, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	c.RequireEncrypted()
	if _, err := c.Decrypt([]byte("legacy")); err == nil {
		t.Fatal("expected strict file decryption to reject plaintext")
	}
	if _, err := c.DecryptString("legacy"); err == nil {
		t.Fatal("expected strict secret decryption to reject plaintext")
	}
}

func TestValidateHeader(t *testing.T) {
	c, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := c.Encrypt([]byte("config system global"))
	if err != nil {
		t.Fatal(err)
	}
	minimal, err := c.Encrypt(nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid envelope", data: encrypted},
		{name: "plaintext", data: []byte("config system global"), wantErr: true},
		{name: "truncated after magic", data: append([]byte(nil), encrypted[:6]...), wantErr: true},
		{name: "truncated authentication tag", data: append([]byte(nil), minimal[:len(minimal)-1]...), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.ValidateHeader(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestInspectHeaderIsBoundedAndPreservesValidation(t *testing.T) {
	c, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := c.Encrypt(bytes.Repeat([]byte("x"), 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	headerSize := len(magic) + c.gcm.NonceSize() + c.gcm.Overhead()
	for _, data := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("config"), 100), encrypted, encrypted[:len(magic)], encrypted[:headerSize-1], encrypted[:headerSize]} {
		r := bytes.NewReader(data)
		isEncrypted, err := c.InspectHeader(r)
		wantEncrypted := HasHeader(data)
		wantErr := wantEncrypted && c.ValidateHeader(data) != nil
		if isEncrypted != wantEncrypted || (err != nil) != wantErr {
			t.Fatalf("%d-byte input: encrypted=%t err=%v, want encrypted=%t error=%t", len(data), isEncrypted, err, wantEncrypted, wantErr)
		}
		if read := len(data) - r.Len(); read > headerSize {
			t.Fatalf("header inspection read %d bytes, limit %d", read, headerSize)
		}
	}
	if ok, err := c.InspectHeader(iotest.OneByteReader(bytes.NewReader(encrypted))); !ok || err != nil {
		t.Fatalf("short reads rejected: encrypted=%t, err=%v", ok, err)
	}
	disabled, _ := New(nil)
	if _, err := disabled.InspectHeader(bytes.NewReader(encrypted)); err == nil {
		t.Fatal("encrypted header accepted without a key")
	}
	readErr := errors.New("read failed")
	if _, err := c.InspectHeader(io.MultiReader(bytes.NewReader(magic), iotest.ErrReader(readErr))); !errors.Is(err, readErr) {
		t.Fatalf("read error lost: %v", err)
	}
}
