package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

func testService(t *testing.T, key []byte) *Service {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Load(logger)
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return New(nil, nil, cfg, cipher, logger)
}

func TestBackoffGrows(t *testing.T) {
	if d := backoff(1); d < time.Second || d >= 3*time.Second {
		t.Errorf("backoff(1) = %v out of range", d)
	}
	if d := backoff(3); d < 4*time.Second {
		t.Errorf("backoff(3) = %v too small", d)
	}
	if d := backoff(10); d > 31*time.Second {
		t.Errorf("backoff(10) = %v exceeds cap", d)
	}
}

func TestFinalizeFilePlaintext(t *testing.T) {
	s := testService(t, nil) // encryption disabled
	dir := t.TempDir()
	p := filepath.Join(dir, "c.conf")
	content := []byte("config text")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	size, sum, err := s.finalizeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d", size)
	}
	want := sha256.Sum256(content)
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("checksum mismatch")
	}
	// File must remain plaintext when encryption is off.
	got, _ := os.ReadFile(p)
	if string(got) != string(content) {
		t.Errorf("file should be unchanged")
	}
}

func TestFinalizeFileEncrypts(t *testing.T) {
	key := make([]byte, 32)
	s := testService(t, key)
	dir := t.TempDir()
	p := filepath.Join(dir, "c.conf")
	content := []byte("secret config")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	size, _, err := s.finalizeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) {
		t.Errorf("size should describe plaintext: %d", size)
	}
	// On disk the file is now ciphertext (has the magic header).
	raw, _ := os.ReadFile(p)
	if !crypto.HasHeader(raw) {
		t.Fatal("file should be encrypted on disk")
	}
	// And it decrypts back to the original.
	dec, err := s.cipher.Decrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(content) {
		t.Fatal("decrypt mismatch")
	}
}
