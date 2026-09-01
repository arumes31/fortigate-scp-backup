package backup

import (
	"errors"
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

func TestFinalizeFileRejectsDisabledEncryption(t *testing.T) {
	s := testService(t, nil)
	dir := t.TempDir()
	p := filepath.Join(dir, "c.conf")
	content := []byte("config text")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.finalizeFile(p); err == nil {
		t.Fatal("expected disabled encryption to be rejected")
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext backup still exists after encryption rejection: %v", err)
	}
}

func TestFinalizeFileRemovesPlaintextWhenEncryptionFails(t *testing.T) {
	s := testService(t, make([]byte, 32))
	p := filepath.Join(t.TempDir(), "c.conf")
	if err := os.WriteFile(p, []byte("secret config"), 0o600); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("random source failed")
	s.encrypt = func([]byte) ([]byte, error) { return nil, wantErr }

	_, _, err := s.finalizeFile(p)
	if !errors.Is(err, wantErr) {
		t.Fatalf("finalizeFile() error = %v, want original encryption error", err)
	}
	if _, statErr := os.Stat(p); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plaintext backup still exists after encryption failure: %v", statErr)
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

func TestMigrateEncryptionAtRest(t *testing.T) {
	key := make([]byte, 32)
	s := testService(t, key)
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "1", "legacy.conf")
	if err := os.MkdirAll(filepath.Dir(plainPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plainPath, []byte("legacy config"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateEncryptionAtRest(dir, s.cipher)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 1 {
		t.Fatalf("migrated = %d, want 1", migrated)
	}
	raw, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.HasHeader(raw) {
		t.Fatal("migrated backup is not encrypted")
	}
	if second, err := MigrateEncryptionAtRest(dir, s.cipher); err != nil || second != 0 {
		t.Fatalf("idempotent migration = (%d, %v), want (0, nil)", second, err)
	}
}

func TestMigrateEncryptionAtRestRejectsTruncatedEncryptedHeader(t *testing.T) {
	s := testService(t, make([]byte, 32))
	dir := t.TempDir()
	path := filepath.Join(dir, "1", "truncated.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("FSENC1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateEncryptionAtRest(dir, s.cipher); err == nil {
		t.Fatal("truncated encrypted header was accepted")
	}
}
