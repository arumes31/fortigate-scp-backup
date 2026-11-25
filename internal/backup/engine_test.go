package backup

import (
	"bytes"
	"context"
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
	if _, _, err := s.finalizeFile(p, filepath.Join(dir, "out.conf")); err == nil {
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

	_, _, err := s.finalizeFile(p, p+".out")
	if !errors.Is(err, wantErr) {
		t.Fatalf("finalizeFile() error = %v, want original encryption error", err)
	}
	if _, statErr := os.Stat(p); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plaintext backup still exists after encryption failure: %v", statErr)
	}
}

func TestFinalizeFileRemovesPlaintextWhenAtomicReplaceFails(t *testing.T) {
	s := testService(t, make([]byte, 32))
	p := filepath.Join(t.TempDir(), "c.conf")
	if err := os.WriteFile(p, []byte("secret config"), 0o600); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("atomic replacement failed")
	s.replaceFile = func(string, []byte) error { return wantErr }

	_, _, err := s.finalizeFile(p, p+".out")
	if !errors.Is(err, wantErr) {
		t.Fatalf("finalizeFile() error = %v, want original replacement error", err)
	}
	if _, statErr := os.Stat(p); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plaintext backup still exists after replacement failure: %v", statErr)
	}
}

func TestFinalizeFileEncrypts(t *testing.T) {
	key := make([]byte, 32)
	s := testService(t, key)
	dir := t.TempDir()
	p := filepath.Join(dir, "c.conf")
	part := p + partSuffix
	content := []byte("secret config")
	if err := os.WriteFile(part, content, 0o600); err != nil {
		t.Fatal(err)
	}
	size, _, err := s.finalizeFile(part, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(part); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext part file still exists: %v", err)
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

func TestFinalizeFileNeverOverwritesExistingBackup(t *testing.T) {
	s := testService(t, make([]byte, 32))
	dir := t.TempDir()
	p := filepath.Join(dir, "c.conf")
	if err := os.WriteFile(p, []byte("older backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	part := p + partSuffix
	if err := os.WriteFile(part, []byte("new config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.finalizeFile(part, p); err == nil {
		t.Fatal("expected an existing backup file to be refused")
	}
	if got, _ := os.ReadFile(p); string(got) != "older backup" {
		t.Fatalf("existing backup was modified: %q", got)
	}
	if _, err := os.Stat(part); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext part file still exists: %v", err)
	}
}

// checkStorage must refuse an empty replacement volume (even after an earlier
// refused run) and accept a volume that holds a recorded backup.
func TestCheckStorageDetectsMissingVolume(t *testing.T) {
	recorded := func(names ...string) func() ([]string, error) {
		return func() ([]string, error) { return names, nil }
	}
	marker := func(dir string) bool {
		_, err := os.Stat(filepath.Join(dir, storageMarker))
		return err == nil
	}

	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "1"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(empty, "1", "20261125_120000Z.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err) // a file from an earlier run on the replacement volume, not a recorded one
	}
	for range 2 {
		if err := checkStorage(empty, recorded("1/old1.conf", "1/old2.conf")); err == nil {
			t.Fatal("empty replacement volume accepted")
		}
	}
	if marker(empty) {
		t.Fatal("marker written on a refused volume")
	}

	real := t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, "1"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "1", "old2.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkStorage(real, recorded("1/old1.conf", "1/old2.conf")); err != nil || !marker(real) {
		t.Fatalf("real volume: err=%v marker=%t", err, marker(real))
	}
	// Once marked, the volume is accepted without consulting the database.
	if err := checkStorage(real, func() ([]string, error) { return nil, errors.New("db down") }); err != nil {
		t.Fatalf("marked volume rejected: %v", err)
	}

	fresh := t.TempDir()
	if err := checkStorage(fresh, recorded()); err != nil || !marker(fresh) {
		t.Fatalf("fresh install: err=%v marker=%t", err, marker(fresh))
	}
}

func TestSweepTempFilesKeepsBackupsWithoutRows(t *testing.T) {
	s := testService(t, make([]byte, 32))
	dir := t.TempDir()
	for _, name := range []string{"20261125_120000.conf", "unrelated.txt", "20261125_130000.conf.part", encryptTempPrefix + "123"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.sweepTempFiles(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 2 || left[0] != "20261125_120000.conf" || left[1] != "unrelated.txt" {
		t.Fatalf("files left after sweep = %v", left)
	}
}

func TestBackupCoalescesWhileQueued(t *testing.T) {
	s := testService(t, make([]byte, 32))
	if !s.claim(7) {
		t.Fatal("first claim should succeed")
	}
	// With a run already claimed, both entry points must return at once without
	// touching the (nil) store; reaching it would panic.
	s.Enqueue(7)
	s.Backup(7)
	if s.claim(7) {
		t.Fatal("claim should stay held by the first run")
	}
	s.queued.Delete(7)
	if !s.claim(7) {
		t.Fatal("claim should succeed again once the run is released")
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
	migrated, err := MigrateEncryptionAtRest(context.Background(), dir, s.cipher)
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
	if second, err := MigrateEncryptionAtRest(context.Background(), dir, s.cipher); err != nil || second != 0 {
		t.Fatalf("idempotent migration = (%d, %v), want (0, nil)", second, err)
	}
}

func TestMigrateEncryptionAtRestTreatsMissingRootAsEmpty(t *testing.T) {
	t.Parallel()
	s := testService(t, bytes.Repeat([]byte{0x31}, 32))
	missingRoot := filepath.Join(t.TempDir(), "not-created")
	migrated, err := MigrateEncryptionAtRest(context.Background(), missingRoot, s.cipher)
	if err != nil || migrated != 0 {
		t.Fatalf("missing-root migration = (%d, %v), want (0, nil)", migrated, err)
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
	if _, err := MigrateEncryptionAtRest(context.Background(), dir, s.cipher); err == nil {
		t.Fatal("truncated encrypted header was accepted")
	}
}
