package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

func TestMigrateEncryptionAtRestConcurrentMixedBackups(t *testing.T) {
	t.Parallel()
	cipher, err := crypto.New(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	existing, err := cipher.Encrypt([]byte("already encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	const count = 32
	for i := range count {
		plain := bytes.Repeat([]byte("config system global\nend\n"), i*50)
		for name, data := range map[string][]byte{
			fmt.Sprintf("plain-%02d.conf", i):     plain,
			fmt.Sprintf("encrypted-%02d.conf", i): existing,
		} {
			if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("leave unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if migrated, err := MigrateEncryptionAtRest(context.Background(), root, cipher); err != nil || migrated != count {
		t.Fatalf("mixed migration = %d, %v", migrated, err)
	}
	for i := range count {
		raw, err := os.ReadFile(filepath.Join(root, fmt.Sprintf("plain-%02d.conf", i)))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := cipher.Decrypt(raw)
		if err != nil || !crypto.HasHeader(raw) || !bytes.Equal(plain, bytes.Repeat([]byte("config system global\nend\n"), i*50)) {
			t.Fatalf("plaintext backup %d changed during migration: %v", i, err)
		}
		raw, err = os.ReadFile(filepath.Join(root, fmt.Sprintf("encrypted-%02d.conf", i)))
		if err != nil || !bytes.Equal(raw, existing) {
			t.Fatalf("encrypted backup %d was rewritten: %v", i, err)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(root, "notes.txt")); err != nil || string(raw) != "leave unchanged" {
		t.Fatalf("non-backup changed: %v", err)
	}
	if migrated, err := MigrateEncryptionAtRest(context.Background(), root, cipher); err != nil || migrated != 0 {
		t.Fatalf("second migration = %d, %v", migrated, err)
	}
}

func TestMigrateEncryptionAtRestCancellationAndWorkerError(t *testing.T) {
	t.Parallel()
	cipher, err := crypto.New(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "legacy.conf")
	if err := os.WriteFile(path, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if migrated, err := MigrateEncryptionAtRest(ctx, root, cipher); migrated != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan = %d, %v", migrated, err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "legacy" {
		t.Fatalf("canceled scan modified backup: %v", err)
	}
	for i := range 32 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("bad-%02d.conf", i)), []byte("FSENC1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err = MigrateEncryptionAtRest(context.Background(), root, cipher)
	if err == nil || !strings.Contains(err.Error(), "encrypted envelope is too short") {
		t.Fatalf("worker error replaced by cancellation: %v", err)
	}
}
