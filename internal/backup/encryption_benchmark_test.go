package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

func BenchmarkEncryptedBackupStartup(b *testing.B) {
	for _, size := range []int{4 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			cipher, err := crypto.New(bytes.Repeat([]byte{0x31}, 32))
			if err != nil {
				b.Fatal(err)
			}
			data, err := cipher.Encrypt(bytes.Repeat([]byte("x"), size))
			if err != nil {
				b.Fatal(err)
			}
			root := b.TempDir()
			const files = 128
			for i := range files {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d.conf", i)), data, 0o600); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				if migrated, err := MigrateEncryptionAtRest(context.Background(), root, cipher); err != nil || migrated != 0 {
					b.Fatalf("startup scan = %d, %v", migrated, err)
				}
			}
			b.ReportMetric(files, "backups/op")
		})
	}
}
