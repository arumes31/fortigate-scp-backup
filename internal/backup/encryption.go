package backup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

// MigrateEncryptionAtRest encrypts legacy plaintext backup files and verifies
// existing ciphertext before the application begins serving requests.
func MigrateEncryptionAtRest(root string, cipher *crypto.Cipher) (int, error) {
	migrated := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".conf") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read backup %q: %w", path, err)
		}
		if crypto.HasHeader(data) {
			if _, err := cipher.Decrypt(data); err != nil {
				return fmt.Errorf("verify encrypted backup %q: %w", path, err)
			}
			return nil
		}
		encrypted, err := cipher.Encrypt(data)
		if err != nil {
			return fmt.Errorf("encrypt backup %q: %w", path, err)
		}
		if !crypto.HasHeader(encrypted) {
			return fmt.Errorf("encrypt backup %q: cipher is not enabled", path)
		}
		if err := replaceFileAtomic(path, encrypted); err != nil {
			return fmt.Errorf("replace backup %q: %w", path, err)
		}
		migrated++
		return nil
	})
	return migrated, err
}

func replaceFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fortisafe-encrypt-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	// Windows does not replace an existing destination with os.Rename. The
	// production image is Linux; this fallback keeps local migration/tests usable.
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
