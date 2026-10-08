package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

// MigrateEncryptionAtRest encrypts legacy plaintext backup files and verifies
// existing envelope structure before the application begins serving requests.
// Encrypted backups need only a bounded header read; plaintext is read in full.
func MigrateEncryptionAtRest(ctx context.Context, root string, cipher *crypto.Cipher) (int, error) {
	group, scanCtx := errgroup.WithContext(ctx)
	// Overlap file-open latency without unbounded descriptors, memory, or I/O.
	group.SetLimit(4)
	var migrated atomic.Int64
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := scanCtx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if path == root && errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".conf") {
			return nil
		}
		group.Go(func() error {
			if err := scanCtx.Err(); err != nil {
				return err
			}
			data, legacy, err := readLegacyBackup(path, cipher)
			if err != nil || !legacy {
				return err
			}
			encrypted, err := cipher.Encrypt(data)
			if err != nil {
				return fmt.Errorf("encrypt backup %q: %w", path, err)
			}
			if !crypto.HasHeader(encrypted) {
				return fmt.Errorf("encrypt backup %q: cipher is not enabled", path)
			}
			if err := scanCtx.Err(); err != nil {
				return err
			}
			if err := replaceFileAtomic(path, encrypted); err != nil {
				return fmt.Errorf("replace backup %q: %w", path, err)
			}
			migrated.Add(1)
			return nil
		})
		return nil
	})
	// Join every worker before returning, including on walk errors. Prefer the
	// worker's original error over the cancellation it caused in the walker.
	if err := group.Wait(); err != nil {
		return int(migrated.Load()), err
	}
	return int(migrated.Load()), walkErr
}

func readLegacyBackup(path string, cipher *crypto.Cipher) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("open backup %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	encrypted, err := cipher.InspectHeader(file)
	if err != nil {
		return nil, false, fmt.Errorf("inspect backup %q: %w", path, err)
	}
	if encrypted {
		return nil, false, nil
	}
	// Rewind the same file so migration includes the inspected plaintext prefix.
	// This helper closes it before the caller replaces it (also on Windows).
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, false, fmt.Errorf("rewind backup %q: %w", path, err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, false, fmt.Errorf("read backup %q: %w", path, err)
	}
	return data, true, nil
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
