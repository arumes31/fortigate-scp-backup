package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/database"
)

// dbOpTimeout bounds each individual store operation.
const dbOpTimeout = 30 * time.Second

// retries mirrors the default retries=3 of the original backup_firewall.
const retries = 3

// backoff returns the delay before retry attempt n (1-based), with jitter, so a
// flapping device is not hammered on immediate retries (#29).
func backoff(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s, 4s, ...
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	return base + time.Duration(rand.Int63n(int64(time.Second)))
}

// backup performs a single backup cycle for the given firewall id: it pulls the
// configuration over SCP, optionally encrypts it at rest, enforces retention,
// prunes stale rows/files, updates firewall status, and emails on failure
// (subject to a 24h "recent success" suppression window).
func (s *Service) backup(fwID int) {
	shouldNotify := true

	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Backup job failed", "fw_id", fwID, "panic", r)
			if shouldNotify {
				s.mailer.Send(
					fmt.Sprintf("Backup Failure Notification - fw_id %d", fwID),
					fmt.Sprintf("Backup job failed for fw_id %d: %v", fwID, r),
					s.cfg.MailRecipient,
				)
			}
		}
	}()

	s.logger.Info("Starting backup job", "fw_id", fwID)

	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), dbOpTimeout)
	fw, err := s.store.GetFirewall(lookupCtx, fwID)
	lookupCancel()
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			s.logger.Warn("No firewall found", "fw_id", fwID)
		} else {
			s.logger.Error("Failed to look up firewall", "fw_id", fwID, "err", err)
		}
		return
	}

	// Mark in-progress so the list/SSE reflect the running backup.
	s.emit(fwID, "In Progress")

	now := s.store.Now()
	timestamp := now.Format(database.BackupTimeLayout)
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))
	if mkErr := os.MkdirAll(fwDir, 0o777); mkErr != nil {
		s.logger.Error("Failed to create backup directory", "dir", fwDir, "err", mkErr)
	}
	filename := timestamp + ".conf"
	localPath := filepath.Join(fwDir, filename)
	// Stored DB filename uses forward slashes: "<fwID>/<timestamp>.conf".
	dbFilename := path.Join(strconv.Itoa(fwID), filename)
	status := "Success"

	// Notify on failure only if the most recent backup is older than 24h.
	lbCtx, lbCancel := context.WithTimeout(context.Background(), dbOpTimeout)
	lastTime, hasLast, lbErr := s.store.LastBackupTime(lbCtx, fwID)
	lbCancel()
	switch {
	case lbErr != nil:
		s.logger.Error("Failed to query last backup time, will notify", "fw_id", fwID, "err", lbErr)
	case hasLast:
		shouldNotify = now.Sub(lastTime) > 24*time.Hour
		s.logger.Debug("Evaluated last backup recency", "fw_id", fwID, "notify", shouldNotify)
	default:
		s.logger.Debug("No previous backups found, will notify", "fw_id", fwID)
	}

	notify := func(subject, body string) {
		if shouldNotify {
			s.mailer.Send(subject, body, s.cfg.MailRecipient)
		} else {
			s.logger.Info("Skipping email notification, last successful backup is recent", "fw_id", fwID)
		}
	}
	failureEmail := func(errMsg string) {
		notify(
			fmt.Sprintf("Backup Failure Notification - %s", fw.FQDN),
			fmt.Sprintf("Backup failed for %s at %s: %s", fw.FQDN, timestamp, errMsg),
		)
	}

	for attempt := 1; attempt <= retries; attempt++ {
		s.logger.Debug("Starting backup attempt",
			"fw_id", fwID, "fqdn", fw.FQDN, "port", fw.SSHPort, "attempt", attempt, "retries", retries)

		if tErr := s.transfer(fw.FQDN, fw.Username, fw.Password, fw.SSHPort, s.cfg.FortigateConfigPath, localPath, s.cfg.SCPTimeout); tErr != nil {
			s.logger.Error("Backup attempt failed", "attempt", attempt, "retries", retries, "fqdn", fw.FQDN, "err", tErr)
			if attempt == retries {
				status = "Failed: " + tErr.Error()
				removeIfEmpty(localPath)
				failureEmail(tErr.Error())
			} else {
				time.Sleep(backoff(attempt))
			}
			continue
		}

		// From here, errors mirror Python's generic except: mark failed and break.
		info, statErr := os.Stat(localPath)
		if statErr != nil {
			status = "Failed: Backup file was not created"
			removeIfEmpty(localPath)
			failureEmail("Backup file was not created")
			break
		}
		if info.Size() == 0 {
			_ = os.Remove(localPath)
			status = "Failed: Backup file is empty"
			failureEmail("Backup file is empty")
			break
		}

		// Compute size/checksum on the plaintext config, then encrypt at rest.
		size, checksum, finErr := s.finalizeFile(localPath)
		if finErr != nil {
			status = "Failed: " + finErr.Error()
			failureEmail(finErr.Error())
			break
		}

		if dbErr := s.recordSuccess(fwID, fw.RetentionCount, now, dbFilename, fwDir, size, checksum); dbErr != nil {
			status = "Failed: " + dbErr.Error()
			removeIfEmpty(localPath)
			failureEmail(dbErr.Error())
			break
		}

		s.logger.Info("Committed backup and status update", "fw_id", fwID, "size", size)
		s.emit(fwID, "Success")
		break
	}

	if status != "Success" {
		ctx, cancel := context.WithTimeout(context.Background(), dbOpTimeout)
		if err := s.store.UpdateFirewallStatus(ctx, fwID, status); err != nil {
			s.logger.Error("Failed to update firewall status", "fw_id", fwID, "err", err)
		}
		cancel()
		s.emit(fwID, status)
		s.logger.Info("Committed firewall status update", "fw_id", fwID, "status", status)
	}
}

// finalizeFile computes the size and SHA-256 checksum of the plaintext backup,
// then, if encryption is enabled, replaces the file on disk with ciphertext.
// The returned size/checksum always describe the plaintext config.
func (s *Service) finalizeFile(localPath string) (int64, string, error) {
	plain, err := os.ReadFile(localPath)
	if err != nil {
		return 0, "", fmt.Errorf("read backup: %w", err)
	}
	sum := sha256.Sum256(plain)
	checksum := hex.EncodeToString(sum[:])
	size := int64(len(plain))

	if s.cipher.Enabled() {
		enc, err := s.cipher.Encrypt(plain)
		if err != nil {
			return 0, "", fmt.Errorf("encrypt backup: %w", err)
		}
		if err := os.WriteFile(localPath, enc, 0o600); err != nil {
			return 0, "", fmt.Errorf("write encrypted backup: %w", err)
		}
	}
	return size, checksum, nil
}

// recordSuccess inserts the backup row, prunes retention overflow, runs cleanup
// and records the successful backup time and status.
func (s *Service) recordSuccess(fwID, retentionCount int, ts time.Time, dbFilename, fwDir string, size int64, checksum string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbOpTimeout)
	defer cancel()

	if err := s.store.InsertBackup(ctx, fwID, ts, dbFilename, size, checksum); err != nil {
		return err
	}

	all, err := s.store.ListBackupFilenames(ctx, fwID)
	if err != nil {
		return err
	}

	if len(all) > retentionCount {
		for _, dbName := range all[retentionCount:] {
			diskPath := filepath.FromSlash(filepath.Join(s.cfg.BackupDir, dbName))
			if _, statErr := os.Stat(diskPath); statErr == nil {
				if rmErr := os.Remove(diskPath); rmErr != nil {
					s.logger.Warn("Failed to delete retention file", "path", diskPath, "err", rmErr)
				}
			}
			if delErr := s.store.DeleteBackupByFilename(ctx, dbName); delErr != nil {
				return delErr
			}
		}
	}

	s.cleanNonexistentBackups(ctx, fwID, fwDir)

	if err := s.store.UpdateFirewallSuccess(ctx, fwID, ts, "Success"); err != nil {
		return err
	}
	return nil
}

// cleanNonexistentBackups removes database rows whose file is gone and deletes
// files on disk with no database row. Never fails the caller.
func (s *Service) cleanNonexistentBackups(ctx context.Context, fwID int, fwDir string) {
	backups, err := s.store.ListBackupIDFilenames(ctx, fwID, 100)
	if err != nil {
		s.logger.Error("Failed to clean non-existent backups", "fw_id", fwID, "err", err)
		return
	}

	dbFilenames := make(map[string]struct{}, len(backups))
	for _, b := range backups {
		dbFilenames[b.Filename] = struct{}{}
	}

	for _, b := range backups {
		diskPath := filepath.FromSlash(filepath.Join(s.cfg.BackupDir, b.Filename))
		if _, statErr := os.Stat(diskPath); errors.Is(statErr, os.ErrNotExist) {
			s.logger.Warn("Removing non-existent backup entry", "filename", b.Filename)
			if delErr := s.store.DeleteBackupByID(ctx, b.ID); delErr != nil {
				s.logger.Error("Failed to remove backup entry", "id", b.ID, "err", delErr)
			}
		}
	}

	entries, err := os.ReadDir(fwDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Error("Failed to scan firewall directory for orphans", "dir", fwDir, "err", err)
		}
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		rel := path.Join(strconv.Itoa(fwID), entry.Name())
		if _, ok := dbFilenames[rel]; !ok {
			orphan := filepath.Join(fwDir, entry.Name())
			s.logger.Warn("Removing orphaned file", "path", orphan)
			if rmErr := os.Remove(orphan); rmErr != nil {
				s.logger.Error("Failed to remove orphaned file", "path", orphan, "err", rmErr)
			}
		}
	}
}

// removeIfEmpty deletes the file at p only if it exists and is zero bytes.
func removeIfEmpty(p string) {
	if info, err := os.Stat(p); err == nil && info.Size() == 0 {
		_ = os.Remove(p)
	}
}
