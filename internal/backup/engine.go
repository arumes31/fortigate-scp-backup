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
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	appsecurity "github.com/arumes31/fortigate-scp-backup/internal/security"
)

// dbOpTimeout bounds each individual store operation.
const dbOpTimeout = 30 * time.Second

// partSuffix marks an in-progress plaintext download next to its final name.
const partSuffix = ".part"

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
// configuration over SCP, encrypts it at rest, enforces retention,
// prunes stale rows/files, updates firewall status, and emails on failure
// (subject to a 24h "recent success" suppression window).
func (s *Service) backup(fwID int) {
	shouldNotify := true

	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Backup job failed", "fw_id", fwID, "panic", r)
			// Persist a failed status so a panic after the "In Progress" emit does
			// not leave the firewall stuck showing an in-progress backup.
			panicStatus := fmt.Sprintf("Failed: panic: %v", r)
			failCtx, failCancel := context.WithTimeout(context.Background(), dbOpTimeout)
			if err := s.store.UpdateFirewallStatus(failCtx, fwID, panicStatus); err != nil {
				s.logger.Error("Failed to persist panic status", "fw_id", fwID, "err", err)
			}
			failCancel()
			s.emit(fwID, panicStatus)
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
	// 0o750: keep per-firewall backup dirs (potentially plaintext configs) off
	// world-readable paths.
	if mkErr := os.MkdirAll(fwDir, 0o750); mkErr != nil {
		s.logger.Error("Failed to create backup directory", "dir", fwDir, "err", mkErr)
	}
	// UTC so the repeated DST hour cannot reuse a filename; the Z keeps these
	// distinct from older local-time names, which finalizeFile refuses to overwrite.
	filename := now.UTC().Format(database.BackupTimeLayout) + "Z.conf"
	localPath := filepath.Join(fwDir, filename)
	// Download to a side file; finalizeFile moves the encrypted result to
	// localPath, so plaintext never sits under the final name.
	partPath := localPath + partSuffix
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

	// Refuse to write, prune or delete anything while the backup volume is missing.
	storageErr := s.ensureStorage()
	if storageErr != nil {
		status = "Failed: " + storageErr.Error()
		s.logger.Error("Backup storage unavailable", "fw_id", fwID, "err", storageErr)
		failureEmail(storageErr.Error())
	}
	for attempt := 1; storageErr == nil && attempt <= retries; attempt++ {
		s.logger.Debug("Starting backup attempt",
			"fw_id", fwID, "fqdn", fw.FQDN, "port", fw.SSHPort, "attempt", attempt, "retries", retries)

		s.setStage(fwID, fmt.Sprintf("downloading configuration (attempt %d/%d)", attempt, retries))
		if tErr := s.transfer(fw.FQDN, fw.Username, fw.Password, fw.SSHPort, s.cfg.FortigateConfigPath, partPath, s.cfg.SCPTimeout); tErr != nil {
			s.logger.Error("Backup attempt failed", "attempt", attempt, "retries", retries, "fqdn", fw.FQDN, "err", tErr)
			// Always discard a partially written config before retrying or failing,
			// so a truncated (non-empty) file never lingers on disk.
			if rmErr := os.Remove(partPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				s.logger.Warn("Failed to remove partial backup file", "path", partPath, "err", rmErr)
			}
			if attempt == retries {
				status = "Failed: " + tErr.Error()
				failureEmail(tErr.Error())
			} else {
				time.Sleep(backoff(attempt))
			}
			continue
		}

		// From here, errors mirror Python's generic except: mark failed and break.
		info, statErr := os.Stat(partPath)
		if statErr != nil {
			status = "Failed: Backup file was not created"
			removeIfEmpty(partPath)
			failureEmail("Backup file was not created")
			break
		}
		if info.Size() == 0 {
			_ = os.Remove(partPath)
			status = "Failed: Backup file is empty"
			failureEmail("Backup file is empty")
			break
		}

		// Compute size/checksum on the plaintext config, then encrypt at rest.
		s.setStage(fwID, "verifying & encrypting")
		size, checksum, finErr := s.finalizeFile(partPath, localPath)
		if finErr != nil {
			status = "Failed: " + finErr.Error()
			failureEmail(finErr.Error())
			break
		}

		s.setStage(fwID, "storing & pruning retention")
		if dbErr := s.recordSuccess(fwID, fw.RetentionCount, now, dbFilename, fwDir, size, checksum); dbErr != nil {
			status = "Failed: " + dbErr.Error()
			// Keep a non-empty file: a failed insert may still have committed its row.
			removeIfEmpty(localPath)
			failureEmail(dbErr.Error())
			break
		}

		s.logger.Info("Committed backup and status update", "fw_id", fwID, "size", size)
		s.emit(fwID, "Success")
		s.publishCommitted(fwID, dbFilename, checksum)
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

// finalizeFile computes the size and SHA-256 checksum of the plaintext backup
// at partPath, atomically writes the ciphertext to localPath and always removes
// partPath. An existing localPath is never overwritten.
// The returned size/checksum always describe the plaintext config.
func (s *Service) finalizeFile(partPath, localPath string) (int64, string, error) {
	defer s.removePlaintext(partPath)
	plain, err := os.ReadFile(partPath)
	if err != nil {
		return 0, "", fmt.Errorf("read backup: %w", err)
	}
	sum := sha256.Sum256(plain)
	checksum := hex.EncodeToString(sum[:])
	size := int64(len(plain))

	enc, err := s.encrypt(plain)
	if err != nil {
		return 0, "", fmt.Errorf("encrypt backup: %w", err)
	}
	if !crypto.HasHeader(enc) {
		return 0, "", errors.New("backup encryption requires an enabled cipher")
	}
	// Pre-UTC filenames used local time, so a new name can match an older backup.
	if _, err := os.Lstat(localPath); err == nil {
		return 0, "", fmt.Errorf("backup file %s already exists", filepath.Base(localPath))
	}
	if err := s.replaceFile(localPath, enc); err != nil {
		return 0, "", fmt.Errorf("write encrypted backup: %w", err)
	}
	return size, checksum, nil
}

func (s *Service) removePlaintext(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Warn("Failed to remove plaintext backup", "path", path, "err", err)
	}
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

	// A retention count below 1 is invalid: a negative value would panic on the
	// all[retentionCount:] slice below, and 0 would delete every backup
	// (including the one just written) while still reporting success. Clamp to
	// keeping at least the newest backup.
	if retentionCount < 1 {
		s.logger.Warn("Invalid retention_count clamped to 1", "fw_id", fwID, "retention_count", retentionCount)
		retentionCount = 1
	}

	if len(all) > retentionCount {
		for _, dbName := range all[retentionCount:] {
			diskPath, pathErr := appsecurity.JoinWithin(s.cfg.BackupDir, dbName)
			if pathErr != nil {
				s.logger.Error("Skipping retention row with invalid backup path", "filename", dbName, "err", pathErr)
				continue
			}
			if _, statErr := os.Stat(diskPath); statErr == nil {
				if rmErr := os.Remove(diskPath); rmErr != nil {
					s.logger.Warn("Failed to delete retention file", "path", diskPath, "err", rmErr)
				}
			}
			if delErr := s.store.DeleteBackupByFilename(ctx, dbName); delErr != nil {
				return delErr
			}
			s.prunedTotal.Add(1)
		}
	}

	s.cleanNonexistentBackups(ctx, fwID, fwDir)

	if err := s.store.UpdateFirewallSuccess(ctx, fwID, ts, "Success"); err != nil {
		return err
	}
	return nil
}

// cleanNonexistentBackups removes database rows whose file is gone and the
// app's own leftover temp files. Other files without a row are kept: deleting
// them could wipe history whenever the database and volume disagree. Never
// fails the caller.
func (s *Service) cleanNonexistentBackups(ctx context.Context, fwID int, fwDir string) {
	backups, err := s.store.ListBackupIDFilenames(ctx, fwID, 0)
	if err != nil {
		s.logger.Error("Failed to clean non-existent backups", "fw_id", fwID, "err", err)
		return
	}
	for _, b := range s.missingBackupRows(backups) {
		s.logger.Warn("Removing non-existent backup entry", "filename", b.Filename)
		if delErr := s.store.DeleteBackupByID(ctx, b.ID); delErr != nil {
			s.logger.Error("Failed to remove backup entry", "id", b.ID, "err", delErr)
		}
	}
	s.sweepTempFiles(fwDir)
}

// missingBackupRows returns the rows whose file no longer exists. ensureStorage
// has already confirmed the backup volume is the one these rows refer to.
func (s *Service) missingBackupRows(backups []models.Backup) []models.Backup {
	var missing []models.Backup
	for _, b := range backups {
		diskPath, pathErr := appsecurity.JoinWithin(s.cfg.BackupDir, b.Filename)
		if pathErr != nil {
			s.logger.Error("Invalid backup path in database", "filename", b.Filename, "err", pathErr)
			continue
		}
		if _, statErr := os.Stat(diskPath); errors.Is(statErr, os.ErrNotExist) {
			missing = append(missing, b)
		}
	}
	return missing
}

// storageMarker sits in BACKUP_DIR so an unmounted or replaced volume is detected
// before any backup is written, pruned or has its row deleted.
const storageMarker = ".fortisafe-storage"

func (s *Service) ensureStorage() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbOpTimeout)
	defer cancel()
	return checkStorage(s.cfg.BackupDir, func() ([]string, error) { return s.store.ListAllBackupFilenames(ctx) })
}

// checkStorage accepts dir when its marker exists, or when it holds at least one
// recorded backup (or none are recorded yet) and then writes the marker. A dir
// without the marker and without any recorded file is not the backup volume.
func checkStorage(dir string, recorded func() ([]string, error)) error {
	marker := filepath.Join(dir, storageMarker)
	if _, err := os.Stat(marker); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("backup storage check: %w", err)
	}
	names, err := recorded()
	if err != nil {
		return fmt.Errorf("backup storage check: %w", err)
	}
	found := len(names) == 0
	for _, name := range names {
		if p, pathErr := appsecurity.JoinWithin(dir, name); pathErr == nil {
			if _, statErr := os.Stat(p); statErr == nil {
				found = true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("backup storage %s has no %s marker and none of the %d recorded backup files; mount the backup volume, or create the marker if the old backups are intentionally gone", dir, storageMarker, len(names))
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("backup storage check: %w", err)
	}
	if err := os.WriteFile(marker, []byte("FortiSafe backup storage marker. Do not delete.\n"), 0o640); err != nil {
		return fmt.Errorf("backup storage marker: %w", err)
	}
	return nil
}

// sweepTempFiles removes leftover download (.part) and encryption temp files.
func (s *Service) sweepTempFiles(fwDir string) {
	entries, err := os.ReadDir(fwDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Error("Failed to scan firewall directory for temp files", "dir", fwDir, "err", err)
		}
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		isTemp := strings.HasPrefix(name, encryptTempPrefix) || strings.HasSuffix(name, partSuffix)
		if !entry.Type().IsRegular() || !isTemp {
			continue
		}
		p := filepath.Join(fwDir, name)
		s.logger.Warn("Removing leftover temp file", "path", p)
		if rmErr := os.Remove(p); rmErr != nil {
			s.logger.Error("Failed to remove leftover temp file", "path", p, "err", rmErr)
		}
	}
}

// removeIfEmpty deletes the file at p only if it exists and is zero bytes.
func removeIfEmpty(p string) {
	if info, err := os.Stat(p); err == nil && info.Size() == 0 {
		_ = os.Remove(p)
	}
}
