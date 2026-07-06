package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/database"
)

// dbOpTimeout bounds each individual store operation. The Python version relied
// on a connection pool without explicit per-statement timeouts; here we use a
// generous bound so a wedged database cannot block a worker forever.
const dbOpTimeout = 30 * time.Second

// retries mirrors the default `retries=3` argument of backup_firewall.
const retries = 3

// backup performs a single backup cycle for the given firewall id. It is a
// faithful port of the Python backup_firewall(fw_id, retries=3, timeout=SCP_TIMEOUT):
// it pulls the configuration over SCP, enforces retention, prunes stale rows and
// files, updates firewall status, and emails on failure (subject to a 24h
// "recent success" suppression window).
func (s *Service) backup(fwID int) {
	// shouldNotify defaults to true so an early/unexpected failure (mirrored by
	// Python's outer try/except) still attempts a notification.
	shouldNotify := true

	// Outer recovery: mirror the top-level try/except which emails on an
	// otherwise-unhandled failure. Panics are logged and never propagate.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Backup job failed", "fw_id", fwID, "panic", r)
			if shouldNotify {
				s.mailer.Send(
					fmt.Sprintf("Backup Failure Notification - fw_id %d", fwID),
					fmt.Sprintf("Backup job failed for fw_id %d: %v", fwID, r),
					s.cfg.MailRecipient,
				)
			} else {
				s.logger.Info("Skipping email notification, last successful backup is recent", "fw_id", fwID)
			}
		}
	}()

	s.logger.Info("Starting backup job", "fw_id", fwID)

	// 1. Look up the firewall.
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

	// 2. Compute timestamp, paths and ensure the firewall directory exists.
	now := s.store.Now()
	timestamp := now.Format(database.BackupTimeLayout)
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))
	if mkErr := os.MkdirAll(fwDir, 0o777); mkErr != nil {
		s.logger.Error("Failed to create backup directory", "dir", fwDir, "err", mkErr)
	}
	filename := timestamp + ".conf"
	localPath := filepath.Join(fwDir, filename)
	// The stored DB filename must use forward slashes: "<fwID>/<timestamp>.conf",
	// matching the Linux os.path.join the Python code produced.
	dbFilename := path.Join(strconv.Itoa(fwID), filename)
	status := "Success"

	// 3. Determine whether we should notify on failure: only if the most recent
	// backup is older than 24h (or there is none / it is unparseable).
	lbCtx, lbCancel := context.WithTimeout(context.Background(), dbOpTimeout)
	lastTS, hasLast, lbErr := s.store.LastBackupTimestamp(lbCtx, fwID)
	lbCancel()
	switch {
	case lbErr != nil:
		s.logger.Error("Failed to query last backup timestamp, will notify", "fw_id", fwID, "err", lbErr)
		shouldNotify = true
	case hasLast:
		if lastTime, perr := time.ParseInLocation(database.BackupTimeLayout, lastTS, now.Location()); perr == nil {
			shouldNotify = now.Sub(lastTime) > 24*time.Hour
			s.logger.Debug("Evaluated last backup recency", "fw_id", fwID, "last_backup", lastTS, "notify", shouldNotify)
		} else {
			s.logger.Warn("Invalid timestamp format, will notify", "fw_id", fwID, "value", lastTS)
			shouldNotify = true
		}
	default:
		s.logger.Debug("No previous backups found, will notify", "fw_id", fwID)
	}

	// 4. Best-effort permissions log, matching the Python debug line.
	if info, statErr := os.Stat(s.cfg.BackupDir); statErr == nil {
		s.logger.Debug("Backup directory permissions", "dir", s.cfg.BackupDir, "mode", info.Mode().Perm().String())
	} else {
		s.logger.Error("Failed to check backup directory permissions", "err", statErr)
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

	// 5. Retry loop.
	for attempt := 1; attempt <= retries; attempt++ {
		s.logger.Debug("Starting backup attempt",
			"fw_id", fwID, "fqdn", fw.FQDN, "port", fw.SSHPort, "user", fw.Username, "attempt", attempt, "retries", retries)

		// Connection + SCP transfer. Errors here are retryable, mirroring the
		// Python (socket.timeout, SSHException, SCPException) branch.
		if tErr := s.transfer(fw.FQDN, fw.Username, fw.Password, fw.SSHPort, s.cfg.FortigateConfigPath, localPath, s.cfg.SCPTimeout); tErr != nil {
			s.logger.Error("Backup attempt failed", "attempt", attempt, "retries", retries, "fqdn", fw.FQDN, "err", tErr)
			if attempt == retries {
				status = "Failed: " + tErr.Error()
				removeIfEmpty(localPath)
				failureEmail(tErr.Error())
			}
			continue
		}

		// From here on, any error mirrors Python's generic `except Exception`
		// branch: mark failed, notify, and break (no further retries).

		// Verify the file was created and is non-empty.
		info, statErr := os.Stat(localPath)
		if statErr != nil {
			errMsg := "Backup file was not created"
			s.logger.Error("Unexpected error during backup attempt",
				"attempt", attempt, "retries", retries, "fqdn", fw.FQDN, "err", errMsg)
			status = "Failed: " + errMsg
			removeIfEmpty(localPath)
			failureEmail(errMsg)
			break
		}
		if info.Size() == 0 {
			_ = os.Remove(localPath)
			errMsg := "Backup file is empty"
			s.logger.Error("Unexpected error during backup attempt",
				"attempt", attempt, "retries", retries, "fqdn", fw.FQDN, "err", errMsg)
			status = "Failed: " + errMsg
			failureEmail(errMsg)
			break
		}
		s.logger.Debug("Backup successful", "fqdn", fw.FQDN, "local", localPath)

		// Record the backup, enforce retention, clean up and mark success.
		if dbErr := s.recordSuccess(fwID, fw.RetentionCount, timestamp, dbFilename, fwDir); dbErr != nil {
			s.logger.Error("Unexpected error during backup attempt",
				"attempt", attempt, "retries", retries, "fqdn", fw.FQDN, "err", dbErr)
			status = "Failed: " + dbErr.Error()
			removeIfEmpty(localPath)
			failureEmail(dbErr.Error())
			break
		}

		s.logger.Info("Committed backup and status update", "fw_id", fwID)
		break
	}

	// 6. Persist a non-success status, matching the trailing Python UPDATE.
	if status != "Success" {
		ctx, cancel := context.WithTimeout(context.Background(), dbOpTimeout)
		if err := s.store.UpdateFirewallStatus(ctx, fwID, status); err != nil {
			s.logger.Error("Failed to update firewall status", "fw_id", fwID, "err", err)
		}
		cancel()
		s.logger.Info("Committed firewall status update", "fw_id", fwID, "status", status)
	}
}

// recordSuccess inserts the new backup row, prunes retention overflow from disk
// and the database, runs the orphan/stale cleanup routine and finally records the
// successful backup time and status. It mirrors the success path of the Python
// try block; a returned error corresponds to Python's generic-exception branch.
func (s *Service) recordSuccess(fwID, retentionCount int, timestamp, dbFilename, fwDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbOpTimeout)
	defer cancel()

	s.logger.Info("Inserting backup entry", "fw_id", fwID)
	if err := s.store.InsertBackup(ctx, fwID, timestamp, dbFilename); err != nil {
		return err
	}

	s.logger.Info("Querying existing backups", "fw_id", fwID)
	all, err := s.store.ListBackupFilenames(ctx, fwID)
	if err != nil {
		return err
	}
	s.logger.Info("Retrieved backups", "fw_id", fwID, "count", len(all))

	if len(all) > retentionCount {
		for _, dbName := range all[retentionCount:] {
			diskPath := filepath.FromSlash(filepath.Join(s.cfg.BackupDir, dbName))
			if _, statErr := os.Stat(diskPath); statErr == nil {
				if rmErr := os.Remove(diskPath); rmErr == nil {
					s.logger.Debug("Deleted file", "path", diskPath)
				} else {
					s.logger.Warn("Failed to delete retention file", "path", diskPath, "err", rmErr)
				}
			}
			if delErr := s.store.DeleteBackupByFilename(ctx, dbName); delErr != nil {
				return delErr
			}
		}
	}

	s.logger.Info("Cleaning non-existent backups", "fw_id", fwID)
	s.cleanNonexistentBackups(ctx, fwID, fwDir)
	s.logger.Info("Non-existent backups cleaned", "fw_id", fwID)

	s.logger.Info("Updating firewall status", "fw_id", fwID)
	if err := s.store.UpdateFirewallSuccess(ctx, fwID, timestamp, "Success"); err != nil {
		return err
	}
	return nil
}

// cleanNonexistentBackups removes database rows whose file no longer exists and
// deletes files on disk that have no corresponding database row. It mirrors the
// Python clean_nonexistent_backups helper and, like it, never fails the caller:
// all errors are logged and swallowed.
func (s *Service) cleanNonexistentBackups(ctx context.Context, fwID int, fwDir string) {
	s.logger.Info("Querying backups table", "fw_id", fwID)
	backups, err := s.store.ListBackupIDFilenames(ctx, fwID, 100)
	if err != nil {
		s.logger.Error("Failed to clean non-existent backups", "fw_id", fwID, "err", err)
		return
	}
	s.logger.Info("Retrieved backup entries", "fw_id", fwID, "count", len(backups))

	dbFilenames := make(map[string]struct{}, len(backups))
	for _, b := range backups {
		dbFilenames[b.Filename] = struct{}{}
	}

	// Remove database rows whose backing file is gone.
	for _, b := range backups {
		diskPath := filepath.FromSlash(filepath.Join(s.cfg.BackupDir, b.Filename))
		if _, statErr := os.Stat(diskPath); errors.Is(statErr, os.ErrNotExist) {
			s.logger.Warn("Removing non-existent backup entry", "filename", b.Filename)
			if delErr := s.store.DeleteBackupByID(ctx, b.ID); delErr != nil {
				s.logger.Error("Failed to remove backup entry", "id", b.ID, "err", delErr)
			}
		}
	}

	// Remove orphaned files that have no database row.
	s.logger.Info("Checking for orphaned files", "dir", fwDir)
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
		// The DB stores filenames with forward slashes, so build the relative
		// key the same way to compare.
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

// removeIfEmpty deletes the file at p only if it exists and is zero bytes,
// mirroring `if os.path.exists(p) and os.path.getsize(p) == 0: os.remove(p)`.
func removeIfEmpty(p string) {
	if info, err := os.Stat(p); err == nil && info.Size() == 0 {
		_ = os.Remove(p)
	}
}
