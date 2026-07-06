// Package backup implements the SSH/SCP backup engine: it pulls a FortiGate
// configuration file, stores it under BACKUP_DIR/<fw_id>/<timestamp>.conf
// (optionally encrypted at rest), enforces retention, updates firewall status
// and emails on failure. A bounded worker pool caps how many firewalls are
// backed up concurrently.
package backup

import (
	"context"
	"log/slog"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
)

// StatusHook is notified whenever a firewall's backup status changes, so the UI
// can update live (e.g. via SSE).
type StatusHook func(fwID int, status string)

// Service performs firewall backups.
type Service struct {
	store  *database.Store
	mailer *mailer.Mailer
	cfg    *config.Config
	cipher *crypto.Cipher
	logger *slog.Logger

	sem  chan struct{} // bounds concurrent backups (#28)
	hook StatusHook
}

// New constructs a backup Service with a concurrency limit.
func New(store *database.Store, m *mailer.Mailer, cfg *config.Config, cipher *crypto.Cipher, logger *slog.Logger) *Service {
	n := cfg.MaxConcurrentBackups
	if n < 1 {
		n = 1
	}
	return &Service{
		store:  store,
		mailer: m,
		cfg:    cfg,
		cipher: cipher,
		logger: logger,
		sem:    make(chan struct{}, n),
	}
}

// SetStatusHook registers a callback invoked on every status transition.
func (s *Service) SetStatusHook(h StatusHook) { s.hook = h }

// Backup runs a single backup cycle for the firewall, blocking until a worker
// slot is free. Safe to call from the scheduler (already in its own goroutine).
func (s *Service) Backup(fwID int) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	s.backup(fwID)
}

// Enqueue triggers an asynchronous backup and returns immediately, marking the
// firewall as in progress. Used by the manual "Backup Now" handler.
func (s *Service) Enqueue(fwID int) {
	s.persistStatus(fwID, "In Progress")
	go s.Backup(fwID)
}

// persistStatus writes a status to the store and notifies the hook (best effort).
func (s *Service) persistStatus(fwID int, status string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.UpdateFirewallStatus(ctx, fwID, status); err != nil {
		s.logger.Error("failed to persist status", "fw_id", fwID, "status", status, "err", err)
	}
	s.emit(fwID, status)
}

// emit notifies the status hook (if any).
func (s *Service) emit(fwID int, status string) {
	if s.hook != nil {
		s.hook(fwID, status)
	}
}
