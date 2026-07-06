// Package backup implements the SSH/SCP backup engine: it pulls a FortiGate
// configuration file, stores it under BACKUP_DIR/<fw_id>/<timestamp>.conf,
// enforces retention, updates firewall status and emails on failure.
package backup

import (
	"log/slog"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
)

// Service performs firewall backups.
type Service struct {
	store  *database.Store
	mailer *mailer.Mailer
	cfg    *config.Config
	logger *slog.Logger
}

// New constructs a backup Service.
func New(store *database.Store, m *mailer.Mailer, cfg *config.Config, logger *slog.Logger) *Service {
	return &Service{store: store, mailer: m, cfg: cfg, logger: logger}
}

// Backup runs a single backup attempt cycle for the given firewall id. It is
// safe to call from the scheduler (recurring) or from the manual "Backup Now"
// handler (synchronous). Implemented in engine.go.
func (s *Service) Backup(fwID int) {
	s.backup(fwID)
}
