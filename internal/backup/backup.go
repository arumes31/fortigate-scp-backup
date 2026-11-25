// Package backup implements the SSH/SCP backup engine: it pulls a FortiGate
// configuration file, stores it under BACKUP_DIR/<fw_id>/<timestamp>.conf
// (encrypted at rest), enforces retention, updates firewall status
// and emails on failure. A bounded worker pool caps how many firewalls are
// backed up concurrently.
package backup

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/mailer"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"golang.org/x/crypto/ssh"
)

// StatusHook is notified whenever a firewall's backup status changes, so the UI
// can update live (e.g. via SSE).
type StatusHook func(fwID int, status string)

// committedBackupGetter is supplementary to the core backup service: optional
// notification lookup failures must never affect successful backup persistence.
type committedBackupGetter interface {
	GetBackupByFilename(context.Context, int, string) (models.Backup, error)
}

const committedLookupTimeout = 2 * time.Second

// Service performs firewall backups.
type Service struct {
	store           *database.Store
	mailer          *mailer.Mailer
	cfg             *config.Config
	cipher          *crypto.Cipher
	encrypt         func([]byte) ([]byte, error)
	replaceFile     func(string, []byte) error
	logger          *slog.Logger
	hostKeyCallback ssh.HostKeyCallback

	sem                chan struct{}              // bounds concurrent backups (#28)
	hook               atomic.Pointer[StatusHook] // set once at startup, read from job goroutines
	queued             sync.Map                   // fwID(int) -> struct{}: a run is queued or running
	committedMu        sync.RWMutex
	committedObservers []func(models.Backup)
	committedGetter    committedBackupGetter

	// Live operational counters for the dashboard. All in-memory: they describe
	// activity since process start and reset on restart.
	running     sync.Map     // fwID(int) -> *runState: in-flight backups
	durTotalNs  atomic.Int64 // sum of completed run durations, nanoseconds
	durCount    atomic.Int64 // number of completed runs
	prunedTotal atomic.Int64 // retention-overflow files pruned since start
}

// runState tracks one in-flight backup for the dashboard: start time plus the
// live coarse stage the engine is currently in.
type runState struct {
	start time.Time
	mu    sync.Mutex
	stage string
}

// RunningBackup describes an in-flight backup for the dashboard "running now" view.
type RunningBackup struct {
	FwID  int
	Since time.Time
	Stage string // coarse engine stage ("downloading configuration (attempt 1/3)", …)
}

// Running returns the firewalls with a backup currently in flight.
func (s *Service) Running() []RunningBackup {
	var out []RunningBackup
	s.running.Range(func(k, v any) bool {
		st := v.(*runState)
		st.mu.Lock()
		stage := st.stage
		st.mu.Unlock()
		out = append(out, RunningBackup{FwID: k.(int), Since: st.start, Stage: stage})
		return true
	})
	return out
}

// setStage publishes the in-flight backup's current stage for the dashboard
// (no-op when the firewall is not tracked as running).
func (s *Service) setStage(fwID int, stage string) {
	if v, ok := s.running.Load(fwID); ok {
		st := v.(*runState)
		st.mu.Lock()
		st.stage = stage
		st.mu.Unlock()
	}
}

// AvgBackupDuration is the mean wall-clock duration of backup runs since start
// (0 when none have run yet).
func (s *Service) AvgBackupDuration() time.Duration {
	c := s.durCount.Load()
	if c == 0 {
		return 0
	}
	return time.Duration(s.durTotalNs.Load() / c)
}

// BackupsRun is the number of backup runs since process start.
func (s *Service) BackupsRun() int64 { return s.durCount.Load() }

// PrunedTotal is the number of retention-overflow files pruned since start.
func (s *Service) PrunedTotal() int64 { return s.prunedTotal.Load() }

// New constructs a backup Service with a concurrency limit.
func New(store *database.Store, m *mailer.Mailer, cfg *config.Config, cipher *crypto.Cipher, logger *slog.Logger) *Service {
	n := cfg.MaxConcurrentBackups
	if n < 1 {
		n = 1
	}
	var committedGetter committedBackupGetter
	if store != nil {
		committedGetter = store
	}
	return &Service{
		store:           store,
		mailer:          m,
		cfg:             cfg,
		cipher:          cipher,
		encrypt:         cipher.Encrypt,
		replaceFile:     replaceFileAtomic,
		logger:          logger,
		committedGetter: committedGetter,
		hostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return fmt.Errorf("SSH host key verification is not configured for %s", hostname)
		},
		sem: make(chan struct{}, n),
	}
}

// SetHostKeyCallback configures the verified host-key policy used by all
// backup and connection-test SSH clients. It must be called before use.
func (s *Service) SetHostKeyCallback(callback ssh.HostKeyCallback) {
	if callback != nil {
		s.hostKeyCallback = callback
	}
}

// SetStatusHook registers a callback invoked on every status transition. It is
// stored atomically because backup jobs (which read it via emit) may already be
// running by the time the web server wires up the hook.
func (s *Service) SetStatusHook(h StatusHook) { s.hook.Store(&h) }

// SubscribeBackup adds a committed-backup observer without replacing the UI
// status hook. Observers must enqueue work and return promptly; heavy work must
// run in their own bounded workers. Registration is safe during backup jobs.
func (s *Service) SubscribeBackup(observer func(models.Backup)) {
	if observer == nil {
		return
	}
	s.committedMu.Lock()
	s.committedObservers = append(s.committedObservers, observer)
	s.committedMu.Unlock()
}

// notifyCommitted isolates optional observers from a completed backup's status.
func (s *Service) notifyCommitted(b models.Backup) {
	if b.ID <= 0 || b.FwID <= 0 {
		return
	}
	s.committedMu.RLock()
	observers := append([]func(models.Backup){}, s.committedObservers...)
	s.committedMu.RUnlock()
	for _, observer := range observers {
		func() {
			defer func() {
				if recover() != nil {
					s.logger.Error("committed backup observer failed", "fw_id", b.FwID, "backup_id", b.ID)
				}
			}()
			observer(b)
		}()
	}
}

// publishCommitted looks up the exact inserted row, not a mutable latest row.
// Lookup failure leaves the backup successful; report startup/reconciliation
// can recover the missed event from the committed backup catalog.
func (s *Service) publishCommitted(fwID int, filename, checksum string) {
	s.committedMu.RLock()
	hasObservers := len(s.committedObservers) > 0
	s.committedMu.RUnlock()
	if !hasObservers || s.committedGetter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), committedLookupTimeout)
	defer cancel()
	b, err := s.committedGetter.GetBackupByFilename(ctx, fwID, filename)
	if err != nil {
		s.logger.Error("failed to read committed backup event", "fw_id", fwID)
		return
	}
	if b.FwID == fwID && b.Filename == filename && b.Checksum == checksum {
		s.notifyCommitted(b)
		return
	}
	s.logger.Warn("committed backup event row no longer available", "fw_id", fwID)
}

// claim marks a run for fwID as queued; it reports false when one is already
// queued or running, so repeated triggers coalesce instead of stacking full runs.
func (s *Service) claim(fwID int) bool {
	_, loaded := s.queued.LoadOrStore(fwID, struct{}{})
	return !loaded
}

// Backup runs a single backup cycle for the firewall, blocking until a worker
// slot is free. It is a no-op while another run for the same firewall is queued
// or running, so a manual "Backup Now" cannot collide with a scheduled run on
// the same timestamped file. Safe to call from the scheduler (already in its own
// goroutine).
func (s *Service) Backup(fwID int) {
	if !s.claim(fwID) {
		s.logger.Info("Backup already queued or running, skipping", "fw_id", fwID)
		return
	}
	s.run(fwID)
}

// run performs a claimed backup and releases the claim when done.
func (s *Service) run(fwID int) {
	defer s.queued.Delete(fwID)
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	start := time.Now()
	s.running.Store(fwID, &runState{start: start})
	defer func() {
		s.running.Delete(fwID)
		s.durTotalNs.Add(int64(time.Since(start)))
		s.durCount.Add(1)
	}()
	s.backup(fwID)
}

// Enqueue triggers an asynchronous backup and returns immediately, marking the
// firewall as in progress. Used by the manual "Backup Now" handler. Claiming
// before writing the status keeps a duplicate click from re-marking a run that
// is just finishing as "In Progress".
func (s *Service) Enqueue(fwID int) {
	if !s.claim(fwID) {
		s.logger.Info("Backup already queued or running, skipping", "fw_id", fwID)
		return
	}
	s.persistStatus(fwID, "In Progress")
	go s.run(fwID)
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
	if h := s.hook.Load(); h != nil {
		(*h)(fwID, status)
	}
}
