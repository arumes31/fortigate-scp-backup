package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// runningView is a firewall with a backup in flight, shaped for the template/JSON.
type runningView struct {
	FwID     int    `json:"fw_id"`
	FQDN     string `json:"fqdn"`
	SinceISO string `json:"since"`
}

// dashboardData is the full overview payload: DB health counts plus live
// operational metrics (storage, durations, next run, running backups).
type dashboardData struct {
	Base     BaseData
	Stats    models.DashboardStats
	Failures []models.Firewall
	Events   []models.ActivityLog // seed for the live SYS_STDOUT panel

	StorageBytes  int64
	StorageWeek   int64
	LargestBytes  int64
	SmallestBytes int64
	AvgDuration   string // human, e.g. "2.3s" or "—"
	BackupsRun    int64
	PrunedTotal   int64
	NextBackupISO string // RFC3339 (UTC) or "" when nothing is scheduled
	Running       []runningView
	ClusterAlert  bool
}

// clusterFailThreshold: a fleet-wide alert fires when at least this many
// firewalls are failing AND they are at least clusterFailRatio of the fleet.
const (
	clusterFailThreshold = 3
	clusterFailRatioPct  = 40
)

// computeDashboard gathers everything the overview page and its live JSON feed
// need. It never fails: individual lookup errors are logged and left at zero.
func (s *Server) computeDashboard(ctx context.Context) dashboardData {
	stats, err := s.store.DashboardStats(ctx)
	if err != nil {
		s.logger.Error("dashboard stats failed", "err", err)
	}
	failures, err := s.store.ListErrors(ctx)
	if err != nil {
		s.logger.Error("dashboard failures failed", "err", err)
	}
	fws, err := s.store.ListFirewalls(ctx)
	if err != nil {
		s.logger.Error("dashboard firewall list failed", "err", err)
	}

	fqdnByID := make(map[int]string, len(fws))
	var next time.Time
	for _, fw := range fws {
		fqdnByID[fw.ID] = fw.FQDN
		if info, ok := s.sched.Info(BackupJobID(fw.ID)); ok {
			if !info.NextRun.IsZero() && (next.IsZero() || info.NextRun.Before(next)) {
				next = info.NextRun
			}
		}
	}

	total, week, largest, smallest := backupStorageStats(s.cfg.BackupDir)

	running := make([]runningView, 0)
	for _, rb := range s.backup.Running() {
		running = append(running, runningView{
			FwID:     rb.FwID,
			FQDN:     fqdnByID[rb.FwID],
			SinceISO: rb.Since.UTC().Format(time.RFC3339),
		})
	}

	nextISO := ""
	if !next.IsZero() {
		nextISO = next.UTC().Format(time.RFC3339)
	}

	avg := "—"
	if d := s.backup.AvgBackupDuration(); d > 0 {
		avg = d.Round(100 * time.Millisecond).String()
	}

	// Seed the live log panel with the most recent activity entries.
	events, err := s.store.ListActivityLogs(ctx, 12, 0)
	if err != nil {
		s.logger.Error("dashboard activity seed failed", "err", err)
	}

	clusterAlert := stats.Failed >= clusterFailThreshold && stats.TotalFirewalls > 0 &&
		stats.Failed*100 >= stats.TotalFirewalls*clusterFailRatioPct

	return dashboardData{
		Stats:         stats,
		Failures:      failures,
		Events:        events,
		StorageBytes:  total,
		StorageWeek:   week,
		LargestBytes:  largest,
		SmallestBytes: smallest,
		AvgDuration:   avg,
		BackupsRun:    s.backup.BackupsRun(),
		PrunedTotal:   s.backup.PrunedTotal(),
		NextBackupISO: nextISO,
		Running:       running,
		ClusterAlert:  clusterAlert,
	}
}

// handleDashboard renders the overview page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := s.computeDashboard(r.Context())
	data.Base = s.base(r, "Dashboard", "dashboard")
	s.render(w, "dashboard.html", data)
}

// handleDashboardStats returns the live-updating subset as JSON so the dashboard
// can refresh tiles, the running list and the next-run countdown without a full
// page reload (driven by SSE events and the auto-refresh interval).
func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	d := s.computeDashboard(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total":         d.Stats.TotalFirewalls,
		"healthy":       d.Stats.Healthy,
		"failed":        d.Stats.Failed,
		"new":           d.Stats.New,
		"backups24h":    d.Stats.BackupsLast24h,
		"totalBackups":  d.Stats.TotalBackups,
		"storageBytes":  d.StorageBytes,
		"storageWeek":   d.StorageWeek,
		"largestBytes":  d.LargestBytes,
		"smallestBytes": d.SmallestBytes,
		"avgDuration":   d.AvgDuration,
		"backupsRun":    d.BackupsRun,
		"prunedTotal":   d.PrunedTotal,
		"nextBackup":    d.NextBackupISO,
		"clusterAlert":  d.ClusterAlert,
		"running":       d.Running,
	})
}

// handleRetryAllFailed enqueues a backup for every firewall whose last run
// failed, then returns to the dashboard.
func (s *Server) handleRetryAllFailed(w http.ResponseWriter, r *http.Request) {
	failures, err := s.store.ListErrors(r.Context())
	if err != nil {
		s.logger.Error("retry-all list errors failed", "err", err)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	for _, fw := range failures {
		s.backup.Enqueue(fw.ID)
	}
	s.store.LogActivity(s.sess.User(r).Username, "Retry All Failed",
		fmt.Sprintf("Triggered backups for %d failing firewalls", len(failures)))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// backupStorageStats walks the backup directory once and returns the total bytes
// used by .conf files, the bytes added in the last 7 days, and the largest and
// smallest single file. Sizes are on-disk (ciphertext when encryption at rest is
// enabled), which is what "storage used" means. A missing directory yields zeros.
func backupStorageStats(root string) (total, week, largest, smallest int64) {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	smallest = -1
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".conf") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		sz := info.Size()
		total += sz
		if info.ModTime().After(cutoff) {
			week += sz
		}
		if sz > largest {
			largest = sz
		}
		if smallest < 0 || sz < smallest {
			smallest = sz
		}
		return nil
	})
	if smallest < 0 {
		smallest = 0
	}
	return total, week, largest, smallest
}
