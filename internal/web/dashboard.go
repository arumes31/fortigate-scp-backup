package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	fgtadmvpnconf "github.com/arumes31/fortigate-scp-backup/extensions/fgt_adm_vpn_conf"
	fgtpolsplit "github.com/arumes31/fortigate-scp-backup/extensions/fgt_polsplit"
	graylogdevicedata "github.com/arumes31/fortigate-scp-backup/extensions/graylog_device_data"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// runningTracker registers in-flight per-firewall operations of one kind for
// the dashboard's "currently running" card. The zero value is ready to use;
// entries are keyed by sequence number so overlapping operations on the same
// firewall never clobber each other.
type runningTracker struct {
	mu  sync.Mutex
	seq int
	ops map[int]*trackedOp
}

type trackedOp struct {
	fwID    int
	started time.Time
	detail  string // current stage, shown on the running card
}

// track registers one operation and returns a note function (publishing the
// current stage) plus the function that removes the entry again (deferred by
// the caller).
func (t *runningTracker) track(fwID int) (note func(detail string), done func()) {
	t.mu.Lock()
	t.seq++
	id := t.seq
	if t.ops == nil {
		t.ops = map[int]*trackedOp{}
	}
	op := &trackedOp{fwID: fwID, started: time.Now()}
	t.ops[id] = op
	t.mu.Unlock()
	note = func(detail string) {
		t.mu.Lock()
		op.detail = detail
		t.mu.Unlock()
	}
	done = func() {
		t.mu.Lock()
		delete(t.ops, id)
		t.mu.Unlock()
	}
	return note, done
}

// list returns the in-flight operations, newest first.
func (t *runningTracker) list() []trackedOp {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]trackedOp, 0, len(t.ops))
	for _, op := range t.ops {
		out = append(out, *op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].started.After(out[j].started) })
	return out
}

// runningView is one in-flight operation for the "currently running" card: a
// firewall backup, or a polsplit analysis working through its Graylog queries.
type runningView struct {
	Kind     string `json:"kind"` // "backup" | "analysis" | "devicedata" | "sshdiag" | "audit" | "live"
	FwID     int    `json:"fw_id"`
	FQDN     string `json:"fqdn"`
	Label    string `json:"label,omitempty"`  // analysis: what runs ("Policy 162")
	Detail   string `json:"detail,omitempty"` // current stage text, e.g. "time step 5/24", "switch SW1"
	Step     int    `json:"step,omitempty"`   // progress within the stage (0 = no numeric progress)
	Total    int    `json:"total,omitempty"`
	SinceISO string `json:"since"`
}

// failureView is one currently-failing firewall for the dashboard's failing
// table: its last SUCCESSFUL backup (distinct from the last attempt) plus the
// error message, surfaced inline instead of only in a hover tooltip.
type failureView struct {
	ID          int
	FQDN        string
	LastSuccess time.Time // zero = never succeeded
	Error       string    // status with the "Failed:" prefix trimmed
}

// staleBackup is a firewall whose last successful backup is far older than its
// schedule would predict, yet is NOT currently reporting a failure — the
// silent-aging case a "Failed" status never catches (e.g. a scheduler entry
// that vanished). Ordered oldest-first.
type staleBackup struct {
	ID          int
	FQDN        string
	LastSuccess time.Time
	AgeHours    int    // whole hours since the last success, for display
	Overdue     string // human "expected every 6h" hint
}

// dashboardData is the full overview payload: DB health counts plus live
// operational metrics (storage, durations, next run, running backups).
type dashboardData struct {
	Base     BaseData
	Stats    models.DashboardStats
	Failures []failureView
	Stale    []staleBackup
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
	BlockedPorts  []blockedPortIssue
	GraylogIssues []graylogIssue
}

// blockedPortIssue is one switch port currently blocked by STP or a
// BPDU/loop/root guard, surfaced as a dashboard issue. The data comes from
// the graylog_device_data extension's store (empty when the extension is
// disabled or has not fetched yet).
type blockedPortIssue struct {
	FwID   int    `json:"fw_id"`
	FQDN   string `json:"fqdn"`
	Switch string `json:"switch"`
	Port   string `json:"port"`
	Reason string `json:"reason"` // guard kind, or STP state/role
	Since  string `json:"since,omitempty"`
}

// blockedPortIssues asks the graylog_device_data extension for the switch ports
// currently out of forwarding (STP block or BPDU/loop/root guard). The extension
// owns the storage; the dashboard only decorates each result with its firewall's
// FQDN. Any error (extension disabled, DB missing, old schema) yields an empty
// list — the dashboard renders fine without the card.
func (s *Server) blockedPortIssues(fqdnByID map[int]string) []blockedPortIssue {
	ports, err := graylogdevicedata.ListBlockedPorts(s.cfg.DataDir)
	if err != nil {
		s.logger.Warn("dashboard blocked-port lookup failed", "err", err)
		return nil
	}
	out := make([]blockedPortIssue, 0, len(ports))
	for _, p := range ports {
		out = append(out, blockedPortIssue{
			FwID:   p.FwID,
			FQDN:   fqdnByID[p.FwID],
			Switch: p.Switch,
			Port:   p.Port,
			Reason: p.Reason,
			Since:  p.Since,
		})
	}
	return out
}

// graylogIssue is one VPN device whose Graylog logging status is unhealthy,
// surfaced from the fgt_adm_vpn_conf extension (which tracks last_graylog_status
// per device). Empty when that extension is disabled or all devices are online.
type graylogIssue struct {
	Firewall  string `json:"firewall"`
	Site      string `json:"site,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
	Status    string `json:"status"` // offline | error | config_missing
	LastCheck string `json:"last_check,omitempty"`
}

// graylogIssues asks the fgt_adm_vpn_conf extension for devices whose Graylog
// logging status is not healthy. The extension owns the storage and the status
// worker; the dashboard only renders the result. Any error (extension disabled,
// DB missing) yields an empty list, so the card simply does not appear.
func (s *Server) graylogIssues() []graylogIssue {
	rows, err := fgtadmvpnconf.ListGraylogIssues(s.cfg.DataDir)
	if err != nil {
		s.logger.Warn("dashboard graylog-status lookup failed", "err", err)
		return nil
	}
	out := make([]graylogIssue, 0, len(rows))
	for _, r := range rows {
		out = append(out, graylogIssue{
			Firewall:  r.Firewall,
			Site:      r.Site,
			Cluster:   r.Cluster,
			Status:    r.Status,
			LastCheck: r.LastCheck,
		})
	}
	return out
}

// clusterFailThreshold: a fleet-wide alert fires when at least this many
// firewalls are failing AND they are at least clusterFailRatio of the fleet.
const (
	clusterFailThreshold = 3
	clusterFailRatioPct  = 40
)

// staleFloor is the minimum age before a backup is considered stale, so very
// frequent schedules (e.g. every 15 min) do not flag on a single missed run.
const staleFloor = 2 * time.Hour

// computeStale flags firewalls whose last successful backup is far older than
// their schedule predicts, excluding those already in a Failed state (shown in
// the failing table) and those never backed up (counted as New/Pending). The
// threshold is 2× the schedule's cadence, floored at staleFloor.
func (s *Server) computeStale(fws []models.Firewall, lastSuccess map[int]time.Time, failedSet map[int]bool) []staleBackup {
	now := time.Now()
	var out []staleBackup
	for _, fw := range fws {
		if failedSet[fw.ID] {
			continue // already surfaced in the failing table
		}
		last, ok := lastSuccess[fw.ID]
		if !ok || last.IsZero() {
			continue // never backed up → the New/Pending tile, not stale
		}
		// Effective cadence: prefer the scheduler's live value (handles cron),
		// fall back to the configured interval.
		interval := time.Duration(fw.IntervalMin) * time.Minute
		if info, ok := s.sched.Info(BackupJobID(fw.ID)); ok && info.Interval > 0 {
			interval = info.Interval
		}
		if interval <= 0 {
			continue // unscheduled → cannot judge staleness
		}
		threshold := 2 * interval
		if threshold < staleFloor {
			threshold = staleFloor
		}
		age := now.Sub(last)
		if age <= threshold {
			continue
		}
		out = append(out, staleBackup{
			ID:          fw.ID,
			FQDN:        fw.FQDN,
			LastSuccess: last,
			AgeHours:    int(age.Hours()),
			Overdue:     "expected every " + humanizeInterval(interval),
		})
	}
	// Oldest first: the most-overdue firewalls lead.
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSuccess.Before(out[j].LastSuccess) })
	return out
}

// humanizeInterval renders a cadence compactly ("15m", "6h", "1d").
func humanizeInterval(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", d/time.Hour)
	default:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
}

// computeDashboard gathers everything the overview page and its live JSON feed
// need. It never fails: individual lookup errors are logged and left at zero.
func (s *Server) computeDashboard(ctx context.Context) dashboardData {
	stats, err := s.store.DashboardStats(ctx)
	if err != nil {
		s.logger.Error("dashboard stats failed", "err", err)
	}
	failedFws, err := s.store.ListErrors(ctx)
	if err != nil {
		s.logger.Error("dashboard failures failed", "err", err)
	}
	fws, err := s.store.ListFirewalls(ctx)
	if err != nil {
		s.logger.Error("dashboard firewall list failed", "err", err)
	}
	// Last SUCCESSFUL backup per firewall (the backups table holds successes
	// only); powers the failing-table "last success" column and stale detection.
	lastSuccess, err := s.store.LastBackupTimes(ctx)
	if err != nil {
		s.logger.Error("dashboard last-backup times failed", "err", err)
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

	failedSet := make(map[int]bool, len(failedFws))
	failures := make([]failureView, 0, len(failedFws))
	for _, fw := range failedFws {
		failedSet[fw.ID] = true
		failures = append(failures, failureView{
			ID:          fw.ID,
			FQDN:        fw.FQDN,
			LastSuccess: lastSuccess[fw.ID],
			Error:       strings.TrimSpace(strings.TrimPrefix(fw.Status, "Failed:")),
		})
	}
	stale := s.computeStale(fws, lastSuccess, failedSet)

	total, week, largest, smallest := backupStorageStats(s.cfg.BackupDir)

	running := make([]runningView, 0)
	for _, rb := range s.backup.Running() {
		running = append(running, runningView{
			Kind:     "backup",
			FwID:     rb.FwID,
			FQDN:     fqdnByID[rb.FwID],
			Detail:   rb.Stage,
			SinceISO: rb.Since.UTC().Format(time.RFC3339),
		})
	}
	// In-flight polsplit analyses (Graylog query sequences) join the card so
	// long-running traffic analyses are visible fleet-wide, not only in the
	// browser tab that started them. Step/Total drive a progress bar; the
	// stage message and sub-detail form the text line.
	for _, ra := range fgtpolsplit.RunningAnalyses() {
		detail := ra.Message
		if ra.Detail != "" {
			detail += " — " + ra.Detail
		}
		running = append(running, runningView{
			Kind:     "analysis",
			FwID:     ra.FwID,
			FQDN:     fqdnByID[ra.FwID],
			Label:    fmt.Sprintf("Policy %d", ra.PolicyID),
			Detail:   detail,
			Step:     ra.Step,
			Total:    ra.Total,
			SinceISO: ra.Started.UTC().Format(time.RFC3339),
		})
	}
	// Topology device-data refreshes (Graylog sweeps) and live SSH diagnostics
	// from the graylog_device_data extension.
	for _, rf := range graylogdevicedata.RunningFetches() {
		running = append(running, runningView{
			Kind:     rf.Kind, // "devicedata" | "sshdiag" | "live"
			FwID:     rf.FwID,
			FQDN:     fqdnByID[rf.FwID],
			Detail:   rf.Detail,
			Step:     rf.Step,
			Total:    rf.Total,
			SinceISO: rf.Started.UTC().Format(time.RFC3339),
		})
	}
	// Audit recomputations (full config parses on cache miss or post-backup warm).
	for _, op := range s.auditRuns.list() {
		running = append(running, runningView{
			Kind:     "audit",
			FwID:     op.fwID,
			FQDN:     fqdnByID[op.fwID],
			Detail:   op.detail,
			SinceISO: op.started.UTC().Format(time.RFC3339),
		})
	}
	// One newest-first timeline regardless of which subsystem contributed the
	// entry (RFC3339 UTC timestamps sort lexicographically).
	sort.SliceStable(running, func(i, j int) bool { return running[i].SinceISO > running[j].SinceISO })

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
		Stale:         stale,
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
		BlockedPorts:  s.blockedPortIssues(fqdnByID),
		GraylogIssues: s.graylogIssues(),
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
		"blockedPorts":  d.BlockedPorts,
		"graylogIssues": d.GraylogIssues,
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
