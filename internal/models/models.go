// Package models holds the plain data structures that mirror the rows of the
// shared PostgreSQL store.
package models

import "time"

// Firewall mirrors a row of the `firewalls` table.
type Firewall struct {
	ID             int
	FQDN           string
	Username       string
	Password       string
	IntervalMin    int
	RetentionCount int
	LastBackup     time.Time // zero when NULL / never backed up
	Status         string
	SSHPort        int
	CronExpr       string // optional cron schedule (overrides IntervalMin)
}

// HasBackup reports whether the firewall has ever completed a backup.
func (f Firewall) HasBackup() bool { return !f.LastBackup.IsZero() }

// Backup mirrors a row of the `backups` table.
type Backup struct {
	ID        int
	FwID      int
	Timestamp time.Time
	Filename  string
	SizeBytes int64
	Checksum  string
}

// User mirrors a row of the `users` table.
type User struct {
	ID           int
	Username     string
	Password     string
	FirstLogin   int
	TOTPSecret   string // empty when NULL
	IsRadiusUser bool
}

// ActivityLog mirrors a row of the `activity_logs` table.
type ActivityLog struct {
	Username  string
	Action    string
	Details   string
	Timestamp time.Time
}

// FirewallSchedule is the minimal projection used to (re)build backup jobs.
type FirewallSchedule struct {
	ID          int
	IntervalMin int
	CronExpr    string
}

// DashboardStats summarises firewall/backup health for the overview page.
type DashboardStats struct {
	TotalFirewalls int
	Healthy        int
	Failed         int
	New            int
	BackupsLast24h int
	TotalBackups   int
}

// FirewallRef is the minimal projection used by config search.
type FirewallRef struct {
	ID   int
	FQDN string
}

// AuditFinding mirrors a row of the `audit_findings` table. The JSON tags are
// used by the insights audit cache (results_json) and the /audit/results API.
type AuditFinding struct {
	FwID           int    `json:"fw_id"`
	BackupFilename string `json:"backup_filename"`
	Severity       string `json:"severity"`
	Text           string `json:"text"` // canonical English text
	// TextDE is the German rendering of Text; the results API substitutes it
	// when the UI language is "de" (empty = English only, e.g. custom rules).
	TextDE      string `json:"text_de,omitempty"`
	Remediation string `json:"remediation"`

	// CheckID identifies the audit check that produced the finding (stable
	// across runs, e.g. "admin-no-2fa"). Empty for custom rules.
	CheckID string `json:"check_id,omitempty"`
	// Key is the stable instance key used for exemption matching: the CheckID
	// plus an object qualifier where one check can fire per object
	// (e.g. "admin-no-2fa:daniel"). Falls back to Text matching when empty.
	Key string `json:"key,omitempty"`
	// Line is the 1-based line number of the detected config statement
	// (0 when the finding has no single anchor line).
	Line int `json:"line,omitempty"`
	// Context holds the detected line ±3 lines (plus the enclosing block end)
	// for display; ContextStart is the 1-based number of its first line.
	Context      string `json:"context,omitempty"`
	ContextStart int    `json:"context_start,omitempty"`
}
