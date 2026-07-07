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
