// Package models holds the plain data structures that mirror the rows of the
// shared PostgreSQL store. Column layouts intentionally match the original
// Python schema for drop-in database compatibility.
package models

// Firewall mirrors a row of the `firewalls` table.
type Firewall struct {
	ID             int
	FQDN           string
	Username       string
	Password       string
	IntervalMin    int
	RetentionCount int
	LastBackup     string // empty when NULL
	Status         string
	SSHPort        int
}

// Backup mirrors a row of the `backups` table.
type Backup struct {
	ID        int
	FwID      int
	Timestamp string
	Filename  string
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
	Timestamp string
}

// FirewallSchedule is the minimal projection used to (re)build backup jobs.
type FirewallSchedule struct {
	ID          int
	IntervalMin int
}

// FirewallRef is the minimal projection used by config search.
type FirewallRef struct {
	ID   int
	FQDN string
}
