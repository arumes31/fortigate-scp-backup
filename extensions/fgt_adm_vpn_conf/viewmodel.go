package fgtadmvpnconf

import "time"

type configRow struct {
	ID                 int64
	Kundenname         string
	Standort           string
	RemoteipFull       string
	RemoteipFull1st    string
	Ike2Username       string
	WanInterface       string
	LanInterface       string
	DnsNameFull        string
	Firewallname       string
	Cid                string
	Radiusmgt          string
	GraylogEnabled     bool
	ClusterHostnames   string
	LastGraylogStatus  string
	LastGraylogDisplay string
	LastGraylogISO     string
	NextCheckISO       string
	LastDnsStatus      string
	LastDnsResolved    string
	LastDnsDisplay     string
	LastDnsISO         string
	HealthState        string
	HealthLabel        string
	HealthSummary      string
	GraylogEvidence    string
	DnsEvidence        string
	LastCheckDisplay   string
	LastCheckISO       string
}

func makeConfigRow(c *VpnConfig, location *time.Location) configRow {
	if location == nil {
		location = time.UTC
	}
	graylogDisplay, graylogISO := formatConfigCheck(c.LastGraylogCheck, location)
	dnsDisplay, dnsISO := formatConfigCheck(c.LastDnsCheck, location)
	lastCheck := latestConfigCheck(c.LastGraylogCheck, c.LastDnsCheck)
	lastDisplay, lastISO := formatConfigCheck(lastCheck, location)
	graylogEvidence, graylogState := graylogHealthEvidence(c)
	dnsEvidence, dnsState := dnsHealthEvidence(c.LastDnsStatus)
	healthState, healthLabel := combinedConfigHealth(graylogState, dnsState)
	nextCheckISO := ""
	if c.GraylogEnabled {
		if nextCheck := c.NextGraylogCheck(); nextCheck != nil {
			nextCheckISO = nextCheck.UTC().Format(time.RFC3339)
		}
	}
	return configRow{
		ID: c.ID, Kundenname: c.Kundenname, Standort: c.Standort,
		RemoteipFull: c.RemoteipFull, RemoteipFull1st: c.RemoteipFull1st,
		Ike2Username: c.Ike2Username, WanInterface: c.WanInterface, LanInterface: c.LanInterface,
		DnsNameFull: c.DnsNameFull, Firewallname: c.Firewallname, Cid: c.Cid,
		Radiusmgt: c.Radiusmgt, GraylogEnabled: c.GraylogEnabled,
		ClusterHostnames: c.ClusterHostnames, LastGraylogStatus: c.LastGraylogStatus,
		LastGraylogDisplay: graylogDisplay, LastGraylogISO: graylogISO, NextCheckISO: nextCheckISO,
		LastDnsStatus: c.LastDnsStatus, LastDnsResolved: c.LastDnsResolved,
		LastDnsDisplay: dnsDisplay, LastDnsISO: dnsISO,
		HealthState: healthState, HealthLabel: healthLabel,
		HealthSummary:   graylogEvidence + " · " + dnsEvidence,
		GraylogEvidence: graylogEvidence, DnsEvidence: dnsEvidence,
		LastCheckDisplay: lastDisplay, LastCheckISO: lastISO,
	}
}

func formatConfigCheck(check *time.Time, location *time.Location) (display, machine string) {
	if check == nil || check.IsZero() {
		return "Not checked", ""
	}
	return check.In(location).Format("2006-01-02 15:04 MST"), check.UTC().Format(time.RFC3339)
}

func latestConfigCheck(checks ...*time.Time) *time.Time {
	var latest *time.Time
	for _, check := range checks {
		if check != nil && !check.IsZero() && (latest == nil || check.After(*latest)) {
			copy := *check
			latest = &copy
		}
	}
	return latest
}

func graylogHealthEvidence(c *VpnConfig) (label, state string) {
	if !c.GraylogEnabled || c.LastGraylogStatus == "disabled" {
		return "Graylog disabled", "disabled"
	}
	switch c.LastGraylogStatus {
	case "online":
		return "Graylog online", "healthy"
	case "offline":
		return "Graylog offline", "failed"
	case "config_missing":
		return "Graylog not configured", "failed"
	case "error":
		return "Graylog check failed", "failed"
	default:
		return "Graylog not checked", "unknown"
	}
}

func dnsHealthEvidence(status string) (label, state string) {
	switch status {
	case "ok":
		return "DNS verified", "healthy"
	case "mismatch":
		return "DNS mismatch", "failed"
	case "unresolved":
		return "DNS unresolved", "failed"
	case "error":
		return "DNS check failed", "failed"
	default:
		return "DNS not checked", "unknown"
	}
}

func combinedConfigHealth(graylogState, dnsState string) (state, label string) {
	if graylogState == "failed" || dnsState == "failed" {
		return "failed", "Attention"
	}
	if graylogState == "disabled" {
		return "warning", "Partial coverage"
	}
	if graylogState == "healthy" && dnsState == "healthy" {
		return "healthy", "Checks pass"
	}
	return "unknown", "Checks pending"
}
