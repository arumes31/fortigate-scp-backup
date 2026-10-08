package web

import (
	"testing"
	"time"
)

func TestDashboardAttentionPrioritizesAndLimitsItems(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	failures := []failureView{
		{ID: 1, FQDN: "newer-failure", LastSuccess: now.Add(-2 * time.Hour), Error: "timeout"},
		{ID: 2, FQDN: "never-succeeded", Error: "authentication failed"},
	}
	stale := []staleBackup{{ID: 3, FQDN: "stale", LastSuccess: now.Add(-48 * time.Hour), Cadence: "6h"}}
	blocked := []blockedPortIssue{{FwID: 4, FQDN: "blocked", Switch: "sw1", Port: "port2", Reason: "loop guard", Since: now.Add(-4 * time.Hour).Format(time.RFC3339)}}
	graylog := []graylogIssue{{Firewall: "logging", Status: "offline", LastCheckTime: now.Add(-time.Hour)}}
	dns := []dnsIssue{{Firewall: "dns", DNSName: "vpn.example", Status: "mismatch", LastCheckTime: now.Add(-3 * time.Hour)}}
	licenses := []licenseIssue{{FwID: 7, FQDN: "license", Service: "FortiCare", Expiry: "2026-09-10", DaysLeft: 6, Level: "warn"}}

	items, remaining, total := buildDashboardAttention(now, failures, stale, blocked, graylog, dns, licenses)
	if len(items) != dashboardAttentionLimit || remaining != 2 || total != 7 {
		t.Fatalf("queue = %d items, %d remaining, %d total", len(items), remaining, total)
	}
	if items[0].Title != "never-succeeded" || items[0].Severity != "Critical" {
		t.Fatalf("first item = %#v, want oldest critical failure", items[0])
	}
	for _, item := range items {
		if item.Source == "" || item.Severity == "" || item.Age == "" || item.Action == "" || item.Href == "" {
			t.Errorf("incomplete attention item: %#v", item)
		}
	}
	if items[3].Severity != "Critical" || items[4].Severity != "Warning" {
		t.Fatalf("critical items must sort before warnings: %#v", items)
	}
}

func TestDashboardAttentionAge(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		at   time.Time
		want string
	}{
		{name: "unknown", want: "Unknown"},
		{name: "minutes", at: now.Add(-12 * time.Minute), want: "12m"},
		{name: "hours", at: now.Add(-8 * time.Hour), want: "8h"},
		{name: "days", at: now.Add(-49 * time.Hour), want: "2d"},
		{name: "future", at: now.Add(30 * time.Hour), want: "in 2d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dashboardAttentionAge(now, tc.at); got != tc.want {
				t.Fatalf("age = %q, want %q", got, tc.want)
			}
		})
	}
}
