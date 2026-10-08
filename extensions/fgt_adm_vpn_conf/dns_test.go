package fgtadmvpnconf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// stubResolver returns a lookupHost func serving fixed answers per hostname
// and counting calls, so tests can assert both results and cadence skips.
func stubResolver(calls map[string]int) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, host string) ([]string, error) {
		if calls != nil {
			calls[host]++
		}
		switch host {
		case "good.adm.example":
			return []string{"10.105.1.1"}, nil
		case "multi.adm.example":
			return []string{"192.0.2.7", "2001:db8::1", "10.105.1.1"}, nil
		case "wrong.adm.example":
			return []string{"10.105.1.99"}, nil
		case "gone.adm.example":
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		case "timeout.adm.example":
			return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
		case "empty.adm.example":
			return []string{}, nil
		}
		return nil, errors.New("unexpected lookup: " + host)
	}
}

func TestComputeDNSStatus(t *testing.T) {
	e := &Extension{lookupHost: stubResolver(nil)}
	cases := []struct {
		name, dnsName, remoteIP string
		wantStatus, wantResolve string
	}{
		{"match", "good.adm.example", "10.105.1.1", dnsStatusOK, "10.105.1.1"},
		{"multi-record any-match", "multi.adm.example", "10.105.1.1", dnsStatusOK, "192.0.2.7, 2001:db8::1, 10.105.1.1"},
		{"wrong ip", "wrong.adm.example", "10.105.1.1", dnsStatusMismatch, "10.105.1.99"},
		{"nxdomain", "gone.adm.example", "10.105.1.1", dnsStatusUnresolved, ""},
		{"resolver timeout", "timeout.adm.example", "10.105.1.1", dnsStatusError, ""},
		{"generic resolver error", "other.adm.example", "10.105.1.1", dnsStatusError, ""},
		{"empty answer", "empty.adm.example", "10.105.1.1", dnsStatusUnresolved, ""},
		{"no dns name", "", "10.105.1.1", dnsStatusUnknown, ""},
		{"no expected ip", "good.adm.example", "", dnsStatusUnknown, ""},
		{"invalid expected ip", "good.adm.example", "not-an-ip", dnsStatusUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, resolved := e.computeDNSStatus(&VpnConfig{DnsNameFull: c.dnsName, RemoteipFull: c.remoteIP})
			if status != c.wantStatus || resolved != c.wantResolve {
				t.Errorf("got (%q, %q), want (%q, %q)", status, resolved, c.wantStatus, c.wantResolve)
			}
		})
	}
}

func TestDnsCheckDue(t *testing.T) {
	now := time.Now().UTC()
	at := func(ago time.Duration) *time.Time { tt := now.Add(-ago); return &tt }
	cases := []struct {
		name    string
		status  string
		checked *time.Time
		want    bool
	}{
		{"never checked", dnsStatusUnknown, nil, true},
		{"ok fresh", dnsStatusOK, at(time.Hour), false},
		{"ok almost due", dnsStatusOK, at(23 * time.Hour), false},
		{"ok due", dnsStatusOK, at(25 * time.Hour), true},
		{"mismatch fresh", dnsStatusMismatch, at(5 * time.Minute), false},
		{"mismatch due", dnsStatusMismatch, at(11 * time.Minute), true},
		{"unresolved due", dnsStatusUnresolved, at(11 * time.Minute), true},
		{"error due", dnsStatusError, at(11 * time.Minute), true},
		{"unknown due", dnsStatusUnknown, at(11 * time.Minute), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dnsCheckDue(&VpnConfig{LastDnsStatus: c.status, LastDnsCheck: c.checked}, now)
			if got != c.want {
				t.Errorf("due = %v, want %v", got, c.want)
			}
		})
	}
}

func TestUpdateDNSStatusDiscardsStaleEndpointResult(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}

	result, err := db.Exec(
		`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname, cid,
		 dns_name_full, last_dns_status, last_dns_resolved)
		 VALUES ('cust', 'site', '10.105.1.1', 'fw-a', '123', 'old.adm.example', 'unknown', '')`,
	)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`UPDATE vpn_config
		 SET dns_name_full = 'new.adm.example', remoteip_full = '10.105.1.2'
		 WHERE id = ?`,
		id,
	); err != nil {
		t.Fatal(err)
	}

	e := &Extension{db: db}
	checkedAt := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	if err := e.updateDNSStatus(
		id,
		"old.adm.example",
		"10.105.1.1",
		checkedAt,
		dnsStatusMismatch,
		"10.105.1.99",
	); err != nil {
		t.Fatal(err)
	}

	var status, resolved string
	var lastCheck any
	if err := db.QueryRow(
		`SELECT last_dns_status, last_dns_resolved, last_dns_check FROM vpn_config WHERE id = ?`,
		id,
	).Scan(&status, &resolved, &lastCheck); err != nil {
		t.Fatal(err)
	}
	if status != dnsStatusUnknown || resolved != "" || lastCheck != nil {
		t.Fatalf("stale result was persisted: status=%q resolved=%q checked=%v", status, resolved, lastCheck)
	}

	if err := e.updateDNSStatus(
		id,
		"new.adm.example",
		"10.105.1.2",
		checkedAt,
		dnsStatusOK,
		"10.105.1.2",
	); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(
		`SELECT last_dns_status, last_dns_resolved FROM vpn_config WHERE id = ?`,
		id,
	).Scan(&status, &resolved); err != nil {
		t.Fatal(err)
	}
	if status != dnsStatusOK || resolved != "10.105.1.2" {
		t.Fatalf("matching result was not persisted: status=%q resolved=%q", status, resolved)
	}
}

// TestDNSSweep verifies one pass over the table: due devices are re-checked
// per their status cadence (24h for ok, 10min otherwise), fresh ones are
// skipped without a lookup, and rows with nothing to validate are reset to
// unknown.
func TestDNSSweep(t *testing.T) {
	dataDir := t.TempDir()
	db, err := openDB(filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	rows := []struct {
		fw, dnsName, status string
		checkedAgo          time.Duration // 0 = never checked
		wantStatus          string
		wantLookups         int
	}{
		{"never-checked", "good.adm.example", "unknown", 0, dnsStatusOK, 1},
		{"ok-fresh", "fresh.adm.example", "ok", time.Hour, dnsStatusOK, 0},
		{"ok-stale", "wrong.adm.example", "ok", 25 * time.Hour, dnsStatusMismatch, 1},
		{"bad-fresh", "wrong.adm.example2", "mismatch", 5 * time.Minute, dnsStatusMismatch, 0},
		{"bad-due", "gone.adm.example", "mismatch", 11 * time.Minute, dnsStatusUnresolved, 1},
		{"no-dns-name", "", "mismatch", 11 * time.Minute, dnsStatusUnknown, 0},
	}
	for i, r := range rows {
		var checked any
		if r.checkedAgo != 0 {
			checked = formatDBTime(now.Add(-r.checkedAgo))
		}
		if _, err := db.Exec(
			`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname, cid,
			 dns_name_full, last_dns_status, last_dns_check)
			 VALUES ('cust', 'site', ?, ?, '123', ?, ?, ?)`,
			// ok-stale expects mismatch: its record points at 10.105.1.99, not this IP.
			fmt.Sprintf("10.105.1.%d", i+1), r.fw, r.dnsName, r.status, checked); err != nil {
			t.Fatalf("insert %s: %v", r.fw, err)
		}
	}

	calls := map[string]int{}
	e := &Extension{db: db, logger: slog.New(slog.DiscardHandler), lookupHost: stubResolver(calls)}
	if err := e.dnsSweep(); err != nil {
		t.Fatalf("dnsSweep: %v", err)
	}

	for _, r := range rows {
		var status string
		if err := db.QueryRow(`SELECT COALESCE(last_dns_status,'') FROM vpn_config WHERE firewallname = ?`, r.fw).Scan(&status); err != nil {
			t.Fatalf("select %s: %v", r.fw, err)
		}
		if status != r.wantStatus {
			t.Errorf("%s: status = %q, want %q", r.fw, status, r.wantStatus)
		}
		if r.dnsName != "" && calls[r.dnsName] != r.wantLookups {
			t.Errorf("%s: lookups = %d, want %d", r.fw, calls[r.dnsName], r.wantLookups)
		}
	}
}

// TestListDNSIssues verifies the dashboard projection lists exactly the
// actionable statuses (mismatch/unresolved) — not ok/error/unknown — and that
// a missing database yields (nil, nil).
func TestListDNSIssues(t *testing.T) {
	if issues, err := ListDNSIssues(t.TempDir()); err != nil || issues != nil {
		t.Fatalf("missing DB: got (%v, %v), want (nil, nil)", issues, err)
	}

	dataDir := t.TempDir()
	db, err := openDB(filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		fw, status, resolved string
		wantListed           bool
	}{
		{"dns-ok", "ok", "10.105.1.1", false},
		{"dns-wrong-ip", "mismatch", "10.105.1.99", true},
		{"dns-no-record", "unresolved", "", true},
		{"dns-resolver-error", "error", "", false}, // infra blip, not actionable
		{"dns-unknown", "unknown", "", false},
	}
	for i, c := range cases {
		if _, err := db.Exec(
			`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname, cid,
			 dns_name_full, last_dns_status, last_dns_resolved, last_dns_check)
			 VALUES ('cust', '', ?, ?, '123', ?, ?, ?, ?)`,
			fmt.Sprintf("10.105.1.%d", 10+i), c.fw, c.fw+".adm.example", c.status, c.resolved,
			formatDBTime(time.Now().UTC())); err != nil {
			t.Fatalf("insert %s: %v", c.fw, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	issues, err := ListDNSIssues(dataDir)
	if err != nil {
		t.Fatalf("ListDNSIssues: %v", err)
	}
	got := map[string]DNSIssue{}
	for _, is := range issues {
		got[is.Firewall] = is
	}
	for _, c := range cases {
		_, listed := got[c.fw]
		if listed != c.wantListed {
			t.Errorf("device %q listed=%v, want %v", c.fw, listed, c.wantListed)
		}
	}
	if is := got["dns-wrong-ip"]; is.Resolved != "10.105.1.99" || is.Expected == "" || is.DNSName == "" {
		t.Errorf("mismatch row missing detail: %+v", is)
	}
	// Standort is blank in the fixtures, so Site must fall back to Kundenname.
	if is := got["dns-no-record"]; is.Site != "cust" {
		t.Errorf("site fallback = %q, want %q", is.Site, "cust")
	}
}
