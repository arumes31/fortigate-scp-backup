package fgtadmvpnconf

import (
	"bytes"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIndexTemplateRenders parses the embedded templates and renders the index
// with one row, guarding the delete-confirmation modal markup against template
// syntax/field mistakes (the extension templates are not exercised elsewhere).
func TestIndexTemplateRenders(t *testing.T) {
	e := &Extension{}
	if err := e.parseTemplates(); err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	data := indexData{
		Configs:                []configRow{{VpnConfig: &VpnConfig{ID: 1, Firewallname: "acme-hq", Radiusmgt: "YES"}}},
		AvailableIPsCount:      5,
		AvailableIPsPercentage: "50.00",
	}
	var buf bytes.Buffer
	if err := e.tmpl.ExecuteTemplate(&buf, indexTemplate, data); err != nil {
		t.Fatalf("execute index: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"open-remove-modal", "removeConfirmCheck", "removal_commands"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered index missing %q", want)
		}
	}
}

func TestGetRandomPassword(t *testing.T) {
	pw := getRandomPassword(34, 4, 4, 2, 2)
	if len(pw) != 34 {
		t.Fatalf("length = %d, want 34", len(pw))
	}
	var upper, lower, digit, special int
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		case r == '!' || r == '#':
			special++
		}
	}
	if upper < 4 || lower < 4 || digit < 2 || special < 2 {
		t.Fatalf("composition too weak: U=%d L=%d D=%d S=%d", upper, lower, digit, special)
	}
}

func TestSplitHostnames(t *testing.T) {
	got := splitHostnames(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(splitHostnames("")) != 0 {
		t.Fatal("empty should yield no hostnames")
	}
}

func TestEscapeGraylogValue(t *testing.T) {
	if got := escapeGraylogValue(`a"b\c`); got != `a\"b\\c` {
		t.Fatalf("got %q", got)
	}
}

func TestContainsStr(t *testing.T) {
	if !containsStr([]string{"a", "error", "b"}, "error") {
		t.Fatal("should find error")
	}
	if containsStr([]string{"a"}, "z") {
		t.Fatal("should not find z")
	}
}

func TestBuildRemovalCommands(t *testing.T) {
	base := VpnConfig{
		Kundenname:   "acme",
		Standort:     "hq",
		Ike2Username: "vpn-adm-acme-hq",
		RemoteipFull: "10.105.1.5",
		DnsNameFull:  "fgt-acme-hq.adm.eworx.at",
	}

	// RADIUS enabled: the RO + HCI/RADIUS objects must all be present.
	yes := base
	yes.Radiusmgt = "YES"
	out := buildRemovalCommands(&yes)
	for _, want := range []string{
		`delete "VPN_EX-ADMRO"`,
		`delete "VPN_EX-ADMHCI"`,
		`delete "RAD-EXADM-1stlvl_1"`,
		`delete "sg-ADM_FGT_Auth_2nd-Level"`,
		`delete "LB-EXADM"`,
		`delete "vpn-adm-acme-hq"`,
		`delete "VPN_ADM_acme-hq_1st"`,
		"config firewall policy",
		"RZP / HCI firewall",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("radius=YES output missing %q", want)
		}
	}
	// phase2 must be deleted before phase1 (dependency order).
	if strings.Index(out, `delete "VPN_EX-ADMRO-1st"`) > strings.Index(out, `delete "VPN_EX-ADMRO"`) {
		t.Error("phase2 must be listed before phase1")
	}

	// RADIUS disabled: no HCI/RADIUS objects, but the RO tunnel + local user stay.
	no := base
	no.Radiusmgt = "NO"
	out = buildRemovalCommands(&no)
	for _, absent := range []string{
		`delete "VPN_EX-ADMHCI"`,
		`delete "RAD-EXADM-1stlvl_1"`,
		"RZP / HCI firewall",
		"config firewall policy",
	} {
		if strings.Contains(out, absent) {
			t.Errorf("radius=NO output should not contain %q", absent)
		}
	}
	for _, want := range []string{`delete "VPN_EX-ADMRO"`, `delete "vpn-adm-acme-hq"`, `delete "LB-EXADM"`} {
		if !strings.Contains(out, want) {
			t.Errorf("radius=NO output missing %q", want)
		}
	}
}

// TestListGraylogIssuesFiltersByAge verifies the dashboard card only lists
// devices that have been unhealthy for at least graylogIssueMinAge (24h),
// matching the alert threshold, and excludes recent/healthy/streak-unknown rows.
func TestListGraylogIssuesFiltersByAge(t *testing.T) {
	dataDir := t.TempDir()
	db, err := openDB(filepath.Join(dataDir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	old := formatDBTime(now.Add(-25 * time.Hour))
	recent := formatDBTime(now.Add(-1 * time.Hour))

	cases := []struct {
		fw, status, since string
		enabled           int
		wantListed        bool
	}{
		{"old-offline", "offline", old, 1, true},           // unhealthy > 24h
		{"old-error", "error", old, 1, true},               // any unhealthy state counts
		{"recent-offline", "offline", recent, 1, false},    // unhealthy < 24h
		{"online", "online", "", 1, false},                 // healthy
		{"unhealthy-no-streak", "offline", "", 1, false},   // streak start unknown
		{"disabled-old-offline", "offline", old, 0, false}, // graylog disabled
	}
	for i, c := range cases {
		var since any
		if c.since != "" {
			since = c.since
		}
		if _, err := db.Exec(
			`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname, cid,
			 graylog_enabled, last_graylog_status, graylog_unhealthy_since)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			"cust", "site", fmt.Sprintf("10.105.1.%d", i+1), c.fw, "123",
			c.enabled, c.status, since); err != nil {
			t.Fatalf("insert %s: %v", c.fw, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	issues, err := ListGraylogIssues(dataDir)
	if err != nil {
		t.Fatalf("ListGraylogIssues: %v", err)
	}
	got := map[string]bool{}
	for _, is := range issues {
		got[is.Firewall] = true
	}
	for _, c := range cases {
		if got[c.fw] != c.wantListed {
			t.Errorf("device %q listed=%v, want %v", c.fw, got[c.fw], c.wantListed)
		}
	}
}

// TestMigrations verifies a legacy database (missing the newer columns) is
// migrated in place and the cid backfill runs (#91).
func TestMigrations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Old-shape table: no cid / graylog_enabled / cluster_hostnames /
	// last_graylog_status / last_graylog_check.
	_, err = db.Exec(`CREATE TABLE vpn_config (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kundenname VARCHAR(100), standort VARCHAR(100),
		remoteip_full VARCHAR(100) UNIQUE, firewallname VARCHAR(100) UNIQUE)`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vpn_config (kundenname, standort, remoteip_full, firewallname)
		VALUES ('acme','hq','10.105.1.1','acme-hq')`); err != nil {
		t.Fatal(err)
	}

	e := &Extension{db: db, logger: slog.New(slog.DiscardHandler), logActivity: func(string, string, string) {}}
	if err := e.ensureMigrations(); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Newer columns must now be selectable.
	for _, col := range []string{"cid", "graylog_enabled", "cluster_hostnames", "last_graylog_status", "last_graylog_check", "graylog_unhealthy_since"} {
		if !columnExists(db, col) {
			t.Errorf("column %q missing after migration", col)
		}
	}
	// cid must be backfilled from firewallname.
	var cid string
	if err := db.QueryRow(`SELECT cid FROM vpn_config WHERE firewallname='acme-hq'`).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(cid) == "" {
		t.Fatal("cid should have been backfilled")
	}
}
