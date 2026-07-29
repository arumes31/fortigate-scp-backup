package web

import (
	"testing"
	"time"
)

// Fixtures are modeled on real FortiOS 7.6 output (captured 2026-07-29) with
// serial/hostname replaced by test placeholders.

const sysStatusFixture = "FGT90G-TEST-N1(Primary) $ Version: FortiGate-90G v7.6.7,build3704,260601 (GA.M)\r\n" +
	"First GA patch build date: 240724\r\n" +
	"FortiCare Registration Level: Enforce\r\n" +
	"Virus-DB: 1.00000(2018-04-09 18:07)\r\n" +
	"Serial-Number: FGT90GTEST0000001\r\n" +
	"BIOS version: 06000201\r\n" +
	"Hostname: FGT90G-TEST-N1\r\n" +
	"Operation Mode: NAT\r\n" +
	"Current virtual domain: root\r\n" +
	"Current HA mode: a-p, primary\r\n" +
	"Branch point: 3704\r\n" +
	"System time: Wed Jul 29 15:26:00 2026\r\n"

func TestParseSystemStatus(t *testing.T) {
	st := parseSystemStatus(sysStatusFixture)
	want := licenseStatus{
		Serial: "FGT90GTEST0000001", Hostname: "FGT90G-TEST-N1",
		Model: "FortiGate-90G", Version: "7.6.7", Build: "3704",
		Registration: "Enforce", HAMode: "a-p, primary", OpMode: "NAT",
	}
	if st != want {
		t.Errorf("parseSystemStatus:\n got %+v\nwant %+v", st, want)
	}
}

const autoupdateFixture = "FGT90G-TEST-N1(Primary) $ \r\n" +
	"\r\n" +
	"AV Engine\r\n" +
	"---------\r\n" +
	"Version: 7.00054 signed\r\n" +
	"Contract Expiry Date: Sat Apr 24 2027\r\n" +
	"Last Updated using manual update on Tue Apr 14 22:14:00 2026\r\n" +
	"Last Update Attempt: n/a\r\n" +
	"Result: Updates Installed\r\n" +
	"\r\n" +
	"Attack Definitions\r\n" +
	"---------\r\n" +
	"Version: 37.00262 signed\r\n" +
	"Contract Expiry Date: Mon Mar  1 2027\r\n" +
	"Last Updated using scheduled update on Wed Jul 29 02:31:04 2026\r\n" +
	"Last Update Attempt: Wed Jul 29 02:31:04 2026\r\n" +
	"Result: Updates Installed\r\n" +
	"\r\n" +
	"SLA Database\r\n" +
	"---------\r\n" +
	"Version: 1.00000\r\n" +
	"Contract Expiry Date: n/a\r\n" +
	"Last Updated using manual update on Sat May  6 16:26:00 2023\r\n" +
	"Last Update Attempt: Wed Jul 29 02:31:04 2026\r\n" +
	"Result: Unauthorized\r\n" +
	"\r\n" +
	"Timezone Database\r\n" +
	"---------\r\n" +
	"Version: 1.012\r\n" +
	"IANA Version: 2026b\r\n" +
	"\r\n" +
	"FDS Address\r\n" +
	"---------\r\n" +
	"198.51.100.6:443\r\n" +
	"\r\n" +
	"\r\n" +
	"FGT90G-TEST-N1(Primary) $"

func TestParseAutoupdateVersions(t *testing.T) {
	ents := parseAutoupdateVersions(autoupdateFixture)
	// FDS Address (no version, no expiry) must be dropped; the other four kept.
	if len(ents) != 4 {
		t.Fatalf("got %d entitlements, want 4: %+v", len(ents), ents)
	}
	byName := map[string]licenseEntitlement{}
	for _, e := range ents {
		byName[e.Service] = e
	}
	av := byName["AV Engine"]
	if av.Version != "7.00054 signed" || av.Expiry != "2027-04-24" ||
		av.LastUpdate != "manual update on Tue Apr 14 22:14:00 2026" || av.Result != "Updates Installed" {
		t.Errorf("AV Engine parsed wrong: %+v", av)
	}
	// Space-padded single-digit day.
	if got := byName["Attack Definitions"].Expiry; got != "2027-03-01" {
		t.Errorf("padded expiry = %q, want 2027-03-01", got)
	}
	// n/a expiry stays empty; the row itself is kept (it has a version).
	sla := byName["SLA Database"]
	if sla.Expiry != "" || sla.Result != "Unauthorized" {
		t.Errorf("SLA Database parsed wrong: %+v", sla)
	}
	// Sections without a Contract Expiry line are still inventoried.
	if _, ok := byName["Timezone Database"]; !ok {
		t.Error("Timezone Database missing")
	}
	if _, ok := byName["FDS Address"]; ok {
		t.Error("FDS Address footer must be filtered out")
	}
}

func TestParseExpiryDate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Sat Apr 24 2027", "2027-04-24"},
		{"Mon Apr  9 2018", "2018-04-09"}, // FortiOS pads single-digit days
		{"n/a", ""},
		{"", ""},
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := parseExpiryDate(c.in); got != c.want {
			t.Errorf("parseExpiryDate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLicenseLevel(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{-1, "expired"}, {0, "crit"}, {30, "crit"}, {31, "warn"}, {60, "warn"}, {61, "ok"}, {400, "ok"},
	}
	for _, c := range cases {
		if got := licenseLevel(c.days); got != c.want {
			t.Errorf("licenseLevel(%d) = %q, want %q", c.days, got, c.want)
		}
	}
}

func TestDaysUntil(t *testing.T) {
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	if got := daysUntil("2026-08-28", now); got != 30 {
		t.Errorf("daysUntil future = %d, want 30", got)
	}
	if got := daysUntil("2026-07-28", now); got >= 0 {
		t.Errorf("daysUntil past = %d, want negative", got)
	}
	if got := daysUntil("not-a-date", now); got != 0 {
		t.Errorf("daysUntil invalid = %d, want 0", got)
	}
}
