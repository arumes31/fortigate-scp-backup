package web

import (
	"testing"
	"time"

	graylogdevicedata "github.com/arumes31/fortigate-scp-backup/extensions/graylog_device_data"
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

// TestClassifyLicense verifies the device-level rollup: a long-lapsed service
// among active entitlements must not mark the device expired (real fleets
// carry stale entries for services outside the current contract bundle).
func TestClassifyLicense(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	ent := func(svc, expiry string) licenseEntitlement {
		return licenseEntitlement{Service: svc, Expiry: expiry}
	}
	cases := []struct {
		name       string
		ents       []licenseEntitlement
		wantLevel  string
		wantExpiry string
		wantLapsed int
	}{
		{"all active", []licenseEntitlement{ent("AV", "2027-02-10"), ent("IPS", "2027-04-24")},
			"ok", "2027-02-10", 0},
		// The reported bug: one service lapsed 2021 while the bundle runs to 2027.
		{"one lapsed among active", []licenseEntitlement{ent("Old", "2021-10-02"), ent("AV", "2027-02-10")},
			"ok", "2027-02-10", 1},
		{"active expiring soon", []licenseEntitlement{ent("Old", "2021-10-02"), ent("AV", "2026-08-10")},
			"crit", "2026-08-10", 1},
		{"all lapsed", []licenseEntitlement{ent("AV", "2021-10-02"), ent("IPS", "2024-01-01")},
			"expired", "2024-01-01", 2},
		{"no dated entitlements", []licenseEntitlement{ent("Tz", ""), ent("Modem", "")},
			"unknown", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyLicense(c.ents, now)
			if got.Level != c.wantLevel || got.Expiry != c.wantExpiry || got.Lapsed != c.wantLapsed {
				t.Errorf("got level=%s expiry=%s lapsed=%d, want %s/%s/%d",
					got.Level, got.Expiry, got.Lapsed, c.wantLevel, c.wantExpiry, c.wantLapsed)
			}
		})
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

// Switch/AP fixtures are modeled on real FortiOS 7.6 output (captured
// 2026-07-30) with serials, hostnames and AP names replaced by placeholders.

const switchInfoStatusFixture = "FGT90G-TEST-N1(Primary) $ Vdom: root\r\n" +
	"Managed Switch : TEST-CORE01     0\r\n" +
	"Version: FortiSwitch-524D v7.6.6,build1137,251212 (GA)\r\n" +
	"Serial-Number: S524DNTEST000001\r\n" +
	"Boot: Warmboot\r\n" +
	"BIOS version: 04000019\r\n" +
	"System Part-Number: P18053-07\r\n" +
	"Burn in MAC: 00:11:22:33:44:55\r\n" +
	"Hostname: TEST-CORE01\r\n" +
	"Security level: high (force)\r\n" +
	"Branch point: 1137 \r\n" +
	"System time: Thu Jul 30 09:55:37 2026\r\n" +
	"\r\n" +
	"Managed Switch : TEST-EDGE01     0\r\n" +
	"Version: FortiSwitch-108E v7.4.9,build0946,260122 (GA)\r\n" +
	"Serial-Number: S108ENTEST000001\r\n" +
	"Firmware Signature: valid\r\n" +
	"Boot: Coldboot \r\n" +
	"Hostname: TEST-EDGE01\r\n" +
	"System time: Thu Jul 30 09:55:38 2026\r\n"

func TestParseSwitchInfoStatus(t *testing.T) {
	devs := parseSwitchInfoStatus(switchInfoStatusFixture)
	if len(devs) != 2 {
		t.Fatalf("parsed %d switches, want 2: %+v", len(devs), devs)
	}
	want := licenseDevice{Kind: "switch", Name: "TEST-CORE01", Serial: "S524DNTEST000001",
		Model: "FortiSwitch-524D", Version: "7.6.6", Build: "1137", Status: "online"}
	if devs[0] != want {
		t.Errorf("first switch = %+v, want %+v", devs[0], want)
	}
	if devs[1].Serial != "S108ENTEST000001" || devs[1].Model != "FortiSwitch-108E" || devs[1].Version != "7.4.9" {
		t.Errorf("second switch = %+v", devs[1])
	}
	if got := parseSwitchInfoStatus("FGT90G-TEST-N1 $ \r\ncommand parse error before 'switch-controller'\r\nCommand fail. Return code -61\r\n"); len(got) != 0 {
		t.Errorf("error output must parse to no switches: %+v", got)
	}
}

func TestParseSwitchInfoStatusPreservesManagedSwitchIDAsMergeKey(t *testing.T) {
	t.Parallel()
	output := "Managed Switch : SWITCH-ID-01 0\r\n" +
		"Version: FortiSwitch-108E v7.4.9,build0946,260122 (GA)\r\n" +
		"Hostname: FRIENDLY-HOSTNAME\r\n"
	devices := parseSwitchInfoStatus(output)
	if len(devices) != 1 || devices[0].Name != "SWITCH-ID-01" {
		t.Fatalf("parsed switches = %+v, want managed switch ID as name", devices)
	}
	merged := mergeSwitchDevices([]string{"SWITCH-ID-01"}, devices)
	if len(merged) != 1 || merged[0].Status != "online" {
		t.Fatalf("merged switches = %+v, want one online switch", merged)
	}
}

const managedSwitchListFixture = "FGT90G-TEST-N1(Primary) $ == [ TEST-CORE01 ]\r\n" +
	"switch-id: TEST-CORE01   \r\n" +
	"== [ TEST-EDGE01 ]\r\n" +
	"switch-id: TEST-EDGE01   \r\n" +
	"== [ TEST-STOCK01 ]\r\n" +
	"switch-id: TEST-STOCK01   \r\n"

func TestParseManagedSwitchList(t *testing.T) {
	ids := parseManagedSwitchList(managedSwitchListFixture)
	if len(ids) != 3 || ids[0] != "TEST-CORE01" || ids[2] != "TEST-STOCK01" {
		t.Errorf("ids = %v", ids)
	}
}

// TestMergeSwitchDevices: a configured switch with no connected section reads
// offline; a connected switch missing from the configured list (global `get`
// unavailable on multi-vdom boxes) is kept.
func TestMergeSwitchDevices(t *testing.T) {
	connected := []licenseDevice{
		{Kind: "switch", Name: "TEST-CORE01", Serial: "S524DNTEST000001", Status: "online"},
		{Kind: "switch", Name: "TEST-VDOM01", Serial: "S524DNTEST000009", Status: "online"},
	}
	got := mergeSwitchDevices([]string{"TEST-CORE01", "TEST-STOCK01"}, connected)
	if len(got) != 3 {
		t.Fatalf("merged %d rows, want 3: %+v", len(got), got)
	}
	if got[0].Serial != "S524DNTEST000001" || got[0].Status != "online" {
		t.Errorf("connected switch not enriched: %+v", got[0])
	}
	if got[1].Name != "TEST-STOCK01" || got[1].Status != "offline" || got[1].Serial != "" {
		t.Errorf("configured-only switch must read offline: %+v", got[1])
	}
	if got[2].Name != "TEST-VDOM01" || got[2].Status != "online" {
		t.Errorf("connected-only switch must be kept: %+v", got[2])
	}
}

const wtpConfigFixture = "FGT90G-TEST-N1(Primary) $ config wireless-controller wtp\r\n" +
	"    edit \"FP231FTEST0000A1\"\r\n" +
	"        set uuid 00000000-0000-0000-0000-000000000001\r\n" +
	"        set admin enable\r\n" +
	"        set name \"AP Test Basement\"\r\n" +
	"        set wtp-profile \"FAP231F-default\"\r\n" +
	"        config radio-1\r\n" +
	"        end\r\n" +
	"    next\r\n" +
	"    edit \"FP231GTEST0000B2\"\r\n" +
	"        set uuid 00000000-0000-0000-0000-000000000002\r\n" +
	"        set admin enable\r\n" +
	"        set wtp-profile \"FAP231G-default\"\r\n" +
	"    next\r\n" +
	"end\r\n"

func TestParseWTPConfig(t *testing.T) {
	devs := parseWTPConfig(wtpConfigFixture)
	if len(devs) != 2 {
		t.Fatalf("parsed %d APs, want 2: %+v", len(devs), devs)
	}
	want := licenseDevice{Kind: "ap", Name: "AP Test Basement", Serial: "FP231FTEST0000A1", Model: "FortiAP-231F"}
	if devs[0] != want {
		t.Errorf("first AP = %+v, want %+v", devs[0], want)
	}
	// An AP without `set name` falls back to its serial; the model still
	// derives from the serial prefix.
	if devs[1].Name != "FP231GTEST0000B2" || devs[1].Model != "FortiAP-231G" {
		t.Errorf("second AP = %+v", devs[1])
	}
}

func TestAPModel(t *testing.T) {
	cases := []struct{ serial, profile, want string }{
		{"FP231FTEST0000A1", "", "FortiAP-231F"},
		{"FP23JFTEST0000A1", "", "FortiAP-23JF"},
		{"PU431FTEST000001", "FAP431F-default", "FortiAP-431F"}, // odd serial → profile fallback
		{"PU431FTEST000001", "custom-profile", ""},
	}
	for _, c := range cases {
		if got := apModel(c.serial, c.profile); got != c.want {
			t.Errorf("apModel(%q, %q) = %q, want %q", c.serial, c.profile, got, c.want)
		}
	}
}

// TestMergeObservedDevices covers the read-time enrichment from the
// graylog_device_data observed inventory: serial backfill for offline
// switches (with ambiguity refusal), discovery of log-only devices, and the
// no-duplicate guarantee when both sources know a device.
func TestMergeObservedDevices(t *testing.T) {
	ssh := []licenseDevice{
		{Kind: "switch", Name: "TEST-CORE01", Serial: "S524DNTEST000001", Status: "online"},
		{Kind: "switch", Name: "TEST-STOCK01", Status: "offline"}, // serial unknown to CLI
		{Kind: "switch", Name: "TEST-AMBIG01", Status: "offline"},
		{Kind: "ap", Name: "AP Test Basement", Serial: "FP231FTEST0000A1"},
	}
	obs := []graylogdevicedata.ObservedDevice{
		{Kind: "switch", Serial: "S524DNTEST000001", Name: "TEST-CORE01"},               // duplicate → no new row
		{Kind: "switch", Serial: "S108ENTEST000001", Name: "test-stock01"},              // backfill (case-insensitive)
		{Kind: "switch", Serial: "S108ENTEST000002", Name: "TEST-AMBIG01"},              // two serials claim
		{Kind: "switch", Serial: "S108ENTEST000003", Name: "TEST-AMBIG01"},              //   the same name → refuse
		{Kind: "switch", Serial: "S148FNTEST000001", Name: "TEST-GHOST01"},              // discovery
		{Kind: "ap", Serial: "FP231GTEST0000B2", Name: "AP Test Attic", IP: "10.0.0.9"}, // discovery
	}
	got := mergeObservedDevices(ssh, obs)

	byName := map[string]licenseDevice{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if d := byName["TEST-STOCK01"]; d.Serial != "S108ENTEST000001" || d.Origin != "logs" || d.Status != "offline" {
		t.Errorf("backfill failed: %+v", d)
	}
	if d := byName["TEST-AMBIG01"]; d.Serial != "" {
		t.Errorf("ambiguous name must not be backfilled: %+v", d)
	}
	if d := byName["TEST-GHOST01"]; d.Serial != "S148FNTEST000001" || d.Origin != "logs" || d.Status != "" {
		t.Errorf("switch discovery failed: %+v", d)
	}
	if d := byName["AP Test Attic"]; d.Kind != "ap" || d.IP != "10.0.0.9" || d.Origin != "logs" {
		t.Errorf("ap discovery failed: %+v", d)
	}
	if d := byName["TEST-CORE01"]; d.Origin != "" {
		t.Errorf("SSH-known device must stay SSH-authoritative: %+v", d)
	}
	if len(got) != 6 {
		t.Fatalf("merged %d rows, want 6: %+v", len(got), got)
	}
	// Ordering: all switches before all APs; discovered rows after SSH rows.
	kinds := ""
	for _, d := range got {
		if d.Kind == "switch" {
			kinds += "s"
		} else {
			kinds += "a"
		}
	}
	if kinds != "ssssaa" {
		t.Errorf("kind ordering = %q, want ssssaa (%+v)", kinds, got)
	}
	if got[3].Name != "TEST-GHOST01" || got[5].Name != "AP Test Attic" {
		t.Errorf("discovered rows must follow SSH rows of their kind: %+v", got)
	}

	// No observations: input passes through untouched.
	if same := mergeObservedDevices(ssh, nil); len(same) != len(ssh) {
		t.Errorf("nil observations changed the list: %+v", same)
	}
}
