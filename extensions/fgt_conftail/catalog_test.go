package fgtconftail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBuildSourceCatalog_StandaloneRegisteredFirewall(t *testing.T) {
	t.Parallel()

	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 41, Name: "  Branch-01.Example.COM  "}},
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}

	for _, source := range []string{
		"branch-01",
		" BRANCH-01 ",
		"branch-01.example.com",
		" BRANCH-01.EXAMPLE.COM ",
	} {
		resolved, ok := catalog.resolve(source)
		if !ok {
			t.Fatalf("resolve(%q) did not find the registered firewall", source)
		}
		if resolved.ID != 41 || resolved.Name != "Branch-01.Example.COM" {
			t.Fatalf("resolve(%q) = %+v, want firewall 41", source, resolved)
		}
	}
	if _, ok := catalog.resolve("not-registered"); ok {
		t.Fatal("resolve() matched an unregistered source")
	}

	coverage := catalog.coverage()
	if len(coverage) != 1 {
		t.Fatalf("coverage() returned %d rows, want 1", len(coverage))
	}
	wantAliases := []string{
		"Branch-01",
		"branch-01",
		"Branch-01.Example.COM",
		"branch-01.example.com",
	}
	if !reflect.DeepEqual(coverage[0].Aliases, wantAliases) {
		t.Fatalf("coverage aliases = %v, want %v", coverage[0].Aliases, wantAliases)
	}
	if got := flattenGroups(catalog.sourceGroups()); !reflect.DeepEqual(got, wantAliases) {
		t.Fatalf("query aliases = %v, want exact and lowercase variants %v", got, wantAliases)
	}
	if warnings := catalog.warnings(); len(warnings) != 0 {
		t.Fatalf("warnings() = %v, want none when optional DB is absent", warnings)
	}
}

func TestBuildSourceCatalog_NormalizesHAAndIgnoresUnregisteredRows(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	createADMDatabase(t, dataDir, []admTestRow{
		{
			FirewallName:     " Logical-Cluster ",
			DNSName:          "cluster-fw",
			DNSNameFull:      " CLUSTER-FW.EXAMPLE.COM ",
			ClusterHostnames: " Node-A , node-b, NODE-A ",
		},
		{
			FirewallName:     "rogue-firewall",
			DNSName:          "rogue",
			DNSNameFull:      "rogue.example.com",
			ClusterHostnames: "rogue-a,rogue-b",
		},
	})

	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{{ID: 7, Name: "cluster-fw.example.com"}},
		dataDir,
	)
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}

	for _, source := range []string{
		"cluster-fw",
		"cluster-fw.example.com",
		"logical-cluster",
		"node-a",
		" NODE-B ",
	} {
		resolved, ok := catalog.resolve(source)
		if !ok || resolved.ID != 7 {
			t.Fatalf("resolve(%q) = (%+v, %t), want registered firewall 7", source, resolved, ok)
		}
	}
	for _, source := range []string{"rogue-firewall", "rogue-a", "rogue-b"} {
		if _, ok := catalog.resolve(source); ok {
			t.Fatalf("resolve(%q) matched an unregistered ADM VPN row", source)
		}
	}

	wantAliases := []string{
		"cluster-fw",
		"cluster-fw.example.com",
		"Logical-Cluster",
		"logical-cluster",
		"NODE-A",
		"Node-A",
		"node-a",
		"node-b",
	}
	coverage := catalog.coverage()
	if len(coverage) != 1 || !reflect.DeepEqual(coverage[0].Aliases, wantAliases) {
		t.Fatalf("coverage() = %+v, want aliases %v", coverage, wantAliases)
	}
	if got := flattenGroups(catalog.sourceGroups()); !reflect.DeepEqual(got, wantAliases) {
		t.Fatalf("query aliases = %v, want exact and lowercase HA variants %v", got, wantAliases)
	}
}

func TestBuildSourceCatalogExcludesGraylogDisabledADMFirewalls(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	createADMDatabase(t, dataDir, []admTestRow{
		{DNSNameFull: "enabled.example.com"},
		{DNSNameFull: "disabled.example.com", GraylogDisabled: true},
	})
	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{
			{ID: 1, Name: "enabled.example.com"},
			{ID: 2, Name: "disabled.example.com"},
		},
		dataDir,
	)
	if err != nil {
		t.Fatal(err)
	}

	if resolved, ok := catalog.resolve("enabled"); !ok || resolved.ID != 1 {
		t.Fatalf("enabled source resolution = (%+v, %t), want firewall 1", resolved, ok)
	}
	if _, ok := catalog.resolve("disabled"); ok {
		t.Fatal("Graylog-disabled ADM VPN firewall was included in source resolution")
	}
	coverage := catalog.coverage()
	if len(coverage) != 1 || coverage[0].FirewallID != 1 {
		t.Fatalf("coverage = %+v, want only Graylog-enabled firewall 1", coverage)
	}
}

func TestBuildSourceCatalog_ExcludesAmbiguousAliases(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	createADMDatabase(t, dataDir, []admTestRow{
		{
			FirewallName:     "shared.example-a.com",
			DNSNameFull:      "shared.example-a.com",
			ClusterHostnames: "node-a, shared-node, node-a",
		},
		{
			FirewallName:     "shared.example-b.com",
			DNSNameFull:      "shared.example-b.com",
			ClusterHostnames: "node-b, SHARED-NODE",
		},
	})

	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{
			{ID: 1, Name: "shared.example-a.com"},
			{ID: 2, Name: "shared.example-b.com"},
		},
		dataDir,
	)
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}

	for _, ambiguous := range []string{"shared", "shared-node"} {
		if _, ok := catalog.resolve(ambiguous); ok {
			t.Fatalf("resolve(%q) accepted an alias shared by logical firewalls", ambiguous)
		}
		if containsAlias(flattenGroups(catalog.sourceGroups()), ambiguous) {
			t.Fatalf("sourceGroups() contains ambiguous alias %q", ambiguous)
		}
	}
	for source, wantID := range map[string]int{
		"node-a":               1,
		"shared.example-a.com": 1,
		"node-b":               2,
		"shared.example-b.com": 2,
	} {
		resolved, ok := catalog.resolve(source)
		if !ok || resolved.ID != wantID {
			t.Fatalf("resolve(%q) = (%+v, %t), want firewall %d", source, resolved, ok, wantID)
		}
	}

	warnings := strings.Join(catalog.warnings(), "\n")
	for _, alias := range []string{"shared", "shared-node"} {
		if !strings.Contains(warnings, alias) || !strings.Contains(warnings, "ambiguous") {
			t.Fatalf("warnings() = %q, want visible ambiguity for %q", warnings, alias)
		}
	}
	coverage := catalog.coverage()
	for _, row := range coverage {
		if len(row.Warnings) == 0 {
			t.Fatalf("coverage row %+v does not expose its alias collision", row)
		}
	}
}

func TestBuildSourceCatalog_ReportsInvalidNamesWithoutBroadening(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	createADMDatabase(t, dataDir, []admTestRow{
		{
			FirewallName:     "valid",
			DNSNameFull:      "valid.example.com",
			ClusterHostnames: "\x01bad," + strings.Repeat("b", maxCatalogAliasBytes+1),
		},
	})

	catalog, err := buildSourceCatalog(
		context.Background(),
		[]firewallRef{
			{ID: 1, Name: "   "},
			{ID: 2, Name: "\x01bad.example.com"},
			{ID: 3, Name: strings.Repeat("a", maxCatalogAliasBytes+1) + ".example.com"},
			{ID: 4, Name: "valid.example.com"},
		},
		dataDir,
	)
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}

	if _, ok := catalog.resolve(""); ok {
		t.Fatal("resolve() accepted an empty alias")
	}
	if _, ok := catalog.resolve("\x01bad"); ok {
		t.Fatal("resolve() accepted an alias with a control character")
	}
	if _, ok := catalog.resolve(strings.Repeat("a", maxCatalogAliasBytes+1)); ok {
		t.Fatal("resolve() accepted an overlong alias")
	}
	resolved, ok := catalog.resolve("valid")
	if !ok || resolved.ID != 4 {
		t.Fatalf("resolve(valid) = (%+v, %t), want firewall 4", resolved, ok)
	}

	coverage := catalog.coverage()
	if len(coverage) != 1 || coverage[0].FirewallID != 4 {
		t.Fatalf("coverage() = %+v, want only the Graylog-enabled ADM firewall", coverage)
	}
	if warnings := catalog.warnings(); len(warnings) == 0 {
		t.Fatalf("warnings() = %v, want invalid enabled ADM aliases to be visible", warnings)
	}
}

func TestBuildSourceCatalog_OptionalAndMalformedADMDatabase(t *testing.T) {
	t.Parallel()

	t.Run("missing database is normal", func(t *testing.T) {
		catalog, err := buildSourceCatalog(
			context.Background(),
			[]firewallRef{{ID: 1, Name: "standalone.example.com"}},
			t.TempDir(),
		)
		if err != nil {
			t.Fatalf("buildSourceCatalog() error = %v", err)
		}
		if warnings := catalog.warnings(); len(warnings) != 0 {
			t.Fatalf("warnings() = %v, want missing optional DB to be silent", warnings)
		}
	})

	t.Run("corrupt database becomes warning", func(t *testing.T) {
		dataDir := t.TempDir()
		dbPath := filepath.Join(dataDir, admVPNDatabaseName)
		if err := os.WriteFile(dbPath, []byte("not a sqlite database"), 0o600); err != nil {
			t.Fatalf("write malformed ADM VPN DB: %v", err)
		}

		catalog, err := buildSourceCatalog(
			context.Background(),
			[]firewallRef{{ID: 1, Name: "standalone.example.com"}},
			dataDir,
		)
		if err != nil {
			t.Fatalf("buildSourceCatalog() error = %v", err)
		}
		if _, ok := catalog.resolve("standalone"); ok {
			t.Fatal("catalog accepted a firewall without a readable ADM Graylog-enabled flag")
		}
		if coverage := catalog.coverage(); len(coverage) != 0 {
			t.Fatalf("coverage = %+v, want none when ADM enablement cannot be read", coverage)
		}
		warnings := strings.Join(catalog.warnings(), "\n")
		if !strings.Contains(warnings, "ADM VPN") {
			t.Fatalf("warnings() = %q, want malformed ADM VPN DB warning", warnings)
		}
	})

	t.Run("query failure becomes warning", func(t *testing.T) {
		dataDir := t.TempDir()
		dbPath := filepath.Join(dataDir, admVPNDatabaseName)
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open malformed-schema DB: %v", err)
		}
		if _, err := db.Exec(`CREATE TABLE vpn_config (firewallname TEXT)`); err != nil {
			t.Fatalf("create malformed schema: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close malformed-schema DB: %v", err)
		}

		catalog, err := buildSourceCatalog(
			context.Background(),
			[]firewallRef{{ID: 1, Name: "standalone.example.com"}},
			dataDir,
		)
		if err != nil {
			t.Fatalf("buildSourceCatalog() error = %v", err)
		}
		warnings := strings.Join(catalog.warnings(), "\n")
		if !strings.Contains(warnings, "ADM VPN") {
			t.Fatalf("warnings() = %q, want query warning", warnings)
		}
	})
}

func TestBuildSourceCatalog_SourceGroupsAreDeterministicAndBounded(t *testing.T) {
	t.Parallel()

	firewalls := make([]firewallRef, 0, 26)
	expectedAliases := make([]string, 0, 52)
	for id := 26; id >= 1; id-- {
		short := fmt.Sprintf("host%02d", id)
		full := short + ".example.com"
		firewalls = append(firewalls, firewallRef{ID: id, Name: full})
		expectedAliases = append(expectedAliases, short, full)
	}
	sort.Strings(expectedAliases)

	catalog, err := buildSourceCatalog(context.Background(), firewalls, t.TempDir())
	if err != nil {
		t.Fatalf("buildSourceCatalog() error = %v", err)
	}
	groups := catalog.sourceGroups()
	if len(groups) != 3 {
		t.Fatalf("sourceGroups() returned %d groups, want 3", len(groups))
	}
	for i, group := range groups {
		if len(group) == 0 || len(group) > maxSourceAliasesPerGroup {
			t.Fatalf("sourceGroups()[%d] has %d aliases, want 1..%d", i, len(group), maxSourceAliasesPerGroup)
		}
	}
	if got := flattenGroups(groups); !reflect.DeepEqual(got, expectedAliases) {
		t.Fatalf("flattened sourceGroups() = %v, want deterministic aliases %v", got, expectedAliases)
	}
	coverage := catalog.coverage()
	for i, row := range coverage {
		wantID := i + 1
		if row.FirewallID != wantID {
			t.Fatalf("coverage()[%d].FirewallID = %d, want deterministic ID %d", i, row.FirewallID, wantID)
		}
	}
}

func TestBuildSourceCatalog_HonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := buildSourceCatalog(
		ctx,
		[]firewallRef{{ID: 1, Name: "standalone.example.com"}},
		t.TempDir(),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("buildSourceCatalog() error = %v, want context.Canceled", err)
	}
}

type admTestRow struct {
	FirewallName     string
	DNSName          string
	DNSNameFull      string
	ClusterHostnames string
	GraylogDisabled  bool
}

func createADMDatabase(t *testing.T, dataDir string, rows []admTestRow) {
	t.Helper()

	dbPath := filepath.Join(dataDir, admVPNDatabaseName)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open ADM VPN DB: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE vpn_config (
		firewallname TEXT,
		dns_name TEXT,
		dns_name_full TEXT,
		cluster_hostnames TEXT,
		graylog_enabled BOOLEAN DEFAULT 1
	)`); err != nil {
		_ = db.Close()
		t.Fatalf("create ADM VPN schema: %v", err)
	}
	for _, row := range rows {
		if _, err := db.Exec(
			`INSERT INTO vpn_config
			 (firewallname, dns_name, dns_name_full, cluster_hostnames, graylog_enabled)
			 VALUES (?, ?, ?, ?, ?)`,
			row.FirewallName,
			row.DNSName,
			row.DNSNameFull,
			row.ClusterHostnames,
			!row.GraylogDisabled,
		); err != nil {
			_ = db.Close()
			t.Fatalf("insert ADM VPN row: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close ADM VPN DB: %v", err)
	}
}

func flattenGroups(groups [][]string) []string {
	aliases := make([]string, 0)
	for _, group := range groups {
		aliases = append(aliases, group...)
	}
	return aliases
}

func containsAlias(aliases []string, target string) bool {
	for _, alias := range aliases {
		if alias == target {
			return true
		}
	}
	return false
}
