package reportlogs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func writeSourceMapping(t *testing.T, dir string, rows ...[4]any) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "fgt-adm-vpn-conf-db.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err = db.Exec(`CREATE TABLE vpn_config (dns_name_full TEXT, dns_name TEXT, firewallname TEXT, cluster_hostnames TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if _, err = db.Exec(`INSERT INTO vpn_config VALUES (?,?,?,?)`, row[0], row[1], row[2], row[3]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMappingRejectsForeignCanonicalIdentityBeforeRequest(t *testing.T) {
	cases := []struct {
		name, registered string
		row              [4]any
	}{
		{"short DNS alias", "fw.customer-b.test", [4]any{"fw.customer-a.test", "fw", "a-primary", "a-primary,a-secondary"}},
		{"short firewall alias", "fw.customer-b.test", [4]any{"fw.customer-a.test", "other", "fw", "a-primary,a-secondary"}},
		{"exact DNS alias", "fw.customer-b.test", [4]any{"fw.customer-a.test", "fw.customer-b.test", "a-primary", "a-primary,a-secondary"}},
		{"exact firewall alias", "fw.customer-b.test", [4]any{"fw.customer-a.test", "other", "fw.customer-b.test", "a-primary,a-secondary"}},
		{"case and root dot", "FW.Customer-B.Test.", [4]any{"FW.CUSTOMER-A.TEST.", "fw", "a-primary", "a-primary,a-secondary"}},
		{"root dot alias", "fw.customer-b.test", [4]any{"fw.customer-a.test", "fw.customer-b.test.", "a-primary", "a-primary,a-secondary"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				writeJSON(t, w, fixtureCount(r, 0))
			})
			writeSourceMapping(t, c.dataDir, tc.row)
			source, a, p := observationInput()
			source.Firewall = tc.registered
			a.Hostname = "b-primary"
			got := c.Collect(context.Background(), source, a, p, observationTime)
			if got.Status != "error" || calls.Load() != 0 || len(got.Sources) != 0 || len(got.Datasets) != 0 {
				t.Fatalf("foreign mapping must fail before fallback or HTTP: %+v calls=%d", got, calls.Load())
			}
			if got.Reason != "graylog source mapping conflicts with the registered firewall identity" {
				t.Fatalf("mapping conflict did not use the static safe error: %q", got.Reason)
			}
		})
	}
}

func TestMappingPreservesCanonicalAndLegacyIdentities(t *testing.T) {
	cases := []struct {
		name, registered string
		row              [4]any
		want             string
	}{
		{"canonical HA", "fw.customer-b.test", [4]any{"fw.customer-b.test", "fw", "b-primary", "b-secondary,b-primary"}, "b-primary,b-secondary"},
		{"case insensitive", "FW.CUSTOMER-B.TEST", [4]any{"fw.customer-b.test", "fw", "Primary-Source", ""}, "Primary-Source,primary-source"},
		{"registered root dot", "fw.customer-b.test.", [4]any{"fw.customer-b.test", "fw", "Primary-Source", ""}, "Primary-Source,primary-source"},
		{"canonical root dot", "fw.customer-b.test", [4]any{"FW.CUSTOMER-B.TEST.", "fw", "Primary-Source", ""}, "Primary-Source,primary-source"},
		{"empty canonical exact alias", "fw.customer-b.test", [4]any{"", "fw.customer-b.test", "b-primary", ""}, "b-primary"},
		{"null canonical short alias", "fw.customer-b.test", [4]any{nil, "fw", "b-primary", ""}, "b-primary"},
		{"short canonical", "fw.customer-b.test", [4]any{"fw", "other", "b-primary", ""}, "b-primary"},
		{"registered short name", "fw", [4]any{"fw.customer-b.test", "fw", "b-primary", ""}, "b-primary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeSourceMapping(t, dir, tc.row)
			hosts, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: tc.registered}, reportmodel.Assessment{Hostname: "unused-fallback"})
			if err != nil || strings.Join(hosts.hosts, ",") != tc.want {
				t.Fatalf("legitimate source mapping changed: hosts=%v err=%v", hosts, err)
			}
		})
	}
}

func TestMappingRejectsMalformedPopulatedCanonicalIdentity(t *testing.T) {
	for _, canonical := range []string{".", ".fw.customer-a.test", "fw..customer-a.test", "fw.customer-a.test..", " fw.customer-a.test", "fw\u200b.customer-a.test", strings.Repeat("a", 257)} {
		t.Run(canonical, func(t *testing.T) {
			var calls atomic.Int32
			c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				writeJSON(t, w, fixtureCount(r, 0))
			})
			writeSourceMapping(t, c.dataDir, [4]any{canonical, "fw", "a-primary", "a-primary,a-secondary"})
			source, a, p := observationInput()
			source.Firewall, a.Hostname = "fw.customer-b.test", "b-primary"
			got := c.Collect(context.Background(), source, a, p, observationTime)
			if got.Status != "error" || calls.Load() != 0 || len(got.Sources) != 0 || len(got.Datasets) != 0 {
				t.Fatalf("malformed canonical identity must fail before fallback or HTTP: %+v calls=%d", got, calls.Load())
			}
			if got.Reason != "graylog source mapping contains an invalid canonical identity" {
				t.Fatalf("malformed mapping did not use the static safe error: %q", got.Reason)
			}
		})
	}
}

func TestMappingRejectsMalformedRegisteredIdentity(t *testing.T) {
	for _, registered := range []string{".", ".fw.customer-b.test", "fw..customer-b.test", "fw.customer-b.test.."} {
		t.Run(registered, func(t *testing.T) {
			var calls atomic.Int32
			c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				writeJSON(t, w, fixtureCount(r, 0))
			})
			writeSourceMapping(t, c.dataDir, [4]any{"fw.customer-a.test", registered, "a-primary", "a-primary,a-secondary"})
			source, a, p := observationInput()
			source.Firewall, a.Hostname = registered, "b-primary"
			got := c.Collect(context.Background(), source, a, p, observationTime)
			if got.Status != "error" || calls.Load() != 0 || len(got.Sources) != 0 || got.Reason != "graylog registered firewall identity is invalid" {
				t.Fatalf("malformed registered identity bypassed canonical matching: %+v calls=%d", got, calls.Load())
			}
		})
	}
}

func TestMappingCanonicalRootDotDoesNotBypassAmbiguity(t *testing.T) {
	dir := t.TempDir()
	writeSourceMapping(t, dir,
		[4]any{"fw.customer-b.test", "fw", "b-primary", ""},
		[4]any{"FW.CUSTOMER-B.TEST.", "fw", "other-primary", ""},
	)
	if _, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: "fw.customer-b.test"}, reportmodel.Assessment{Hostname: "unused-fallback"}); err == nil {
		t.Fatal("equivalent duplicate canonical mappings must remain ambiguous")
	}
}

func TestADMHostSpellingsFindLowercaseLogsAndCaptureScope(t *testing.T) {
	var calls atomic.Int32
	c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		query := r.URL.Query().Get("query")
		var request aggregateRequest
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			query = request.Query
		}
		// The indexed source is lowercase, while ADM stores device spelling.
		// The old collector stopped at no_data here despite a valid HA mapping.
		if !strings.Contains(query, `source:"fgt-hq-a"`) || !strings.Contains(query, `source:"fgt-hq-b"`) {
			writeJSON(t, w, fixtureCount(r, 0))
			return
		}
		for _, selector := range []string{`source:"FGT-HQ-A"`, `source:"FGT-HQ-B"`, `vd:"root"`, "timestamp:["} {
			if !strings.Contains(query, selector) {
				t.Errorf("query lost a captured source/VDOM/time selector: %q", query)
			}
		}
		for _, foreign := range []string{"friendly-alias", "unrelated-node", "config-only-node", "firewall.example.test"} {
			if strings.Contains(query, foreign) {
				t.Errorf("ADM cluster lookup included an unbound source: %q", query)
			}
		}
		if r.Method == http.MethodGet {
			writeJSON(t, w, fixtureCount(r, fixtureTotal(query)))
		} else {
			writeJSON(t, w, fixtureAggregation(request))
		}
	})
	writeSourceMapping(t, c.dataDir,
		[4]any{"firewall.example.test", "firewall", "friendly-alias", " FGT-HQ-A, FGT-HQ-B,FGT-HQ-A "},
		[4]any{"unrelated.example.test", "unrelated", "unrelated-node", ""},
	)
	source, assessment, profile := observationInput()
	assessment.Hostname = "config-only-node"
	got := c.Collect(context.Background(), source, assessment, profile, observationTime)
	if got.Status != "partial" || len(got.Datasets) != 9 || calls.Load() > maxQueries {
		t.Fatalf("lowercase indexed HA sources were not collected: %+v calls=%d", got, calls.Load())
	}
	if strings.Join(got.Sources, ",") != "FGT-HQ-A,FGT-HQ-B,fgt-hq-a,fgt-hq-b" || got.SourceOrigin != "adm_vpn_cluster_hostnames" || got.SourceMatch != "dns_name_full" || strings.Join(got.VDOMs, ",") != "root" {
		t.Fatalf("actual source provenance was not captured: %+v", got)
	}
	wantQuery := scopeQuery(got.Sources, []string{"root"}, timeWindow{got.WindowStart, got.WindowEnd})
	if got.Query != wantQuery || strings.Contains(got.Query, "PRIVATE_API_TOKEN") || strings.Contains(got.Query, c.baseURL) {
		t.Fatalf("captured query is not the bounded credential-free request scope: %q", got.Query)
	}
	profile.Filters.VDOMs[0] = "changed-after-collection"
	if got.VDOMs[0] != "root" {
		t.Fatal("captured VDOM scope aliases the profile")
	}
}

func TestLowercaseVariantCannotClaimAnotherADMSource(t *testing.T) {
	cases := []struct {
		name, foreignName, foreignCluster string
	}{
		{"standalone", "fgt-hq-a", ""},
		{"cluster member", "other-label", " unrelated-node, fgt-hq-a "},
		{"case-folded ownership", "Fgt-Hq-A", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				writeJSON(t, w, fixtureCount(r, 0))
			})
			writeSourceMapping(t, c.dataDir,
				[4]any{"firewall.example.test", "firewall", "local-label", "FGT-HQ-A,FGT-HQ-B"},
				[4]any{"other.example.test", "other", tc.foreignName, tc.foreignCluster},
			)
			source, assessment, profile := observationInput()
			got := c.Collect(context.Background(), source, assessment, profile, observationTime)
			if got.Status != "error" || calls.Load() != 0 || len(got.Sources) != 0 || got.Query != "" || got.Reason != "graylog source spelling is ambiguous across ADM VPN mappings; collection was not widened" {
				t.Fatalf("case expansion crossed an ADM ownership boundary: %+v calls=%d", got, calls.Load())
			}
		})
	}
}

func TestLowercaseVariantDoesNotTreatOverriddenADMLabelAsSource(t *testing.T) {
	dir := t.TempDir()
	writeSourceMapping(t, dir,
		[4]any{"firewall.example.test", "firewall", "local-label", "FGT-HQ-A"},
		[4]any{"other.example.test", "other", "fgt-hq-a", "foreign-node"},
	)
	got, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: "firewall.example.test"}, reportmodel.Assessment{})
	if err != nil || strings.Join(got.hosts, ",") != "FGT-HQ-A,fgt-hq-a" {
		t.Fatalf("cluster_hostnames must override a display firewallname for ownership too: %+v %v", got, err)
	}
}

func TestCaseOwnershipScanRemainsBounded(t *testing.T) {
	for _, tc := range []struct {
		name, extraRowsSQL string
	}{
		{"row count", `WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10001) INSERT INTO vpn_config SELECT 'other-'||x||'.example.test', 'other-'||x, 'other-node-'||x, '' FROM n`},
		{"scanned bytes", `WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000) INSERT INTO vpn_config SELECT 'other-'||x||'.example.test', 'other-'||x, 'other-node-'||x, printf('%3000s','x') FROM n`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeSourceMapping(t, dir, [4]any{"firewall.example.test", "firewall", "FGT-HQ-A", ""})
			db, err := sql.Open("sqlite", filepath.Join(dir, "fgt-adm-vpn-conf-db.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(tc.extraRowsSQL); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			_ = db.Close()
			got, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: "firewall.example.test"}, reportmodel.Assessment{})
			if err == nil || len(got.hosts) != 0 || err.Error() != "graylog source ownership exceeds the supported mapping size" {
				t.Fatalf("ownership scan failed to enforce its bound: %+v %v", got, err)
			}
		})
	}
}

func TestUnmappedConfigCaseVariantCannotClaimADMSource(t *testing.T) {
	dir := t.TempDir()
	writeSourceMapping(t, dir, [4]any{"other.example.test", "other", "fgt-hq-a", ""})
	got, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: "firewall.example.test"}, reportmodel.Assessment{Hostname: "FGT-HQ-A"})
	if err == nil || len(got.hosts) != 0 || err.Error() != "graylog source spelling is ambiguous across ADM VPN mappings; collection was not widened" {
		t.Fatalf("configuration fallback case expansion claimed an unrelated ADM source: %+v %v", got, err)
	}
}

func TestConfiguredSourceLimitAppliesBeforeCaseExpansion(t *testing.T) {
	dir := t.TempDir()
	var hosts []string
	for i := 0; i < maxSourceIdentities; i++ {
		hosts = append(hosts, fmt.Sprintf("FGT-Node-%02d", i))
	}
	writeSourceMapping(t, dir, [4]any{"firewall.example.test", "firewall", "ignored-label", strings.Join(hosts, ",")})
	got, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: "firewall.example.test"}, reportmodel.Assessment{})
	if err != nil || len(got.hosts) != 2*maxSourceIdentities {
		t.Fatalf("legitimate maximum-size mapping rejected due to case variants: %+v %v", got, err)
	}
}

func TestUnusableConfiguredClusterDoesNotFallBack(t *testing.T) {
	for _, cluster := range []string{",", " , , ", "  "} {
		t.Run(cluster, func(t *testing.T) {
			dir := t.TempDir()
			writeSourceMapping(t, dir, [4]any{"firewall.example.test", "firewall", "must-not-fallback", cluster})
			got, err := New(nil, dir).sources(context.Background(), reportmodel.Source{Firewall: "firewall.example.test"}, reportmodel.Assessment{Hostname: "must-not-fallback-either"})
			if err == nil || len(got.hosts) != 0 || err.Error() != "graylog source mapping contains no usable cluster hostname" {
				t.Fatalf("unusable cluster mapping silently selected another source: %+v %v", got, err)
			}
		})
	}
}

func TestNoDataKeepsSourceProvenanceAndReproducibleQuery(t *testing.T) {
	cases := []struct {
		name, hostname, origin, match string
		row                           *[4]any
	}{
		{"standalone ADM", "unused", "adm_vpn_firewallname", "dns_name_full", &[4]any{"firewall.example.test", "firewall", "standalone-node", ""}},
		{"exact alias", "unused", "adm_vpn_firewallname", "exact_alias", &[4]any{"", "firewall.example.test", "standalone-node", ""}},
		{"short alias", "unused", "adm_vpn_firewallname", "short_alias", &[4]any{"", "firewall", "standalone-node", ""}},
		{"configuration fallback", "config-node", "config_hostname", "", nil},
		{"registered fallback", "", "registered_short_hostname", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requested string
			c := testCollector(t, func(w http.ResponseWriter, r *http.Request) {
				requested = r.URL.Query().Get("query")
				writeJSON(t, w, fixtureCount(r, 0))
			})
			if tc.row != nil {
				writeSourceMapping(t, c.dataDir, *tc.row)
			}
			source, assessment, profile := observationInput()
			assessment.Hostname = tc.hostname
			got := c.Collect(context.Background(), source, assessment, profile, observationTime)
			if got.Status != "no_data" || got.SourceOrigin != tc.origin || got.SourceMatch != tc.match || got.Query == "" || got.Query != requested || len(got.VDOMs) != 1 || got.VDOMs[0] != "root" {
				t.Fatalf("no_data hides the effective source binding or query: %+v", got)
			}
		})
	}
}
