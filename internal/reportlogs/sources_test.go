package reportlogs

import (
	"context"
	"database/sql"
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
		{"case insensitive", "FW.CUSTOMER-B.TEST", [4]any{"fw.customer-b.test", "fw", "Primary-Source", ""}, "Primary-Source"},
		{"registered root dot", "fw.customer-b.test.", [4]any{"fw.customer-b.test", "fw", "Primary-Source", ""}, "Primary-Source"},
		{"canonical root dot", "fw.customer-b.test", [4]any{"FW.CUSTOMER-B.TEST.", "fw", "Primary-Source", ""}, "Primary-Source"},
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
			if err != nil || strings.Join(hosts, ",") != tc.want {
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
