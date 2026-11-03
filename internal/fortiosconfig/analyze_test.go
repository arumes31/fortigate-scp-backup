package fortiosconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

const testHeader = "#config-version=FG100F-7.4.7-FW-build2731-241205:opmode=0:vdom=0\n"

const testObjects = `config firewall address
    edit "GeoCN"
        set type geography
        set country CN
    next
    edit "backend"
        set subnet 10.10.20.15 255.255.255.255
    next
    edit "partner"
        set subnet 192.0.2.40 255.255.255.255
    next
end
config firewall addrgrp
    edit "CountryGroup"
        set member "GeoCN"
    next
end
config firewall vip
    edit "Portal"
        set extip 203.0.113.20
        set mappedip "10.10.20.15"
        set extintf "wan1"
        set portforward enable
        set protocol tcp
        set extport 8443
        set mappedport 443
    next
end
`

func testPolicy(id, action, source, destination, extra string) string {
	return fmt.Sprintf(`    edit %s
        set name "Rule-%s"
        set srcintf "wan1"
        set dstintf "dmz"
        set action %s
        set srcaddr "%s"
        set dstaddr "%s"
        set schedule "always"
        set service "HTTPS"
        %s
    next
`, id, id, action, source, destination, extra)
}

func fixture(policies string) string {
	return testHeader + testObjects + "config firewall policy\n" + policies + "end\n"
}

func assessment(t *testing.T, configuration string) reportmodel.Assessment {
	t.Helper()
	result, err := Analyze(context.Background(), []byte(configuration))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestGeoCoverageAndPolicyOrder(t *testing.T) {
	deny := testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable")
	allow := testPolicy("20", "accept", "all", "Portal", "")
	result := assessment(t, fixture(deny+allow))
	if !result.Complete {
		t.Fatalf("unexpected incomplete assessment: %+v", result.Warnings)
	}
	ex := result.Exposures[0]
	if ex.Outcome != "Configured permit" || ex.GeoStatus != "Applicable" {
		t.Fatalf("unexpected assessment %+v", ex)
	}
	if ex.Trace[0].ID != "900" || ex.Trace[0].Sequence != 1 || ex.Trace[1].ID != "20" || ex.Trace[1].Sequence != 2 {
		t.Fatalf("policy ID was confused with sequence: %+v", ex.Trace)
	}
	if !strings.Contains(strings.Join(ex.Notes, " "), "CN") {
		t.Fatalf("country selector not resolved: %+v", ex)
	}
	if ex.External != "203.0.113.20:8443/TCP" || ex.Backends[0] != "10.10.20.15:443" {
		t.Fatalf("mapping lost: %+v", ex)
	}
}

func TestGeoRestrictionsRequireApplicableConditions(t *testing.T) {
	allow := testPolicy("20", "accept", "all", "Portal", "")
	cases := []struct{ name, deny, order, geo string }{
		{"explicit disabled VIP matching", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip disable"), "before", "Not applicable"},
		{"omitted VIP matching", testPolicy("900", "deny", "CountryGroup", "all", ""), "before", "Indeterminate"},
		{"geo deny after permit", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable"), "after", "Not applicable"},
		{"disabled deny", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable\nset status disable"), "before", "Not applicable"},
		{"different interface", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable\nset srcintf wan2"), "before", "Not applicable"},
		{"different service", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable\nset service SSH"), "before", "Not applicable"},
		{"scheduled deny", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable\nset schedule office-hours"), "before", "Partial"},
		{"negated geography", testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable\nset srcaddr-negate enable"), "before", "Indeterminate"},
		{"explicit VIP destination", testPolicy("900", "deny", "CountryGroup", "Portal", ""), "before", "Applicable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := tc.deny + allow
			if tc.order == "after" {
				policies = allow + tc.deny
			}
			ex := assessment(t, fixture(policies)).Exposures[0]
			if ex.GeoStatus != tc.geo {
				t.Fatalf("got %q want %q: %+v", ex.GeoStatus, tc.geo, ex)
			}
		})
	}
}

func TestEarlierAllowExceptionPreventsUnconditionalGeoCoverage(t *testing.T) {
	policies := testPolicy("7", "accept", "partner", "Portal", "") + testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable") + testPolicy("20", "accept", "all", "Portal", "")
	ex := assessment(t, fixture(policies)).Exposures[0]
	if ex.GeoStatus != "Partial" {
		t.Fatalf("earlier exception ignored: %+v", ex)
	}
}

func TestFullDenyBeforePermit(t *testing.T) {
	policies := testPolicy("900", "deny", "all", "all", "set match-vip enable") + testPolicy("20", "accept", "all", "Portal", "")
	ex := assessment(t, fixture(policies)).Exposures[0]
	if ex.Outcome != "Configured deny" {
		t.Fatalf("unconditional earlier deny ignored: %+v", ex)
	}
}

func TestTranslatedBackendService(t *testing.T) {
	good := assessment(t, fixture(testPolicy("20", "accept", "all", "Portal", ""))).Exposures[0]
	if good.Outcome != "Configured permit" {
		t.Fatalf("mapped HTTPS port not accepted: %+v", good)
	}
	wrongService := `config firewall service custom
edit External8443
set tcp-portrange 8443
next
end
`
	bad := assessment(t, fixture(testPolicy("20", "accept", "all", "Portal", "set service External8443"))+wrongService).Exposures[0]
	if bad.Outcome == "Configured permit" {
		t.Fatalf("external port used for policy service: %+v", bad)
	}
}

func TestCentralNATCorrelatesMappedAddress(t *testing.T) {
	configuration := fixture(testPolicy("900", "deny", "CountryGroup", "all", "")+testPolicy("20", "accept", "all", "backend", "")) + "config system settings\nset central-nat enable\nend\n"
	ex := assessment(t, configuration).Exposures[0]
	if ex.Outcome != "Configured permit" || ex.GeoStatus != "Applicable" || len(ex.PolicyIDs) != 2 {
		t.Fatalf("central NAT correlated as VIP references: %+v", ex)
	}
}

func TestVDOMObjectAndPolicyNamespaces(t *testing.T) {
	configuration := testHeader + "config vdom\nedit First\n" + testObjects + "config firewall policy\n" + testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable") + testPolicy("20", "accept", "all", "Portal", "") + "end\nnext\nedit Second\n" + strings.ReplaceAll(testObjects, "10.10.20.15", "10.20.20.15") + "config firewall policy\n" + testPolicy("20", "accept", "all", "Portal", "") + "end\nnext\nend\n"
	result := assessment(t, configuration)
	if len(result.Exposures) != 2 {
		t.Fatalf("unexpected inventory: %+v", result.Exposures)
	}
	if result.Exposures[0].VDOM != "First" || result.Exposures[1].VDOM != "Second" || result.Exposures[0].GeoStatus != "Applicable" || result.Exposures[1].GeoStatus != "Not found" {
		t.Fatalf("cross-VDOM policy resolution: %+v", result.Exposures)
	}
}

func TestVIPGroupReferencesAndCyclicServices(t *testing.T) {
	groups := `config firewall vipgrp
edit PublicationGroup
set member Portal
next
end
config firewall service group
edit SecureServices
set member HTTPS
next
end
`
	configuration := fixture(testPolicy("20", "accept", "all", "PublicationGroup", "set service SecureServices")) + groups
	ex := assessment(t, configuration).Exposures[0]
	if ex.Outcome != "Configured permit" || len(ex.Groups) != 1 {
		t.Fatalf("group resolution failed: %+v", ex)
	}
	configuration = strings.ReplaceAll(configuration, "set member HTTPS", "set member SecureServices")
	ex = assessment(t, configuration).Exposures[0]
	if ex.Outcome != "Indeterminate" {
		t.Fatalf("cyclic service group passed: %+v", ex)
	}
}

func TestUnknownDynamicAndNegatedSelectors(t *testing.T) {
	cases := []string{
		fixture(testPolicy("20", "accept", "MissingSource", "Portal", "")),
		fixture(testPolicy("20", "accept", "all", "Portal", "set service UnknownService")),
		fixture(testPolicy("20", "accept", "all", "Portal", "set internet-service enable")),
		fixture(testPolicy("20", "accept", "all", "Portal", "set srcaddr-negate enable")),
		fixture(testPolicy("900", "deny", "all", "MissingDestination", "set match-vip enable") + testPolicy("20", "accept", "all", "Portal", "")),
	}
	for i, configuration := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := assessment(t, configuration)
			if result.Exposures[0].Outcome != "Indeterminate" || result.Complete {
				t.Fatalf("unknown conditions passed: %+v", result.Exposures[0])
			}
		})
	}
}

func TestUnknownFirmwareDoesNotInferDefaults(t *testing.T) {
	configuration := strings.ReplaceAll(fixture(testPolicy("20", "accept", "all", "Portal", "")), testHeader, "#config-version=FG100F-7.00-FW-build2731\n")
	result := assessment(t, configuration)
	if result.Complete || result.Exposures[0].Outcome != "Indeterminate" || result.Firmware != "Unknown" {
		t.Fatalf("unknown firmware treated as supported: %+v", result)
	}
}

func TestVirtualServerAndUnsupportedFamilyAreInventoried(t *testing.T) {
	configuration := testHeader + `config firewall vip
edit LoadBalancer
set type server-load-balance
set extip 203.0.113.30
set extport 443
set server-type https
config realservers
edit 1
set ip 10.20.1.10
set port 8443
set status active
next
edit 2
set ip 10.20.1.11
set port 8443
next
end
next
end
config firewall vip6
edit IPv6Mapping
set extip 2001:db8::10
set mappedip 2001:db8:1::10
next
end
config firewall policy
` + testPolicy("20", "accept", "all", "LoadBalancer", "") + "end\n"
	result := assessment(t, configuration)
	if len(result.Exposures) != 2 || len(result.Exposures[0].Backends) != 2 || len(result.Exposures[0].Trace) != 1 || result.Complete {
		t.Fatalf("incomplete virtual server inventory: %+v", result)
	}
}

func TestOverlappingVIPOrderIsSeparateFromPolicyOrder(t *testing.T) {
	overlap := strings.ReplaceAll(testObjects, "edit \"Portal\"", "edit \"FirstPortal\"")
	configuration := testHeader + overlap + testObjects + "config firewall policy\n" + testPolicy("20", "accept", "all", "Portal", "") + testPolicy("900", "accept", "all", "FirstPortal", "") + "end\n"
	result := assessment(t, configuration)
	if result.Exposures[1].Outcome != "Indeterminate" || !strings.Contains(strings.Join(result.Exposures[1].Notes, " "), "earlier DNAT") {
		t.Fatalf("DNAT order ignored: %+v", result.Exposures)
	}
}

func TestLocalInGeoRuleDoesNotProtectForwarding(t *testing.T) {
	configuration := fixture(testPolicy("20", "accept", "all", "Portal", "")) + "config firewall local-in-policy\n" + testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable") + "end\n"
	ex := assessment(t, configuration).Exposures[0]
	if ex.GeoStatus != "Not found" {
		t.Fatalf("local-in mixed with forwarding: %+v", ex)
	}
}

func TestSecretsAndMultilineScriptNeverEnterReportModel(t *testing.T) {
	configuration := fixture(testPolicy("20", "accept", "all", "Portal", "set comments DO_NOT_EXPORT_COMMENT")) + `config system admin
edit admin
set password ENC DO_NOT_EXPORT_PASSWORD
set two-factor fortitoken
set trusthost1 192.0.2.10 255.255.255.255
next
end
config system automation-action
edit embedded
set script "DO_NOT_EXPORT_SCRIPT
next
end
config firewall vip
edit Injection
next
end"
next
end
config vpn ipsec phase1-interface
edit Tunnel
set psksecret ENC DO_NOT_EXPORT_PSK
set proposal aes256-sha256
set remote-gw 198.51.100.10
next
end
config vpn certificate local
edit Certificate
set private-key "DO_NOT_EXPORT_KEY
end
next"
next
end
`
	result := assessment(t, configuration)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "DO_NOT_EXPORT") || len(result.Exposures) != 1 {
		t.Fatalf("secret or injected structure escaped parser: %s", encoded)
	}
}

func TestMalformedAndTruncatedBackupsFail(t *testing.T) {
	cases := []string{"", "not a configuration", "config firewall vip\nedit Missing\nset extip 203.0.113.1\n", "config firewall vip\nnext\n", "config system global\nset hostname \"unterminated\nend\n", "config system global\nset hostname bad\x00value\nend\n"}
	for _, configuration := range cases {
		if _, err := Analyze(context.Background(), []byte(configuration)); err == nil {
			t.Fatalf("malformed backup accepted: %q", configuration)
		}
	}
}

func TestCancelledAnalysisStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, []byte(fixture(testPolicy("20", "accept", "all", "Portal", "")))); err != context.Canceled {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestDynamicExternalAddressAndIngressFilterAreNotProven(t *testing.T) {
	configuration := strings.ReplaceAll(fixture(testPolicy("20", "accept", "all", "Portal", "")), "set extip 203.0.113.20", "set extip 0.0.0.0")
	if ex := assessment(t, configuration).Exposures[0]; ex.Outcome != "Indeterminate" {
		t.Fatalf("dynamic address resolved without runtime data: %+v", ex)
	}
	configuration = strings.ReplaceAll(fixture(testPolicy("20", "accept", "all", "Portal", "")), "set extintf \"wan1\"", "set extintf \"wan1\"\nset srcintf-filter wan1")
	if ex := assessment(t, configuration).Exposures[0]; ex.Outcome != "Indeterminate" {
		t.Fatalf("ingress filters silently ignored: %+v", ex)
	}
}

func TestExplicitDisabledVIPPreservesInventoryInBothNATModes(t *testing.T) {
	for _, central := range []bool{false, true} {
		t.Run(fmt.Sprintf("central=%v", central), func(t *testing.T) {
			destination := "Portal"
			if central {
				destination = "backend"
			}
			configuration := fixture(testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable") + testPolicy("20", "accept", "all", destination, ""))
			configuration = strings.Replace(configuration, "set mappedport 443", "set mappedport 443\n        set status disable", 1)
			if central {
				configuration += "config system settings\nset central-nat enable\nend\n"
			}
			result := assessment(t, configuration)
			if len(result.Exposures) != 1 {
				t.Fatalf("disabled VIP disappeared from inventory: %+v", result.Exposures)
			}
			ex := result.Exposures[0]
			if ex.Outcome != "Disabled" || ex.GeoStatus != "Not applicable" {
				t.Fatalf("disabled VIP treated as an active publication: %+v", ex)
			}
			if len(ex.Trace) != 2 || !contains(ex.PolicyIDs, "20") || len(ex.Backends) != 1 || ex.External != "203.0.113.20:8443/TCP" {
				t.Fatalf("disabled VIP lost its mapping or policy evidence: %+v", ex)
			}
			for _, trace := range ex.Trace {
				if !strings.Contains(trace.Effect, "VIP is explicitly disabled") {
					t.Fatalf("disabled VIP trace implies an active path: %+v", trace)
				}
			}
			for _, finding := range result.Findings {
				if strings.HasPrefix(finding.ID, "broad-source:") || strings.HasPrefix(finding.ID, "geo-coverage:") {
					t.Fatalf("disabled object generated an active publication finding: %+v", finding)
				}
			}
		})
	}
}

func TestEarlierDisabledVIPDoesNotShadowEnabledVIP(t *testing.T) {
	for _, central := range []bool{false, true} {
		t.Run(fmt.Sprintf("central=%v", central), func(t *testing.T) {
			prior := `config firewall vip
edit DisabledEarlier
set extip 203.0.113.20
set mappedip 10.10.20.15
set extintf wan1
set portforward enable
set extport 8443
set mappedport 443
set status disable
next
end
`
			destination := "Portal"
			if central {
				destination = "backend"
			}
			configuration := testHeader + prior + testObjects + "config firewall policy\n" + testPolicy("20", "accept", "all", destination, "") + "end\n"
			if central {
				configuration += "config system settings\nset central-nat enable\nend\n"
			}
			result := assessment(t, configuration)
			if len(result.Exposures) != 2 || result.Exposures[0].Outcome != "Disabled" || result.Exposures[1].Outcome != "Configured permit" {
				t.Fatalf("disabled earlier object affected active translation: %+v", result.Exposures)
			}
			if strings.Contains(strings.Join(result.Exposures[1].Notes, " "), "earlier DNAT object overlaps") {
				t.Fatalf("disabled earlier object was considered an overlap: %+v", result.Exposures[1])
			}
		})
	}
}
