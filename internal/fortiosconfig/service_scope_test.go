package fortiosconfig

import (
	"fmt"
	"strings"
	"testing"
)

func staticNATFixture(policies string) string {
	objects := strings.NewReplacer(
		"        set portforward enable\n", "",
		"        set protocol tcp\n", "",
		"        set extport 8443\n", "",
		"        set mappedport 443\n", "",
	).Replace(testObjects)
	return testHeader + objects + "config firewall policy\n" + policies + "end\n"
}

func TestStaticNATRequiresAllProtocolCoverage(t *testing.T) {
	for _, central := range []bool{false, true} {
		for _, tc := range []struct {
			name, denyService, source, permitService, outcome, geo string
			complete                                               bool
		}{
			{"TCP deny", "ALL_TCP", "all", "ALL", "Indeterminate", "Not found", false},
			{"TCP geographic deny", "ALL_TCP", "CountryGroup", "ALL", "Indeterminate", "Partial", false},
			{"UDP geographic deny", "ALL_UDP", "CountryGroup", "ALL", "Indeterminate", "Partial", false},
			{"all-protocol deny", "ALL", "all", "ALL", "Configured deny", "Not found", true},
			{"all-protocol geographic deny", "ALL", "CountryGroup", "ALL", "Configured permit", "Applicable", true},
			{"all-protocol permit", "", "all", "ALL", "Configured permit", "Not found", true},
			{"TCP-only permit", "", "all", "ALL_TCP", "Indeterminate", "Not found", false},
		} {
			t.Run(fmt.Sprintf("central=%v/%s", central, tc.name), func(t *testing.T) {
				destination := "Portal"
				if central {
					destination = "backend"
				}
				policies := ""
				if tc.denyService != "" {
					policies = testPolicy("10", "deny", tc.source, "all", "set match-vip enable\nset service "+tc.denyService)
				}
				policies += testPolicy("20", "accept", "all", destination, "set service "+tc.permitService)
				configuration := staticNATFixture(policies)
				if central {
					configuration += "config system settings\nset central-nat enable\nend\n"
				}
				result := assessment(t, configuration)
				ex := result.Exposures[0]
				if ex.Outcome != tc.outcome || ex.GeoStatus != tc.geo || result.Complete != tc.complete {
					t.Fatalf("incorrect whole-IP mapping coverage: outcome=%q geo=%q complete=%v; want %q, %q, %v", ex.Outcome, ex.GeoStatus, result.Complete, tc.outcome, tc.geo, tc.complete)
				}
			})
		}
	}
}

func TestStaticNATIgnoresInactivePortForwardingProtocol(t *testing.T) {
	policies := testPolicy("10", "deny", "all", "all", "set match-vip enable\nset service ALL_UDP") + testPolicy("20", "accept", "all", "Portal", "set service ALL")
	configuration := strings.NewReplacer("set portforward enable", "set portforward disable", "set protocol tcp", "set protocol udp").Replace(fixture(policies))
	result := assessment(t, configuration)
	if result.Exposures[0].Outcome != "Indeterminate" || result.Complete {
		t.Fatalf("inactive port-forwarding protocol narrowed a whole-IP mapping: %+v", result.Exposures[0])
	}
}

func TestUnknownPortForwardingProtocolRemainsIndeterminate(t *testing.T) {
	configuration := strings.Replace(fixture(testPolicy("20", "accept", "all", "Portal", "set service ALL")), "set protocol tcp", "set protocol all-ip", 1)
	result := assessment(t, configuration)
	if result.Exposures[0].Outcome != "Indeterminate" || result.Complete {
		t.Fatalf("raw unknown protocol acquired the internal all-IP scope: %+v", result.Exposures[0])
	}
}

func TestCustomServiceDestinationConstraintsAreNotProtectionProof(t *testing.T) {
	for _, protocol := range []string{"set tcp-portrange 443", "set protocol IP\nset protocol-number 0"} {
		for _, tc := range []struct {
			name, settings string
			unrestricted   bool
		}{
			{"omitted default", "", true},
			{"explicit defaults", "set iprange 0.0.0.0\nset fqdn \"\"", true},
			{"full IPv4 range", "set iprange 0.0.0.0-255.255.255.255", true},
			{"unrelated address", "set iprange 192.0.2.100", false},
			{"backend address still requires NAT-stage proof", "set iprange 10.10.20.15", false},
			{"external address still requires NAT-stage proof", "set iprange 203.0.113.20", false},
			{"restricted range", "set iprange 192.0.2.1-192.0.2.254", false},
			{"FQDN", "set fqdn service.example.invalid", false},
			{"default IP plus FQDN", "set iprange 0.0.0.0\nset fqdn service.example.invalid", false},
			{"empty IP is not a default", "set iprange \"\"", false},
			{"multiple IP values", "set iprange 0.0.0.0 192.0.2.100", false},
		} {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				// Resolve through a group so a constrained member cannot acquire
				// unconditional coverage through the group's representation.
				services := "config firewall service custom\nedit Scoped\n" + protocol + "\n" + tc.settings + "\nnext\nend\n" +
					"config firewall service group\nedit ScopedGroup\nset member Scoped\nnext\nend\n"
				policies := testPolicy("10", "deny", "CountryGroup", "all", "set match-vip enable\nset service ScopedGroup") + testPolicy("20", "accept", "all", "Portal", "")
				result := assessment(t, fixture(policies)+services)
				ex := result.Exposures[0]
				if tc.unrestricted {
					if ex.Outcome != "Configured permit" || ex.GeoStatus != "Applicable" || !result.Complete {
						t.Fatalf("unrestricted service lost valid coverage: %+v", ex)
					}
				} else if ex.Outcome != "Indeterminate" || ex.GeoStatus != "Indeterminate" || result.Complete {
					t.Fatalf("unresolved service destination established protection: %+v, complete=%v", ex, result.Complete)
				}
			})
		}
	}
}

func TestConstrainedServiceCannotEstablishBlanketDenyOrPermit(t *testing.T) {
	services := "config firewall service custom\nedit Scoped\nset tcp-portrange 443\nset iprange 192.0.2.100\nnext\nend\n"
	for _, policies := range []string{
		testPolicy("10", "deny", "all", "all", "set match-vip enable\nset service Scoped") + testPolicy("20", "accept", "all", "Portal", ""),
		testPolicy("20", "accept", "all", "Portal", "set service Scoped"),
	} {
		result := assessment(t, fixture(policies)+services)
		if result.Exposures[0].Outcome != "Indeterminate" || result.Complete {
			t.Fatalf("unresolved service destination produced definitive outcome: %+v", result.Exposures[0])
		}
	}
}

func TestExplicitIPServiceProtocols(t *testing.T) {
	for _, tc := range []struct {
		name, vipProtocol, serviceName, number, outcome string
		complete                                        bool
	}{
		{"standard ALL default", "tcp", "ALL", "", "Configured permit", true},
		{"standard ALL explicit zero", "tcp", "ALL", "0", "Configured permit", true},
		{"renamed all-protocol service", "udp", "AnyIP", "0", "Configured permit", true},
		{"TCP protocol", "tcp", "IPService", "6", "Configured permit", true},
		{"UDP protocol", "udp", "IPService", "17", "Configured permit", true},
		{"SCTP protocol", "sctp", "IPService", "132", "Configured permit", true},
		{"TCP service does not cover UDP", "udp", "IPService", "6", "Conditional", true},
		{"ICMP service does not cover TCP", "tcp", "IPService", "1", "Conditional", true},
		{"customized ALL is not unrestricted", "tcp", "ALL", "17", "Conditional", true},
		{"invalid protocol number", "tcp", "ALL", "256", "Indeterminate", false},
		{"reserved protocol number", "tcp", "ALL", "255", "Indeterminate", false},
		{"negative protocol number", "tcp", "ALL", "-1", "Indeterminate", false},
		{"malformed protocol number", "tcp", "ALL", "invalid", "Indeterminate", false},
		{"multiple protocol numbers", "tcp", "ALL", "0 6", "Indeterminate", false},
		{"empty protocol number", "tcp", "ALL", "\"\"", "Indeterminate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := "set protocol IP\n"
			if tc.number != "" {
				settings += "set protocol-number " + tc.number + "\n"
			}
			services := "config firewall service custom\nedit " + tc.serviceName + "\n" + settings + "next\nend\n"
			configuration := fixture(testPolicy("20", "accept", "all", "Portal", "set service "+tc.serviceName)) + services
			configuration = strings.Replace(configuration, "set protocol tcp", "set protocol "+tc.vipProtocol, 1)
			result := assessment(t, configuration)
			if result.Exposures[0].Outcome != tc.outcome || result.Complete != tc.complete {
				t.Fatalf("incorrect explicit IP service scope: outcome=%q complete=%v; want %q, %v", result.Exposures[0].Outcome, result.Complete, tc.outcome, tc.complete)
			}
		})
	}
}

func TestIPProtocolSpecificDeniesDoNotCoverStaticNAT(t *testing.T) {
	for _, number := range []string{"1", "6", "17", "132"} {
		t.Run(number, func(t *testing.T) {
			services := "config firewall service custom\nedit IPService\nset protocol IP\nset protocol-number " + number + "\nnext\nend\n"
			policies := testPolicy("10", "deny", "CountryGroup", "all", "set match-vip enable\nset service IPService") + testPolicy("20", "accept", "all", "Portal", "set service ALL")
			result := assessment(t, staticNATFixture(policies)+services)
			if result.Exposures[0].Outcome != "Indeterminate" || result.Exposures[0].GeoStatus != "Partial" || result.Complete {
				t.Fatalf("one IP protocol covered an all-protocol mapping: %+v", result.Exposures[0])
			}
		})
	}
}
