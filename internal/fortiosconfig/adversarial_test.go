package fortiosconfig

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func TestEarlierAddressRangeOrUnresolvedVIPPreventsPositiveGeoClaim(t *testing.T) {
	for _, tc := range []struct {
		name, address string
		overlap       bool
	}{
		{"hyphen range", "203.0.113.10-203.0.113.40", true},
		{"two endpoints", "203.0.113.10 203.0.113.40", true},
		{"dynamic interface", "0.0.0.0", true},
		{"unresolved address", "listener.example.invalid", true},
		{"disjoint range", "203.0.114.10-203.0.114.40", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := fmt.Sprintf(`config firewall vip
edit Earlier
set extip %s
set extintf wan2
set mappedip 10.10.20.99
set portforward enable
set extport 8443
set mappedport 443
next
end
`, tc.address)
			policies := testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable") + testPolicy("20", "accept", "all", "Portal", "") + testPolicy("50", "accept", "all", "Earlier", "")
			result := assessment(t, testHeader+prior+testObjects+"config firewall policy\n"+policies+"end\n")
			ex := result.Exposures[1]
			if tc.overlap {
				if ex.Outcome != "Indeterminate" || ex.GeoStatus != "Indeterminate" {
					t.Fatalf("possible DNAT overlap produced a positive claim: %+v", ex)
				}
			} else if ex.Outcome != "Configured permit" || ex.GeoStatus != "Applicable" {
				t.Fatalf("known-disjoint range must not poison another listener: %+v", ex)
			}
		})
	}
}

func TestUnresolvedMappingOrPolicyReferencePreventsGeoClaim(t *testing.T) {
	base := fixture(testPolicy("900", "deny", "CountryGroup", "all", "set match-vip enable") + testPolicy("20", "accept", "all", "Portal", ""))
	cases := []string{
		strings.ReplaceAll(base, "set mappedport 443", "set mappedport invalid"),
		strings.ReplaceAll(base, "set mappedip \"10.10.20.15\"", "set mappedip \"backend.example.invalid\""),
		strings.ReplaceAll(base, "config firewall policy\n", "config firewall policy\n"+testPolicy("7", "deny", "all", "MissingDestination", "set match-vip enable")),
	}
	for index, configuration := range cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			ex := assessment(t, configuration).Exposures[0]
			if ex.GeoStatus != "Indeterminate" || ex.Outcome != "Indeterminate" {
				t.Fatalf("unresolved dependency produced a positive geo claim: %+v", ex)
			}
		})
	}
}

func diamondGroups(inv *inventory, table map[string]*node, prefix, leaf string) string {
	previous := leaf
	for i := 0; i < 48; i++ {
		name := fmt.Sprintf("%s%d", prefix, i)
		table[name] = &node{values: map[string][]string{"member": {previous, previous}}}
		previous = name
	}
	return previous
}

func TestDiamondGroupGraphsAreResolvedOnce(t *testing.T) {
	for _, kind := range []string{"sources", "address match", "services", "VIP references"} {
		t.Run(kind, func(t *testing.T) {
			inv := newInventory()
			switch kind {
			case "sources":
				inv.addresses["Country"] = &node{values: map[string][]string{"type": {"geography"}, "country": {"CN"}}}
				name := diamondGroups(inv, inv.addressGroups, "A", "Country")
				value := inv.sources([]string{name})
				if value.unknown || len(value.countries) != 1 || value.countries[0] != "CN" {
					t.Fatalf("wrong source result: %+v", value)
				}
			case "address match":
				inv.addresses["Backend"] = &node{values: map[string][]string{"subnet": {"10.0.0.1", "255.255.255.255"}}}
				name := diamondGroups(inv, inv.addressGroups, "A", "Backend")
				yes, unknown := inv.addressMatch([]string{name}, netip.MustParseAddr("192.0.2.1"))
				if yes || unknown {
					t.Fatalf("wrong address result: match=%v unknown=%v", yes, unknown)
				}
			case "services":
				name := diamondGroups(inv, inv.serviceGroups, "S", "HTTPS")
				value := inv.servicesFor([]string{name})
				if value.unknown || len(value.ports["tcp"]) != 1 {
					t.Fatalf("service graph expanded duplicates: %+v", value)
				}
			case "VIP references":
				inv.vipNames["OtherVIP"] = true
				name := diamondGroups(inv, inv.vipGroups, "V", "OtherVIP")
				yes, unknown := inv.references([]string{name}, "TargetVIP")
				if yes || unknown {
					t.Fatalf("wrong VIP result: match=%v unknown=%v", yes, unknown)
				}
			}
			if inv.work.err != nil {
				t.Fatal(inv.work.err)
			}
			if used := 20000000 - inv.work.remaining; used > 1000 {
				t.Fatalf("diamond graph consumed %d work units; repeated nodes were expanded", used)
			}
		})
	}
}

func TestExcessiveGroupFanoutFailsWithoutPartialAssessment(t *testing.T) {
	configuration := fixture(testPolicy("20", "accept", "all", "Portal", "set service HugeGroup")) + "config firewall service group\nedit HugeGroup\nset member " + strings.Repeat("HTTPS ", 10001) + "\nnext\nend\n"
	result, err := Analyze(context.Background(), []byte(configuration))
	if err == nil || !strings.Contains(err.Error(), "resolution limit") {
		t.Fatalf("expected bounded resolver failure, got %v", err)
	}
	if result.Complete || len(result.Exposures) > 0 {
		t.Fatalf("budget exhaustion published partial positive data: %+v", result)
	}
}

type countingCancellation struct {
	context.Context
	cancel        context.CancelFunc
	checks, after int
}

func (c *countingCancellation) Err() error {
	c.checks++
	if c.checks >= c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCancellationIsCheckedInsideLongQuotedValues(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &countingCancellation{Context: base, cancel: cancel, after: 10}
	configuration := testHeader + "config system automation-action\nedit Task\nset script \"" + strings.Repeat("next\nend\n", 10000) + "done\"\nnext\nend\n"
	if _, err := parse(ctx, []byte(configuration)); err != context.Canceled {
		t.Fatalf("long quoted value did not honor cancellation: %v", err)
	}
}

func TestLongQuotedValueUsesLinearScan(t *testing.T) {
	configuration := testHeader + "config system automation-action\nedit Task\nset script \"" + strings.Repeat("next\nend\n", 10000) + "done\"\nnext\nend\n"
	doc, err := parse(context.Background(), []byte(configuration))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.sections) != 1 || len(doc.objects("system automation-action")) != 1 {
		t.Fatalf("embedded commands escaped multiline value: %+v", doc)
	}
}

func TestGeoExplanationAmplificationFailsBeforeLargeOutput(t *testing.T) {
	// Only 140 policies and one VIP, well below the traversal/relationship
	// bounds, create 4,900 distinct deny/permit explanations without this guard.
	var policies strings.Builder
	for i := 0; i < 70; i++ {
		policies.WriteString(testPolicy(fmt.Sprint(100+i), "deny", "CountryGroup", "all", "set match-vip enable"))
	}
	for i := 0; i < 70; i++ {
		policies.WriteString(testPolicy(fmt.Sprint(200+i), "accept", "all", "Portal", ""))
	}
	configuration := fixture(policies.String())
	if len(configuration) > 100000 {
		t.Fatal("adversarial fixture unexpectedly large")
	}
	result, err := Analyze(context.Background(), []byte(configuration))
	if err == nil || !strings.Contains(err.Error(), "note output limit") {
		t.Fatalf("expected bounded note failure, got %v", err)
	}
	if result.Complete || len(result.Exposures) != 0 || len(result.Findings) != 0 {
		t.Fatalf("note exhaustion published a partial assessment: %+v", result)
	}
}

func TestNoteBudgetCheckedBeforeFormatting(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			inv := newInventory()
			if kind == "count" {
				inv.work.notesRemaining = 0
			} else {
				inv.work.noteBytesRemaining = 0
			}
			built := false
			ex := reportmodel.Exposure{}
			ok := inv.appendNote(&ex, 20, func() string { built = true; return "must not be built" })
			if ok || built || len(ex.Notes) != 0 || inv.work.err == nil {
				t.Fatalf("exhausted budget permitted formatting: ok=%v built=%v notes=%v err=%v", ok, built, ex.Notes, inv.work.err)
			}
		})
	}
}
