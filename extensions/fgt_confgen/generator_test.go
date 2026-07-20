package fgt_confgen

import (
	"strings"
	"testing"
)

func minimalPolicy() Policy {
	return Policy{
		PolicyID:        "p1",
		PolicyName:      "Test",
		SrcInterfaces:   []string{"lan1"},
		DstInterfaces:   []string{"wan1"},
		SrcAddresses:    []string{"all"},
		DstAddresses:    []string{"all"},
		Action:          "accept",
		InspectionMode:  "flow",
		LogTraffic:      "all",
		LogTrafficStart: "enable",
		AutoAsicOffload: "enable",
		Nat:             "disable",
	}
}

// TestGenerateAcceptsFrontendServiceTypes guards validatePolicy against the
// types the UI actually sends: 'template' (predefined service), 'group'
// (service group) and the blank default 'Add Service' row.
func TestGenerateAcceptsFrontendServiceTypes(t *testing.T) {
	p := minimalPolicy()
	p.Services = []Service{
		{Type: "template", Name: "HTTPS"},
		{Type: "group", Name: "Web Access Group"},
		{Type: "", Name: "", Protocol: "TCP", Port: ""}, // untouched blank row
	}
	out, err := GenerateOutput1(p)
	if err != nil {
		t.Fatalf("GenerateOutput1 rejected frontend service types: %v", err)
	}
	if !strings.Contains(out, `"HTTPS"`) || !strings.Contains(out, `"Web Access Group"`) {
		t.Errorf("output missing services:\n%s", out)
	}
	if _, err := GenerateOutput2(p); err != nil {
		t.Errorf("GenerateOutput2: %v", err)
	}
	if _, err := GenerateOutput3(p); err != nil {
		t.Errorf("GenerateOutput3: %v", err)
	}
}

// TestGenerateNormalizesLegacyEmptyFields guards generation of templates
// saved by older builds / imported without the enum fields: empty values get
// the same defaults the UI form displays.
func TestGenerateNormalizesLegacyEmptyFields(t *testing.T) {
	p := minimalPolicy()
	p.Action = ""
	p.InspectionMode = ""
	p.LogTraffic = ""
	p.LogTrafficStart = ""
	p.AutoAsicOffload = ""
	p.Nat = ""
	p.Services = []Service{{Type: "template", Name: "HTTPS"}}
	out, err := GenerateOutput1(p)
	if err != nil {
		t.Fatalf("legacy template rejected: %v", err)
	}
	for _, want := range []string{"set action accept", "set inspection-mode flow",
		"set logtraffic all", "set logtraffic-start enable", "set nat disable"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestGenerateStillRejectsInjection keeps the hardening intact: control chars
// or quotes in names must still fail validation.
func TestGenerateStillRejectsInjection(t *testing.T) {
	p := minimalPolicy()
	p.Services = []Service{{Type: "template", Name: "HT\"TPS"}}
	if _, err := GenerateOutput1(p); err == nil {
		t.Error("service name with embedded quote must be rejected")
	}
	p = minimalPolicy()
	p.Action = "accept\nset action deny"
	p.Services = []Service{{Type: "template", Name: "HTTPS"}}
	if _, err := GenerateOutput1(p); err == nil {
		t.Error("action outside the enum must be rejected")
	}
}

// TestGenerateSrcISDBUsesSrcKeys: the source-side ISDB block must emit the
// -src- CLI keys (internet-service-id is the destination-side key).
func TestGenerateSrcISDBUsesSrcKeys(t *testing.T) {
	p := minimalPolicy()
	p.SrcAddresses = nil
	p.SrcInternetServices = []string{"65536", "Google-Web"}
	p.Services = []Service{{Type: "template", Name: "HTTPS"}}
	out, err := GenerateOutput1(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `set internet-service-src-id "65536"`) {
		t.Errorf("missing internet-service-src-id:\n%s", out)
	}
	if !strings.Contains(out, `set internet-service-src-name "Google-Web"`) {
		t.Errorf("missing internet-service-src-name:\n%s", out)
	}
	if strings.Contains(out, "set internet-service-id ") {
		t.Errorf("src block must not emit the destination-side internet-service-id key:\n%s", out)
	}
}

// TestGenerateWhitespaceEntriesExcluded: whitespace-only list values (UI
// padding) are treated as empty everywhere, so a blank address never validates
// past mutual-exclusion only to be emitted next to the Internet-Service block
// (a combination FortiOS rejects), and surrounding whitespace on a real value
// is trimmed on emission.
func TestGenerateWhitespaceEntriesExcluded(t *testing.T) {
	p := minimalPolicy()
	p.DstAddresses = []string{"   "}
	p.DstInternetServices = []string{"Google-Web"}
	p.Services = []Service{{Type: "template", Name: "HTTPS"}}
	out, err := GenerateOutput1(p)
	if err != nil {
		t.Fatalf("whitespace-only dstaddr must be ignored, not rejected: %v", err)
	}
	if !strings.Contains(out, "set internet-service enable") {
		t.Errorf("expected destination ISDB block:\n%s", out)
	}
	if strings.Contains(out, "set dstaddr") {
		t.Errorf("whitespace-only dstaddr must not be emitted alongside ISDB:\n%s", out)
	}

	p = minimalPolicy()
	p.SrcAddresses = []string{"  lan-net  ", "   "}
	p.Services = []Service{{Type: "template", Name: "HTTPS"}}
	out, err = GenerateOutput1(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `set srcaddr "lan-net"`) {
		t.Errorf("surrounding whitespace on a real srcaddr must be trimmed:\n%s", out)
	}
}
