package fgt_confgen

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseConfigNestedNumericEdit guards the stack parser against the
// unquoted-edit desync: `edit 1` inside a nested sub-table (secondaryip,
// vrrp, realservers) must not pop the enclosing frames and swallow every
// subsequent entry of the section.
func TestParseConfigNestedNumericEdit(t *testing.T) {
	cfg := `
config system interface
    edit "port1"
        set vdom "root"
        config secondaryip
            edit 1
                set ip 10.0.0.2 255.255.255.0
            next
        end
        set ip 10.0.0.1 255.255.255.0
    next
    edit "port2"
        set ip 10.0.1.1 255.255.255.0
    next
end
config firewall vip
    edit "vip-lb"
        set extip 1.2.3.4
        config realservers
            edit 1
                set ip 10.0.0.10
            next
            edit 2
                set ip 10.0.0.11
            next
        end
    next
    edit "vip-plain"
        set extip 1.2.3.5
        set mappedip "10.0.0.12"
    next
end
`
	parsed := ParseConfig(cfg)
	if len(parsed.Interfaces) != 2 || parsed.Interfaces[0] != "port1" || parsed.Interfaces[1] != "port2" {
		t.Errorf("interfaces = %v, want [port1 port2]", parsed.Interfaces)
	}
	if len(parsed.VIPs) != 2 {
		t.Errorf("vips = %v, want [vip-lb vip-plain]", parsed.VIPs)
	}
}

// TestParseConfigVipGroupSections guards the section matching: VIP groups and
// NAT46/64 VIPs are IPv4-policy-usable and must be collected like plain VIPs.
func TestParseConfigVipGroupSections(t *testing.T) {
	cfg := `
config firewall vip
    edit "vip1"
        set extip 1.2.3.4
    next
end
config firewall vipgrp
    edit "vipgroup1"
        set member "vip1"
    next
end
config firewall vip46
    edit "vip46-1"
        set extip 1.2.3.5
    next
end
`
	parsed := ParseConfig(cfg)
	want := map[string]bool{"vip1": true, "vipgroup1": true, "vip46-1": true}
	if len(parsed.VIPs) != len(want) {
		t.Fatalf("vips = %v, want %v", parsed.VIPs, want)
	}
	for _, v := range parsed.VIPs {
		if !want[v] {
			t.Errorf("unexpected vip %q", v)
		}
	}
}

// TestParseConfigExampleConf parses the real fixture: the desync bug reduced
// 121 interfaces to 2, so a healthy floor proves the walker stays in sync.
func TestParseConfigExampleConf(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "example.conf"))
	if err != nil {
		t.Skipf("example.conf not available: %v", err)
	}
	parsed := ParseConfig(string(data))
	if len(parsed.Interfaces) < 100 {
		t.Errorf("only %d interfaces parsed from example.conf — nested-edit desync regressed?", len(parsed.Interfaces))
	}
	if len(parsed.Addresses) < 1000 {
		t.Errorf("only %d addresses parsed from example.conf", len(parsed.Addresses))
	}
}
