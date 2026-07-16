package fgt_polsplit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `
config firewall address
    edit "H_Server1"
        set uuid aaaa-bbbb
        set subnet 10.0.0.10 255.255.255.255
    next
    edit "LAN_Users"
        set subnet 192.168.10.0 255.255.255.0
    next
    edit "H_Range_Single"
        set type iprange
        set start-ip 10.0.0.20
        set end-ip 10.0.0.20
    next
    edit "H_Tagged"
        set subnet 10.0.0.30 255.255.255.255
        config tagging
            edit "t1"
                set category "cat"
            next
        end
        set comment "after nested block"
    next
    edit "FQDN_Site"
        set type fqdn
        set fqdn "example.com"
    next
end
config firewall addrgrp
    edit "G_Servers"
        set member "H_Server1"
    next
end
config firewall service custom
    edit "HTTPS"
        set category "Web Access"
        set tcp-portrange 443
    next
    edit "DNS"
        set tcp-portrange 53
        set udp-portrange 53
    next
    edit "MYRANGE"
        set tcp-portrange 8000-8010
    next
    edit "ALL_ICMP"
        set protocol ICMP
    next
    edit "PING"
        set protocol ICMP
        set icmptype 8
    next
    edit "GRE"
        set protocol IP
        set protocol-number 47
    next
end
config firewall service group
    edit "Web Access Group"
        set member "HTTPS"
    next
end
config firewall policy
    edit 5
        set name "Open Policy"
        set uuid cccc-dddd
        set srcintf "lan1" "lan2"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set av-profile "default"
        set logtraffic all
        set nat enable
        set comments "too open"
    next
    edit 12
        set srcintf "lan1"
        set dstintf "wan1"
        set action accept
        set srcaddr "H_Server1"
        set dstaddr "all"
        set schedule "always"
        set service "HTTPS"
    next
end
`

func TestParseBackupPolicy(t *testing.T) {
	pb := ParseBackup(testConfig, 5)
	if pb.Policy == nil {
		t.Fatal("policy 5 not found")
	}
	p := pb.Policy
	if p.Name != "Open Policy" {
		t.Errorf("name = %q", p.Name)
	}
	if len(p.SrcIntf) != 2 || p.SrcIntf[0] != "lan1" || p.SrcIntf[1] != "lan2" {
		t.Errorf("srcintf = %v", p.SrcIntf)
	}
	if p.Action != "accept" || p.NAT != "enable" || p.Schedule != "always" {
		t.Errorf("action/nat/schedule = %q/%q/%q", p.Action, p.NAT, p.Schedule)
	}
	if p.Comments != "too open" {
		t.Errorf("comments = %q", p.Comments)
	}
	joined := strings.Join(p.CloneLines, "\n")
	for _, want := range []string{`set srcintf "lan1" "lan2"`, "set action accept", "set nat enable",
		"set utm-status enable", `set ssl-ssh-profile "certificate-inspection"`, `set av-profile "default"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("clone lines missing %q:\n%s", want, joined)
		}
	}
	for _, notWant := range []string{"set name", "set uuid", "set srcaddr", "set dstaddr", "set service", "set logtraffic", "set comments"} {
		if strings.Contains(joined, notWant) {
			t.Errorf("clone lines must not carry %q:\n%s", notWant, joined)
		}
	}
	if len(pb.UsedPolicyIDs) != 2 || pb.UsedPolicyIDs[0] != 5 || pb.UsedPolicyIDs[1] != 12 {
		t.Errorf("used policy IDs = %v", pb.UsedPolicyIDs)
	}
}

func TestParseBackupObjects(t *testing.T) {
	pb := ParseBackup(testConfig, 5)

	if got := pb.AddrByCIDR["10.0.0.10/32"]; len(got) != 1 || got[0] != "H_Server1" {
		t.Errorf("host lookup = %v", got)
	}
	if got := pb.AddrByCIDR["192.168.10.0/24"]; len(got) != 1 || got[0] != "LAN_Users" {
		t.Errorf("subnet lookup = %v", got)
	}
	if got := pb.AddrByCIDR["10.0.0.20/32"]; len(got) != 1 || got[0] != "H_Range_Single" {
		t.Errorf("single-ip range lookup = %v", got)
	}
	// The nested `config tagging` block must not break the enclosing object.
	if got := pb.AddrByCIDR["10.0.0.30/32"]; len(got) != 1 || got[0] != "H_Tagged" {
		t.Errorf("tagged host lookup = %v", got)
	}

	if got := pb.SvcByKey["tcp/443"]; len(got) != 1 || got[0] != "HTTPS" {
		t.Errorf("tcp/443 = %v", got)
	}
	if got := pb.SvcByKey["tcp/53"]; len(got) != 0 {
		t.Errorf("multi-proto DNS must not be a single-key service, got %v", got)
	}
	if got := pb.SvcByKey["icmp"]; len(got) != 1 || got[0] != "ALL_ICMP" {
		t.Errorf("icmp = %v (PING has an icmptype and must not match)", got)
	}
	if got := pb.SvcByKey["ip-47"]; len(got) != 1 || got[0] != "GRE" {
		t.Errorf("ip-47 = %v", got)
	}
	if _, ok := pb.SvcByKey["tcp/8000"]; ok {
		t.Error("port range must not register a single-port key")
	}

	if pb.SvcNames["https"] != "HTTPS" || pb.SvcNames["web access group"] != "Web Access Group" {
		t.Errorf("service name map = %v", pb.SvcNames)
	}
	for _, name := range []string{"h_server1", "g_servers", "https", "all_icmp"} {
		if !pb.TakenNames[name] {
			t.Errorf("taken names missing %q", name)
		}
	}
}

func TestParseBackupVDOM(t *testing.T) {
	cfg := `
config vdom
edit root
config firewall policy
    edit 5
        set srcintf "a"
        set dstintf "b"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
next
edit dmz
config firewall policy
    edit 5
        set srcintf "x"
        set dstintf "y"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
    edit 9
        set srcintf "x"
        set dstintf "y"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
next
end
`
	pb := ParseBackup(cfg, 5)
	if pb.Policy == nil {
		t.Fatal("policy 5 not found")
	}
	if pb.Policy.VDOM != "root" {
		t.Errorf("vdom = %q", pb.Policy.VDOM)
	}
	if len(pb.PolicyVDOMs) != 2 {
		t.Errorf("policy vdoms = %v", pb.PolicyVDOMs)
	}
	// ID space restricted to the matched VDOM (root has only ID 5).
	if len(pb.UsedPolicyIDs) != 1 || pb.UsedPolicyIDs[0] != 5 {
		t.Errorf("used policy IDs = %v", pb.UsedPolicyIDs)
	}
}

func TestSplitConfigValues(t *testing.T) {
	got := splitConfigValues(`"VL100" "guest wifi" always`)
	want := []string{"VL100", "guest wifi", "always"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseBackupExampleConf parses the real 1.9 MB fixture and spot-checks
// known entries so the parser is proven against genuine FortiOS output.
func TestParseBackupExampleConf(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "example.conf"))
	if err != nil {
		t.Skipf("example.conf not available: %v", err)
	}
	pb := ParseBackup(string(data), 611)
	if pb.Policy == nil {
		t.Fatal("policy 611 not found in example.conf")
	}
	p := pb.Policy
	if p.Action != "accept" || p.NAT != "enable" {
		t.Errorf("action/nat = %q/%q", p.Action, p.NAT)
	}
	if len(p.SrcAddr) != 1 || p.SrcAddr[0] != "LAN_Internal-Server" {
		t.Errorf("srcaddr = %v", p.SrcAddr)
	}
	if len(pb.UsedPolicyIDs) < 3 {
		t.Errorf("expected many policy IDs, got %d", len(pb.UsedPolicyIDs))
	}
	if got := pb.AddrByCIDR["192.168.100.0/23"]; len(got) == 0 || got[0] != "LAN_Internal" {
		t.Errorf("LAN_Internal lookup = %v", got)
	}
	if got := pb.SvcByKey["tcp/443"]; len(got) == 0 || got[0] != "HTTPS" {
		t.Errorf("tcp/443 = %v", got)
	}
}
