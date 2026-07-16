package fgt_polsplit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set role wan
    next
    edit "lan1"
        set ip 10.0.0.254 255.255.255.0
        set role lan
        config secondaryip
            edit 1
                set ip 10.0.1.254 255.255.255.0
            next
        end
    next
end
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
        edit "SD-WAN-Internet"
        next
    end
    config members
        edit 1
            set interface "wan2"
        next
    end
end
config firewall internet-service-name
    edit "Google-Web"
        set internet-service-id 65537
    next
    edit "Microsoft-Office.365"
        set internet-service-id 327781
    next
end
config firewall vip
    edit "VIP_Web"
        set extip 203.0.113.10
        set mappedip "10.0.0.80"
    next
end
config system automation-action
    edit "Script_Fix"
        set action-type cli-script
        set script "config system central-management
set mode backup
end
next
config firewall address
edit \"EVIL_FAKE\"
next
end"
    next
end
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
	pb := ParseBackup(testConfig, 5, "")
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
	pb := ParseBackup(testConfig, 5, "")

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
	// A single contiguous range registers an exact range key.
	if got := pb.SvcByKey["tcp/8000-8010"]; len(got) != 1 || got[0] != "MYRANGE" {
		t.Errorf("range key lookup = %v", got)
	}
	// Group member sets are indexed by signature for exact-match reuse.
	if got := pb.AddrGrpBySig[groupSig([]string{"H_Server1"})]; got != "G_Servers" {
		t.Errorf("addrgrp sig lookup = %q", got)
	}
	if got := pb.SvcGrpBySig[groupSig([]string{"HTTPS"})]; got != "Web Access Group" {
		t.Errorf("svcgrp sig lookup = %q", got)
	}
	// WAN classification: role wan + SD-WAN member + the builtin and custom
	// SD-WAN zone names (policies reference zones directly in dstintf).
	for _, want := range []string{"wan1", "wan2", "virtual-wan-link", "sd-wan-internet"} {
		if !pb.WANInterfaces[want] {
			t.Errorf("WANInterfaces missing %q: %v", want, pb.WANInterfaces)
		}
	}
	if pb.WANInterfaces["lan1"] {
		t.Error("lan1 must not be WAN-classified")
	}
	// Firewall self-IPs from interface definitions, including secondaryip.
	if !pb.FirewallIPs["203.0.113.2"] || !pb.FirewallIPs["10.0.0.254"] || !pb.FirewallIPs["10.0.1.254"] {
		t.Errorf("FirewallIPs = %v", pb.FirewallIPs)
	}
	// ISDB names collected for internet-service suggestions.
	if len(pb.ISDBNames) != 2 || pb.ISDBNames[0] != "Google-Web" {
		t.Errorf("ISDBNames = %v", pb.ISDBNames)
	}
	// The DNS object (tcp+udp 53) is an exact dual-protocol match.
	if got := pb.SvcByKey["tcpudp/53"]; len(got) != 1 || got[0] != "DNS" {
		t.Errorf("tcpudp/53 = %v", got)
	}
	// VIPs share the address namespace and must count as taken.
	for _, name := range []string{"h_server1", "g_servers", "https", "all_icmp", "vip_web"} {
		if !pb.TakenNames[name] {
			t.Errorf("taken names missing %q", name)
		}
	}
	// The automation-action script embeds raw CLI (end/next/config/edit
	// lines) inside one quoted value — none of it may leak into the
	// inventory or desync the section stack (the address assertions above
	// already prove the sections AFTER the script parsed intact).
	if pb.TakenNames["evil_fake"] {
		t.Error("embedded script content leaked into the parsed inventory")
	}
}

func TestQuoteOpen(t *testing.T) {
	cases := []struct {
		line string
		in   bool
		want bool
	}{
		{`set comment "all closed"`, false, false},
		{`set script "still open`, false, true},
		{`plain text inside a value`, true, true},
		{`ends the value"`, true, false},
		{`edit \"escaped\" stays open`, true, true},
		{`set x "a" "b" "c"`, false, false},
	}
	for _, c := range cases {
		if got := quoteOpen(c.line, c.in); got != c.want {
			t.Errorf("quoteOpen(%q, %v) = %v, want %v", c.line, c.in, got, c.want)
		}
	}
}

func TestParseBackupVDOM(t *testing.T) {
	cfg := `
config vdom
edit root
config firewall address
    edit "H_Local"
        set subnet 10.0.0.1 255.255.255.255
    next
end
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
config firewall address
    edit "H_Local"
        set subnet 192.168.1.1 255.255.255.255
    next
end
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
	// 1. Ambiguity: default to root (first match)
	pb := ParseBackup(cfg, 5, "")
	if pb.Policy == nil {
		t.Fatal("policy 5 not found")
	}
	if pb.Policy.VDOM != "root" {
		t.Errorf("vdom = %q", pb.Policy.VDOM)
	}
	if len(pb.PolicyVDOMs) != 2 || pb.PolicyVDOMs[0] != "root" || pb.PolicyVDOMs[1] != "dmz" {
		t.Errorf("policy vdoms = %v", pb.PolicyVDOMs)
	}
	if len(pb.UsedPolicyIDs) != 1 || pb.UsedPolicyIDs[0] != 5 {
		t.Errorf("used policy IDs = %v", pb.UsedPolicyIDs)
	}
	// Assert root-level objects
	if got := pb.AddrByCIDR["10.0.0.1/32"]; len(got) != 1 || got[0] != "H_Local" {
		t.Errorf("root H_Local address lookup = %v", got)
	}
	if got := pb.AddrByCIDR["192.168.1.1/32"]; len(got) != 0 {
		t.Errorf("dmz address leaked to root: %v", got)
	}

	// 2. Select DMZ VDOM explicitly
	pbDMZ := ParseBackup(cfg, 5, "dmz")
	if pbDMZ.Policy == nil {
		t.Fatal("policy 5 not found in dmz")
	}
	if pbDMZ.Policy.VDOM != "dmz" {
		t.Errorf("vdom = %q", pbDMZ.Policy.VDOM)
	}
	if len(pbDMZ.UsedPolicyIDs) != 2 || pbDMZ.UsedPolicyIDs[0] != 5 || pbDMZ.UsedPolicyIDs[1] != 9 {
		t.Errorf("dmz used policy IDs = %v", pbDMZ.UsedPolicyIDs)
	}
	// Assert dmz-level objects
	if got := pbDMZ.AddrByCIDR["192.168.1.1/32"]; len(got) != 1 || got[0] != "H_Local" {
		t.Errorf("dmz H_Local address lookup = %v", got)
	}
	if got := pbDMZ.AddrByCIDR["10.0.0.1/32"]; len(got) != 0 {
		t.Errorf("root address leaked to dmz: %v", got)
	}

	// 3. An explicit VDOM that matches nothing must NOT silently fall back to
	// another VDOM's policy — that would hand the caller the wrong object
	// inventory and policy-ID space.
	pbMiss := ParseBackup(cfg, 5, "does-not-exist")
	if pbMiss.Policy != nil {
		t.Errorf("expected no policy for unmatched vdom, got vdom %q", pbMiss.Policy.VDOM)
	}
	if len(pbMiss.PolicyVDOMs) != 2 {
		t.Errorf("PolicyVDOMs should still list the matches: %v", pbMiss.PolicyVDOMs)
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
	pb := ParseBackup(string(data), 611, "")
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
