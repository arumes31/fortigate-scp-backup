package fgt_confconv

import (
	"fmt"
	"strings"
)

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func removeStr(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func dedupStr(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, v := range list {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func replaceStr(list []string, old, new string) []string {
	out := make([]string, len(list))
	for i, v := range list {
		if v == old {
			out[i] = new
		} else {
			out[i] = v
		}
	}
	return out
}

// quoteJoin renders a member/interface list the way FortiGate CLI expects:
// space-separated, each element double-quoted.
func quoteJoin(list []string) string {
	parts := make([]string, len(list))
	for i, v := range list {
		parts[i] = `"` + v + `"`
	}
	return strings.Join(parts, " ")
}

// referencingPolicies returns the IDs of policies whose srcintf/dstintf list
// contains ifaceName.
func referencingPolicies(cfg *FGConfig, ifaceName string) []int {
	var ids []int
	for _, p := range cfg.Policies {
		if containsStr(p.SrcIntf, ifaceName) || containsStr(p.DstIntf, ifaceName) {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

// referencingRoutes returns the sequence numbers of active static routes
// whose device is ifaceName.
func referencingRoutes(cfg *FGConfig, ifaceName string) []int {
	var seqs []int
	for _, rt := range cfg.StaticRoutes {
		if rt.Device == ifaceName && !rt.Disabled {
			seqs = append(seqs, rt.Seq)
		}
	}
	return seqs
}

// zoneContaining returns the name of the system zone ifaceName currently
// belongs to, or "" if none.
func zoneContaining(cfg *FGConfig, ifaceName string) string {
	for name, z := range cfg.Zones {
		if containsStr(z.Interfaces, ifaceName) {
			return name
		}
	}
	return ""
}

// isSDWANMember reports whether ifaceName is already an SD-WAN member.
func isSDWANMember(cfg *FGConfig, ifaceName string) bool {
	for _, m := range cfg.SDWANMembers {
		if m.Interface == ifaceName {
			return true
		}
	}
	return false
}

// replaceInterfaceInPolicies substitutes oldName with newName in every
// policy's srcintf/dstintf list that references it, de-duplicating the list
// afterward (in case the policy already referenced newName too). Returns the
// IDs of every policy it touched, in encounter order.
func replaceInterfaceInPolicies(cfg *FGConfig, oldName, newName string) []int {
	var touched []int
	for _, p := range cfg.Policies {
		changed := false
		if containsStr(p.SrcIntf, oldName) {
			p.SrcIntf = dedupStr(replaceStr(p.SrcIntf, oldName, newName))
			changed = true
		}
		if containsStr(p.DstIntf, oldName) {
			p.DstIntf = dedupStr(replaceStr(p.DstIntf, oldName, newName))
			changed = true
		}
		if changed {
			touched = append(touched, p.ID)
		}
	}
	return touched
}

// policyByID finds a policy by ID (nil if not found).
func policyByID(cfg *FGConfig, id int) *PolicyEntry {
	for _, p := range cfg.Policies {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// cliPolicyIntfBlock renders the CLI needed to set a policy's srcintf/dstintf
// to their current (already-mutated) values.
func cliPolicyIntfBlock(p *PolicyEntry) []string {
	return []string{
		"config firewall policy",
		fmt.Sprintf("    edit %d", p.ID),
		fmt.Sprintf("        set srcintf %s", quoteJoin(p.SrcIntf)),
		fmt.Sprintf("        set dstintf %s", quoteJoin(p.DstIntf)),
		"    next",
		"end",
	}
}
