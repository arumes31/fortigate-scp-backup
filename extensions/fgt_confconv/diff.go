package fgt_confconv

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

const maxConfigChanges = 500

// ConfigChange is a bounded, value-free description of one modeled object
// mutation. Summary deliberately names changed fields but never their values;
// configuration values remain confined to the generated CLI review.
type ConfigChange struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Action  string `json:"action"`
	Summary string `json:"summary"`
}

// DiffConfigs compares the parsed source model with the post-pipeline model.
// It returns at most maxConfigChanges rows in deterministic order while total
// still reports the complete number of modeled mutations.
func DiffConfigs(before, after *FGConfig) (changes []ConfigChange, total int, truncated bool) {
	if before == nil || after == nil {
		return []ConfigChange{}, 0, false
	}

	changes = append(changes, diffInterfaces(before.Interfaces, after.Interfaces)...)
	changes = append(changes, diffZones(before.Zones, after.Zones)...)
	changes = append(changes, diffPolicies(before.Policies, after.Policies)...)
	changes = append(changes, diffRoutes(before.StaticRoutes, after.StaticRoutes)...)
	changes = append(changes, diffSDWANZones(before.SDWANZones, after.SDWANZones)...)
	changes = append(changes, diffSDWANMembers(before.SDWANMembers, after.SDWANMembers)...)
	changes = append(changes, diffSDWANRules(before.SDWANRules, after.SDWANRules)...)
	changes = append(changes, diffStringMaps("SD-WAN health check", before.SDWANHealthChecks, after.SDWANHealthChecks)...)

	sort.Slice(changes, func(i, j int) bool {
		left, right := changes[i], changes[j]
		if changeKindRank(left.Kind) != changeKindRank(right.Kind) {
			return changeKindRank(left.Kind) < changeKindRank(right.Kind)
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Action < right.Action
	})

	total = len(changes)
	if total > maxConfigChanges {
		changes = changes[:maxConfigChanges]
		truncated = true
	}
	if changes == nil {
		changes = []ConfigChange{}
	}
	return changes, total, truncated
}

func changeKindRank(kind string) int {
	switch kind {
	case "interface":
		return 10
	case "zone":
		return 20
	case "policy":
		return 30
	case "static route":
		return 40
	case "SD-WAN zone":
		return 50
	case "SD-WAN member":
		return 60
	case "SD-WAN rule":
		return 70
	case "SD-WAN health check":
		return 80
	default:
		return 100
	}
}

func diffInterfaces(before, after map[string]*InterfaceEntry) []ConfigChange {
	var out []ConfigChange
	for _, name := range sortedStringUnion(interfaceKeys(before), interfaceKeys(after)) {
		left, leftOK := before[name]
		right, rightOK := after[name]
		switch {
		case !leftOK && rightOK:
			out = append(out, ConfigChange{Kind: "interface", Name: name, Action: "create", Summary: "Created interface."})
		case leftOK && !rightOK:
			out = append(out, ConfigChange{Kind: "interface", Name: name, Action: "delete", Summary: "Deleted interface."})
		case leftOK && rightOK:
			var fields []string
			if left.Type != right.Type {
				fields = append(fields, "type")
			}
			if left.Parent != right.Parent {
				fields = append(fields, "parent interface")
			}
			if left.VLANID != right.VLANID {
				fields = append(fields, "VLAN ID")
			}
			if left.IP != right.IP {
				fields = append(fields, "IP address")
			}
			if left.Allowaccess != right.Allowaccess {
				fields = append(fields, "administrative access")
			}
			if left.Role != right.Role {
				fields = append(fields, "role")
			}
			if !slices.Equal(left.Members, right.Members) {
				fields = append(fields, "member ports")
			}
			if left.Fortilink != right.Fortilink {
				fields = append(fields, "FortiLink state")
			}
			if len(fields) > 0 {
				out = append(out, updatedChange("interface", name, fields))
			}
		}
	}
	return out
}

func diffZones(before, after map[string]*ZoneEntry) []ConfigChange {
	var out []ConfigChange
	for _, name := range sortedStringUnion(zoneKeys(before), zoneKeys(after)) {
		left, leftOK := before[name]
		right, rightOK := after[name]
		switch {
		case !leftOK && rightOK:
			out = append(out, ConfigChange{Kind: "zone", Name: name, Action: "create", Summary: "Created zone."})
		case leftOK && !rightOK:
			out = append(out, ConfigChange{Kind: "zone", Name: name, Action: "delete", Summary: "Deleted zone."})
		case leftOK && rightOK:
			var fields []string
			if !slices.Equal(left.Interfaces, right.Interfaces) {
				fields = append(fields, "interfaces")
			}
			if left.IntrazoneDeny != right.IntrazoneDeny {
				fields = append(fields, "intrazone policy")
			}
			if len(fields) > 0 {
				out = append(out, updatedChange("zone", name, fields))
			}
		}
	}
	return out
}

func diffPolicies(before, after []*PolicyEntry) []ConfigChange {
	left := make(map[int]*PolicyEntry, len(before))
	right := make(map[int]*PolicyEntry, len(after))
	for _, policy := range before {
		left[policy.ID] = policy
	}
	for _, policy := range after {
		right[policy.ID] = policy
	}
	var out []ConfigChange
	for _, id := range sortedIntUnion(intKeys(left), intKeys(right)) {
		beforePolicy, leftOK := left[id]
		afterPolicy, rightOK := right[id]
		name := strconv.Itoa(id)
		switch {
		case !leftOK && rightOK:
			out = append(out, ConfigChange{Kind: "policy", Name: name, Action: "create", Summary: "Created policy."})
		case leftOK && !rightOK:
			out = append(out, ConfigChange{Kind: "policy", Name: name, Action: "delete", Summary: "Deleted policy."})
		case leftOK && rightOK:
			var fields []string
			if !slices.Equal(beforePolicy.SrcIntf, afterPolicy.SrcIntf) {
				fields = append(fields, "source interfaces")
			}
			if !slices.Equal(beforePolicy.DstIntf, afterPolicy.DstIntf) {
				fields = append(fields, "destination interfaces")
			}
			if len(fields) > 0 {
				out = append(out, updatedChange("policy", name, fields))
			}
		}
	}
	return out
}

func diffRoutes(before, after []*RouteEntry) []ConfigChange {
	left := make(map[int]*RouteEntry, len(before))
	right := make(map[int]*RouteEntry, len(after))
	for _, route := range before {
		left[route.Seq] = route
	}
	for _, route := range after {
		right[route.Seq] = route
	}
	var out []ConfigChange
	for _, seq := range sortedIntUnion(intKeys(left), intKeys(right)) {
		beforeRoute, leftOK := left[seq]
		afterRoute, rightOK := right[seq]
		name := strconv.Itoa(seq)
		switch {
		case !leftOK && rightOK:
			out = append(out, ConfigChange{Kind: "static route", Name: name, Action: "create", Summary: "Created static route."})
		case leftOK && !rightOK:
			out = append(out, ConfigChange{Kind: "static route", Name: name, Action: "delete", Summary: "Deleted static route."})
		case leftOK && rightOK && !beforeRoute.Disabled && afterRoute.Disabled:
			out = append(out, ConfigChange{Kind: "static route", Name: name, Action: "disable", Summary: "Disabled superseded static route."})
		case leftOK && rightOK:
			var fields []string
			if beforeRoute.Dst != afterRoute.Dst {
				fields = append(fields, "destination")
			}
			if beforeRoute.Device != afterRoute.Device {
				fields = append(fields, "device")
			}
			if beforeRoute.Gateway != afterRoute.Gateway {
				fields = append(fields, "gateway")
			}
			if beforeRoute.Disabled != afterRoute.Disabled {
				fields = append(fields, "status")
			}
			if len(fields) > 0 {
				out = append(out, updatedChange("static route", name, fields))
			}
		}
	}
	return out
}

func diffSDWANZones(before, after map[string]*SDWANZone) []ConfigChange {
	return diffStringMaps("SD-WAN zone", sdwanZoneKeys(before), sdwanZoneKeys(after))
}

func diffSDWANMembers(before, after []*SDWANMember) []ConfigChange {
	left := make(map[int]*SDWANMember, len(before))
	right := make(map[int]*SDWANMember, len(after))
	for _, member := range before {
		left[member.Seq] = member
	}
	for _, member := range after {
		right[member.Seq] = member
	}
	var out []ConfigChange
	for _, seq := range sortedIntUnion(intKeys(left), intKeys(right)) {
		beforeMember, leftOK := left[seq]
		afterMember, rightOK := right[seq]
		name := strconv.Itoa(seq)
		switch {
		case !leftOK && rightOK:
			out = append(out, ConfigChange{Kind: "SD-WAN member", Name: name, Action: "create", Summary: "Created SD-WAN member."})
		case leftOK && !rightOK:
			out = append(out, ConfigChange{Kind: "SD-WAN member", Name: name, Action: "delete", Summary: "Deleted SD-WAN member."})
		case leftOK && rightOK:
			var fields []string
			if beforeMember.Interface != afterMember.Interface {
				fields = append(fields, "interface")
			}
			if beforeMember.Gateway != afterMember.Gateway {
				fields = append(fields, "gateway")
			}
			if beforeMember.Zone != afterMember.Zone {
				fields = append(fields, "zone")
			}
			if len(fields) > 0 {
				out = append(out, updatedChange("SD-WAN member", name, fields))
			}
		}
	}
	return out
}

func diffSDWANRules(before, after []*SDWANRule) []ConfigChange {
	left := make(map[int]*SDWANRule, len(before))
	right := make(map[int]*SDWANRule, len(after))
	for _, rule := range before {
		left[rule.Seq] = rule
	}
	for _, rule := range after {
		right[rule.Seq] = rule
	}
	var out []ConfigChange
	for _, seq := range sortedIntUnion(intKeys(left), intKeys(right)) {
		beforeRule, leftOK := left[seq]
		afterRule, rightOK := right[seq]
		name := strconv.Itoa(seq)
		switch {
		case !leftOK && rightOK:
			out = append(out, ConfigChange{Kind: "SD-WAN rule", Name: name, Action: "create", Summary: "Created SD-WAN rule."})
		case leftOK && !rightOK:
			out = append(out, ConfigChange{Kind: "SD-WAN rule", Name: name, Action: "delete", Summary: "Deleted SD-WAN rule."})
		case leftOK && rightOK && *beforeRule != *afterRule:
			out = append(out, ConfigChange{Kind: "SD-WAN rule", Name: name, Action: "update", Summary: "Changed SD-WAN rule settings."})
		}
	}
	return out
}

func diffStringMaps(kind string, before, after []string) []ConfigChange {
	left := make(map[string]bool, len(before))
	right := make(map[string]bool, len(after))
	for _, name := range before {
		left[name] = true
	}
	for _, name := range after {
		right[name] = true
	}
	var out []ConfigChange
	for _, name := range sortedStringUnion(before, after) {
		switch {
		case !left[name] && right[name]:
			out = append(out, ConfigChange{Kind: kind, Name: name, Action: "create", Summary: "Created " + kind + "."})
		case left[name] && !right[name]:
			out = append(out, ConfigChange{Kind: kind, Name: name, Action: "delete", Summary: "Deleted " + kind + "."})
		}
	}
	return out
}

func updatedChange(kind, name string, fields []string) ConfigChange {
	return ConfigChange{Kind: kind, Name: name, Action: "update", Summary: "Changed fields: " + strings.Join(fields, ", ") + "."}
}

func interfaceKeys(values map[string]*InterfaceEntry) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func zoneKeys(values map[string]*ZoneEntry) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func sdwanZoneKeys(values map[string]*SDWANZone) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func intKeys[T any](values map[int]T) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func sortedStringUnion(left, right []string) []string {
	seen := make(map[string]bool, len(left)+len(right))
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		seen[value] = true
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sortedIntUnion(left, right []int) []int {
	seen := make(map[int]bool, len(left)+len(right))
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		seen[value] = true
	}
	values := make([]int, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Ints(values)
	return values
}
