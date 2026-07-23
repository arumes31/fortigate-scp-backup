package fgt_confconv

import (
	"regexp"
	"strconv"
	"strings"
)

// editRe extracts the quoted name from `edit "name"`. Unquoted edits
// (`edit 5`, sequence numbers in policy/route/sdwan-member tables) fall back
// to the raw remainder of the line.
var editRe = regexp.MustCompile(`^edit\s+"([^"]+)"`)

var configVersionRe = regexp.MustCompile(`^#config-version=\S*?-(\d+)\.(\d+)\.(\d+)-`)

// watchedSections are config sections a touched interface might appear in
// that recipes deliberately never rewrite -- every `set` line inside one is
// captured verbatim for the reference scanner (see ScanReferences).
var watchedSections = map[string]bool{
	"firewall vip":               true,
	"vpn ipsec phase1-interface": true,
	"system dhcp server":         true,
	"system ha":                  true,
	"system snmp community":      true,
	"log syslogd setting":        true,
	"system accprofile":          true,
}

type stackElem struct {
	isConfig bool
	name     string
}

// getActiveContext returns the nearest enclosing config-section name and,
// if there is exactly one edit frame open directly inside it, that edit's
// name. Mirrors fgt_confgen's parser: deeper nesting inside an edit (e.g. a
// VLAN interface's nested `config ipv6` block) naturally resolves to that
// inner section instead, so it is transparently ignored here.
func getActiveContext(stack []stackElem) (section, edit string) {
	configIdx := -1
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].isConfig {
			configIdx = i
			break
		}
	}
	if configIdx == -1 {
		return "", ""
	}
	sec := stack[configIdx].name
	for i := configIdx + 1; i < len(stack); i++ {
		if !stack[i].isConfig {
			return sec, stack[i].name
		}
	}
	return sec, ""
}

// insideSDWAN reports whether the second-nearest config frame (the one
// enclosing "members"/"zone"/"health-check") is "system sdwan" -- needed
// because both `config system zone` (top level) and `config system sdwan`'s
// nested `config zone` produce different frame names ("system zone" vs
// "zone"), but "members"/"zone"/"health-check" alone don't say which parent
// they're under.
func insideSDWAN(stack []stackElem) bool {
	configs := make([]string, 0, len(stack))
	for _, f := range stack {
		if f.isConfig {
			configs = append(configs, f.name)
		}
	}
	for i := len(configs) - 1; i > 0; i-- {
		if configs[i] == "members" || configs[i] == "zone" || configs[i] == "health-check" {
			return configs[i-1] == "system sdwan"
		}
	}
	return false
}

// parseSetLine splits `set <key> <value...>` into key and raw value string.
func parseSetLine(line string) (key, value string) {
	rest := strings.TrimPrefix(line, "set ")
	sp := strings.IndexByte(rest, ' ')
	if sp == -1 {
		return rest, ""
	}
	return rest[:sp], strings.TrimSpace(rest[sp+1:])
}

// splitConfigValues splits a FortiGate `set` value list into its members,
// honouring double quotes: `"VL100" "eworx GUEST" always` -> [VL100, eworx GUEST, always].
func splitConfigValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			if inQuote {
				out = append(out, cur.String())
				cur.Reset()
			}
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		case c == '\\' && inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ParseFortiOSVersion scans a backup's leading header lines for
// `#config-version=FGT...-X.Y.Z-...`. ok is false if no header was found.
func ParseFortiOSVersion(content string) (v FortiOSVersion, ok bool) {
	lines := strings.SplitN(content, "\n", 20)
	for _, line := range lines {
		if m := configVersionRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			maj, _ := strconv.Atoi(m[1])
			min, _ := strconv.Atoi(m[2])
			pat, _ := strconv.Atoi(m[3])
			return FortiOSVersion{Major: maj, Minor: min, Patch: pat, Raw: strings.TrimSpace(line)}, true
		}
	}
	return FortiOSVersion{}, false
}

// ParseConfig walks a raw FortiGate backup into an FGConfig. It never errors
// on unrecognized sections -- it simply does not build a model for them --
// so it stays robust against config content this extension does not yet
// know about.
func ParseConfig(content string) *FGConfig {
	cfg := &FGConfig{
		Interfaces: make(map[string]*InterfaceEntry),
		Zones:      make(map[string]*ZoneEntry),
		SDWANZones: make(map[string]*SDWANZone),
	}
	if v, ok := ParseFortiOSVersion(content); ok {
		cfg.Version = v
	}

	var stack []stackElem

	// per-edit scratch state, reset whenever a new edit frame is pushed for
	// one of the core sections.
	var curIface *InterfaceEntry
	var curZone *ZoneEntry
	var curPolicy *PolicyEntry
	var curRoute *RouteEntry
	var curMember *SDWANMember

	lines := strings.Split(content, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "config ") {
			stack = append(stack, stackElem{isConfig: true, name: strings.TrimSpace(strings.TrimPrefix(line, "config "))})
			continue
		}

		if line == "end" {
			for len(stack) > 0 {
				elem := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if elem.isConfig {
					break
				}
			}
			continue
		}

		if line == "next" {
			sec, edit := getActiveContext(stack)
			switch {
			case sec == "system interface" && curIface != nil && curIface.Name == edit:
				cfg.Interfaces[curIface.Name] = curIface
				curIface = nil
			case sec == "system zone" && curZone != nil && curZone.Name == edit:
				cfg.Zones[curZone.Name] = curZone
				curZone = nil
			case sec == "firewall policy" && curPolicy != nil:
				cfg.Policies = append(cfg.Policies, curPolicy)
				curPolicy = nil
			case sec == "router static" && curRoute != nil:
				cfg.StaticRoutes = append(cfg.StaticRoutes, curRoute)
				curRoute = nil
			case sec == "members" && insideSDWAN(stack) && curMember != nil:
				cfg.SDWANMembers = append(cfg.SDWANMembers, curMember)
				curMember = nil
			case sec == "zone" && insideSDWAN(stack) && edit != "":
				cfg.SDWANZones[edit] = &SDWANZone{Name: edit}
			case sec == "health-check" && insideSDWAN(stack) && edit != "":
				cfg.SDWANHealthChecks = append(cfg.SDWANHealthChecks, edit)
			}
			for len(stack) > 0 {
				elem := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if !elem.isConfig {
					break
				}
			}
			continue
		}

		if strings.HasPrefix(line, "edit ") {
			var name string
			if m := editRe.FindStringSubmatch(line); len(m) > 1 {
				name = m[1]
			} else {
				name = strings.TrimSpace(strings.TrimPrefix(line, "edit "))
			}
			stack = append(stack, stackElem{isConfig: false, name: name})

			sec, edit := getActiveContext(stack)
			if edit != name {
				continue // not directly inside the section we just pushed for
			}
			switch {
			case sec == "system interface":
				curIface = &InterfaceEntry{Name: name}
			case sec == "system zone":
				curZone = &ZoneEntry{Name: name}
			case sec == "firewall policy":
				if id, err := strconv.Atoi(name); err == nil {
					curPolicy = &PolicyEntry{ID: id}
				}
			case sec == "router static":
				if seq, err := strconv.Atoi(name); err == nil {
					curRoute = &RouteEntry{Seq: seq}
				}
			case sec == "members" && insideSDWAN(stack):
				if seq, err := strconv.Atoi(name); err == nil {
					curMember = &SDWANMember{Seq: seq}
				}
			}
			continue
		}

		if !strings.HasPrefix(line, "set ") {
			continue
		}

		sec, edit := getActiveContext(stack)
		key, val := parseSetLine(line)

		if watchedSections[sec] && edit != "" {
			cfg.WatchedLines = append(cfg.WatchedLines, WatchedLine{Section: sec, Edit: edit, Line: line})
			continue
		}

		switch {
		case sec == "system interface" && curIface != nil && curIface.Name == edit:
			switch key {
			case "type":
				curIface.Type = val
			case "interface":
				curIface.Parent = strings.Trim(val, `"`)
			case "vlanid":
				curIface.VLANID, _ = strconv.Atoi(val)
			case "ip":
				curIface.IP = val
			case "allowaccess":
				curIface.Allowaccess = val
			case "role":
				curIface.Role = val
			case "member":
				curIface.Members = splitConfigValues(val)
			case "fortilink":
				curIface.Fortilink = val == "enable"
			default:
				curIface.Lines = append(curIface.Lines, line)
			}

		case sec == "system zone" && curZone != nil && curZone.Name == edit:
			switch key {
			case "interface":
				curZone.Interfaces = splitConfigValues(val)
			case "intrazone-deny":
				curZone.IntrazoneDeny = val == "enable"
			}

		case sec == "firewall policy" && curPolicy != nil:
			switch key {
			case "srcintf":
				curPolicy.SrcIntf = splitConfigValues(val)
			case "dstintf":
				curPolicy.DstIntf = splitConfigValues(val)
			}

		case sec == "router static" && curRoute != nil:
			switch key {
			case "dst":
				curRoute.Dst = val
			case "device":
				curRoute.Device = strings.Trim(val, `"`)
			case "gateway":
				curRoute.Gateway = val
			}

		case sec == "members" && insideSDWAN(stack) && curMember != nil:
			switch key {
			case "interface":
				curMember.Interface = strings.Trim(val, `"`)
			case "gateway":
				curMember.Gateway = val
			case "zone":
				curMember.Zone = strings.Trim(val, `"`)
			}
		}
	}

	return cfg
}

// ScanReferences returns every captured WatchedLine that mentions ifaceName
// as a whole token (so "wan1" never matches inside "wan10"), forming the
// basis of a recipe's "everything else, flagged" warnings.
func ScanReferences(cfg *FGConfig, ifaceName string) []RefHit {
	var hits []RefHit
	for _, wl := range cfg.WatchedLines {
		_, val := parseSetLine(wl.Line)
		for _, tok := range splitConfigValues(val) {
			if tok == ifaceName {
				hits = append(hits, RefHit(wl))
				break
			}
		}
	}
	return hits
}
