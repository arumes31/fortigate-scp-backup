package fgt_confconv

import (
	"encoding/json"
	"fmt"
)

// FortiOSVersion is the FortiOS build parsed from a backup's #config-version
// header, e.g. "FGT90G-7.6.7-FW-build3704-260601" -> {7, 6, 7}.
type FortiOSVersion struct {
	Major, Minor, Patch int
	Build               int    // `-buildNNNN-` from the header; the reliable signal
	Raw                 string // the full header line, for error messages
}

// fortiOS74GABuild is the build number of FortiOS 7.4.0 GA. Build numbers rise
// monotonically across trains, so any build at or above it is 7.4+ (e.g. build
// 2902 is 7.4.12). This is the trustworthy check when the version string is
// masked/unreliable -- some devices report "7.00" while actually running 7.4.x.
const fortiOS74GABuild = 2360

// SupportsSDWANSyntax reports whether this version uses the modern
// `config system sdwan` naming (7.4+) that the SD-WAN recipes target. Below
// 7.4, FortiOS used `config system virtual-wan-link` instead. The X.Y.Z string
// is unreliable on some builds, so the build number is the fallback signal.
func (v FortiOSVersion) SupportsSDWANSyntax() bool {
	if v.Major > 7 || (v.Major == 7 && v.Minor >= 4) {
		return true
	}
	return v.Build >= fortiOS74GABuild
}

func (v FortiOSVersion) String() string {
	if v.Major == 0 && v.Build > 0 {
		// Version string was masked/unparseable; report the build instead of a
		// misleading "0.0.0".
		return fmt.Sprintf("build %d", v.Build)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// InterfaceEntry is a parsed `config system interface` edit block.
type InterfaceEntry struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`   // "" (physical), "aggregate", "hard-switch", "vlan", "redundant", ...
	Parent      string   `json:"parent"` // `set interface <parent>` -- the VLAN parent / member's owning aggregate
	VLANID      int      `json:"vlanId"` // `set vlanid N`, 0 if not a VLAN
	IP          string   `json:"ip"`     // raw `set ip <addr> <mask>` value, "" if none
	Allowaccess string   `json:"allowaccess"`
	Role        string   `json:"role"`      // `set role lan|wan|dmz|undefined`
	Members     []string `json:"members"`   // `set member ...` for aggregate/hardware-switch/redundant types
	Fortilink   bool     `json:"fortilink"` // `set fortilink enable`
	Lines       []string `json:"-"`         // every other raw `set ...` line, verbatim, for recipes that need to carry settings over
}

// ZoneEntry is a parsed `config system zone` edit block.
type ZoneEntry struct {
	Name          string   `json:"name"`
	Interfaces    []string `json:"interfaces"`
	IntrazoneDeny bool     `json:"intrazoneDeny"`
}

// PolicyEntry is a minimal parsed `config firewall policy` edit block -- just
// enough for interface-reference rewriting. Unlike fgt_polsplit's parser this
// deliberately does not resolve addresses/services/NAT; recipes here only
// ever touch srcintf/dstintf.
type PolicyEntry struct {
	ID      int
	SrcIntf []string
	DstIntf []string
}

// RouteEntry is a parsed `config router static` edit block.
type RouteEntry struct {
	Seq      int    `json:"seq"`
	Dst      string `json:"dst"` // "" means the default route (0.0.0.0/0.0.0.0, or omitted entirely)
	Device   string `json:"device"`
	Gateway  string `json:"gateway"`
	Disabled bool   `json:"disabled"` // true once a recipe supersedes this route; emitted commented-out, never deleted
}

// SDWANMember is a parsed `config system sdwan` -> `config members` edit block.
type SDWANMember struct {
	Seq       int    `json:"seq"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Zone      string `json:"zone"`
}

// SDWANZone is a parsed `config system sdwan` -> `config zone` edit block.
type SDWANZone struct {
	Name string `json:"name"`
}

// WatchedLine is one raw `set` line captured from a config section that
// recipes never rewrite automatically (VIPs, IPsec phase1, DHCP servers, HA,
// SNMP, syslog, admin access). ScanReferences token-matches these against an
// interface name to build operator warnings without needing a full parser
// for every one of those sections.
type WatchedLine struct {
	Section string // e.g. "firewall vip", "vpn ipsec phase1-interface"
	Edit    string // the edit-block name/id the line occurred in
	Line    string // the raw `set ...` line, trimmed
}

// RefHit is one WatchedLine that mentioned a given interface name as a whole
// token -- the basis for a recipe's non-core-path warning.
type RefHit struct {
	Section string
	Edit    string
	Line    string
}

// FGConfig is the in-memory parsed config model every recipe reads and
// mutates. A pipeline run clones it once per invocation so chained recipes
// see each other's changes without touching the original parse.
type FGConfig struct {
	Version      FortiOSVersion
	Interfaces   map[string]*InterfaceEntry
	Zones        map[string]*ZoneEntry
	Policies     []*PolicyEntry
	StaticRoutes []*RouteEntry
	SDWANMembers []*SDWANMember
	SDWANZones   map[string]*SDWANZone
	// SDWANHealthChecks holds just the names of `config system sdwan ->
	// config health-check` entries -- enough for recipes to tell whether any
	// exist, without needing to model ping-server details.
	SDWANHealthChecks []string
	WatchedLines      []WatchedLine
}

// Clone returns a deep copy so a pipeline run can mutate freely without
// affecting the original parse (or a previous recipe's already-applied step).
func (c *FGConfig) Clone() *FGConfig {
	out := &FGConfig{
		Version:    c.Version,
		Interfaces: make(map[string]*InterfaceEntry, len(c.Interfaces)),
		Zones:      make(map[string]*ZoneEntry, len(c.Zones)),
		SDWANZones: make(map[string]*SDWANZone, len(c.SDWANZones)),
	}
	for k, v := range c.Interfaces {
		cp := *v
		cp.Members = append([]string(nil), v.Members...)
		cp.Lines = append([]string(nil), v.Lines...)
		out.Interfaces[k] = &cp
	}
	for k, v := range c.Zones {
		cp := *v
		cp.Interfaces = append([]string(nil), v.Interfaces...)
		out.Zones[k] = &cp
	}
	for _, p := range c.Policies {
		cp := *p
		cp.SrcIntf = append([]string(nil), p.SrcIntf...)
		cp.DstIntf = append([]string(nil), p.DstIntf...)
		out.Policies = append(out.Policies, &cp)
	}
	for _, r := range c.StaticRoutes {
		cp := *r
		out.StaticRoutes = append(out.StaticRoutes, &cp)
	}
	for _, m := range c.SDWANMembers {
		cp := *m
		out.SDWANMembers = append(out.SDWANMembers, &cp)
	}
	for k, v := range c.SDWANZones {
		cp := *v
		out.SDWANZones[k] = &cp
	}
	out.WatchedLines = append([]WatchedLine(nil), c.WatchedLines...)
	out.SDWANHealthChecks = append([]string(nil), c.SDWANHealthChecks...)
	return out
}

// CLIBlock is one recipe's contribution to the final generated script.
type CLIBlock struct {
	Recipe string   `json:"recipe"`
	Label  string   `json:"label"`
	Lines  []string `json:"lines"`
}

// Warning is a non-core-traffic-path reference (or any other issue) a recipe
// found but deliberately did not rewrite, surfaced to the operator instead.
type Warning struct {
	Recipe  string `json:"recipe"`
	Detail  string `json:"detail"`
	Section string `json:"section,omitempty"`
	Line    string `json:"line,omitempty"`
}

// Recipe is one self-contained structural migration. Run mutates cfg in
// place to reflect the end state and returns the CLI needed to get there.
type Recipe interface {
	Key() string
	Label() string
	// Applicable reports whether this recipe's preconditions are met given
	// the model's current state (which may already reflect earlier recipes
	// in the same pipeline run). The string is a human-readable reason used
	// in the 400 response when false.
	Applicable(cfg *FGConfig) (bool, string)
	Run(cfg *FGConfig, opts json.RawMessage) ([]CLIBlock, []Warning, error)
}
