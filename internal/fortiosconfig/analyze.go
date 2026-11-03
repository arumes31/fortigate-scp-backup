package fortiosconfig

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

var firmwarePattern = regexp.MustCompile(`-(7\.(?:0|2|4|6)\.\d+)-`)

// Analyze derives one secret-free assessment from a complete saved backup.
// Its conclusions describe configured policy conditions, never live exposure.
func Analyze(ctx context.Context, plain []byte) (reportmodel.Assessment, error) {
	doc, err := parse(ctx, plain)
	if err != nil {
		return reportmodel.Assessment{}, err
	}
	result := reportmodel.Assessment{Complete: true, Firmware: "Unknown", VDOMs: []string{}, Warnings: []string{}, Exposures: []reportmodel.Exposure{}, Sections: []reportmodel.Section{}, Findings: []reportmodel.Finding{}}
	if version := firmwarePattern.FindStringSubmatch(doc.header); len(version) > 1 {
		result.Firmware = version[1]
	} else {
		result.Complete = false
		result.Warnings = append(result.Warnings, "Exact supported FortiOS release could not be established from the backup header. Policy conclusions are indeterminate.")
	}
	if len(doc.warnings) > 0 {
		result.Complete = false
		result.Warnings = append(result.Warnings, doc.warnings...)
	}
	inventories := map[string]*inventory{}
	work := newWorkBudget(ctx)
	get := func(vdom string) *inventory {
		inv := inventories[vdom]
		if inv == nil {
			inv = newInventory()
			inv.work = work
			inventories[vdom] = inv
		}
		return inv
	}
	for _, table := range doc.sections {
		if !work.take() {
			return reportmodel.Assessment{}, work.err
		}
		if table.name == "system global" {
			if hostname := table.get("hostname"); hostname != "" {
				result.Hostname = display(hostname)
			}
		}
		if table.name == "vdom" {
			for _, n := range table.children {
				if n.kind == "edit" {
					get(n.name)
				}
			}
		}
		inv := get(table.vdom())
		if table.name == "system settings" {
			inv.central = table.get("central-nat") == "enable"
			inv.unsupportedMode = table.get("ngfw-mode") == "policy-based" || table.get("opmode") == "transparent"
		}
		for _, n := range table.children {
			if !work.take() {
				return reportmodel.Assessment{}, work.err
			}
			if n.kind != "edit" {
				continue
			}
			target := get(n.vdom())
			switch table.name {
			case "system interface":
				target.interfaces[n.name] = n
			case "system zone":
				target.zones[n.name] = n
			case "firewall address":
				target.addresses[n.name] = n
			case "firewall addrgrp":
				target.addressGroups[n.name] = n
			case "firewall service custom":
				target.services[n.name] = n
			case "firewall service group":
				target.serviceGroups[n.name] = n
			case "firewall vipgrp", "firewall vipgrp6":
				target.vipGroups[n.name] = n
			case "firewall vip", "firewall vip6", "firewall vip46", "firewall vip64":
				target.vips = append(target.vips, n)
				target.vipNames[n.name] = true
			case "firewall policy":
				target.policies = append(target.policies, n)
			case "firewall policy6", "firewall security-policy":
				result.Complete = false
				result.Warnings = append(result.Warnings, "Additional IPv6 or policy-based NGFW policy tables are present; their access-control semantics are outside the current evaluator.")
			}
		}
	}
	keys := make([]string, 0, len(inventories))
	for vdom := range inventories {
		keys = append(keys, vdom)
	}
	sort.Strings(keys)
	totalTraces := 0
	for _, vdom := range keys {
		inv := inventories[vdom]
		// Global-only wrappers are not independent policy domains. The root
		// entry remains when it contains actual configuration or is the only one.
		if vdom == "root" && len(keys) > 1 && len(inv.vips) == 0 && len(inv.policies) == 0 && len(inv.interfaces) == 0 {
			continue
		}
		result.VDOMs = append(result.VDOMs, display(vdom))
		if len(inv.vips) > 3000 || len(inv.policies) > 20000 || int64(len(inv.vips))*int64(len(inv.policies)) > 5000000 {
			return reportmodel.Assessment{}, fmt.Errorf("VDOM analysis exceeds the bounded VIP/policy work limit")
		}
		for index, vip := range inv.vips {
			if err := ctx.Err(); err != nil {
				return reportmodel.Assessment{}, err
			}
			exposure := analyzeExposure(inv, vip, index, result.Firmware != "Unknown" && !inv.unsupportedMode && len(doc.warnings) == 0)
			if work.err != nil {
				return reportmodel.Assessment{}, work.err
			}
			totalTraces += len(exposure.Trace)
			if totalTraces > 50000 {
				return reportmodel.Assessment{}, fmt.Errorf("report exceeds the 50000 policy relationship limit")
			}
			if exposure.Outcome == "Indeterminate" {
				result.Complete = false
			}
			result.Exposures = append(result.Exposures, exposure)
			result.Findings = append(result.Findings, exposureFindings(exposure)...)
		}
		if inv.unsupportedMode {
			result.Complete = false
			result.Warnings = append(result.Warnings, "Transparent or policy-based NGFW mode is present; forwarding inventory is available but policy applicability is indeterminate.")
		}
	}
	result.Sections, result.Findings = technical(doc, result.Findings)
	if err := ctx.Err(); err != nil {
		return reportmodel.Assessment{}, err
	}
	if !result.Complete {
		result.Warnings = append(result.Warnings, "Some policy outcomes require review. Consult each forwarding's notes; incomplete analysis is not a passing check.")
		result.Findings = append(result.Findings, reportmodel.Finding{ID: "analysis-coverage", Category: "analysis", Priority: "Informational", Title: "Assessment coverage requires review", TitleDE: "Analyseumfang prüfen", Detail: "Some configuration relationships could not be established from the saved snapshot.", DetailDE: "Einige Konfigurationsbeziehungen konnten aus der Sicherung nicht bestimmt werden.", Recommendation: "Have an engineer validate the reported limitations before using these results for an access-control decision.", RecommendationDE: "Die aufgeführten Einschränkungen vor einer Zugriffsentscheidung technisch prüfen lassen."})
	}
	result.Warnings = unique(result.Warnings)
	return result, nil
}

func analyzeExposure(inv *inventory, vip *node, index int, knownVersion bool) reportmodel.Exposure {
	ex := reportmodel.Exposure{VDOM: display(vip.vdom()), Name: display(vip.name), Kind: publicationKind(vip), Type: vip.value("type", "static-nat"), ExternalInterface: display(vip.value("extintf", "any")), Outcome: "Indeterminate", GeoStatus: "Not found", Backends: []string{}, Groups: []string{}, PolicyIDs: []string{}, Notes: []string{}, Trace: []reportmodel.PolicyTrace{}, Evidence: vip.evidence()}
	disabled := vip.get("status") == "disable"
	protocol := vip.value("protocol", "tcp")
	externalIP := vip.get("extip")
	if externalIP == "0.0.0.0" {
		if iface := inv.interfaces[vip.get("extintf")]; iface != nil && iface.value("mode", "static") == "static" && len(iface.values["ip"]) > 0 {
			externalIP = iface.values["ip"][0]
		} else {
			externalIP = "interface address (not established from backup)"
			if !inv.appendNote(&ex, len("The external interface address is dynamic or absent from this snapshot."), func() string { return "The external interface address is dynamic or absent from this snapshot." }) {
				return ex
			}
		}
	}
	ex.External = display(externalIP)
	portforward := vip.get("portforward") == "enable"
	port, portOK := portRange(vip.get("mappedport"))
	externalPort, externalPortOK := portRange(vip.get("extport"))
	if portforward || vip.get("extport") != "" {
		ex.External += ":" + display(vip.get("extport")) + "/" + strings.ToUpper(protocol)
	}
	if !portforward {
		port = interval{1, 65535}
		portOK = true
		externalPort = interval{1, 65535}
		externalPortOK = true
		if !inv.appendNote(&ex, len("Static address mapping: publication scope also depends on the associated policy services."), func() string {
			return "Static address mapping: publication scope also depends on the associated policy services."
		}) {
			return ex
		}
	}
	backendIP, backendOK := netip.ParseAddr(vip.get("mappedip"))
	if mapped := vip.get("mappedip"); mapped != "" {
		backend := display(mapped)
		if vip.get("mappedport") != "" {
			backend += ":" + display(vip.get("mappedport"))
		}
		ex.Backends = append(ex.Backends, backend)
	}
	for _, child := range vip.children {
		if !inv.work.take() {
			return ex
		}
		if child.kind != "config" || child.name != "realservers" {
			continue
		}
		for _, server := range child.children {
			if !inv.work.take() {
				return ex
			}
			if server.kind != "edit" {
				continue
			}
			ex.Backends = append(ex.Backends, display(server.get("ip"))+":"+display(server.get("port"))+" ("+display(server.value("status", "active"))+")")
		}
	}
	for name := range inv.vipGroups {
		if !inv.work.take() {
			return ex
		}
		yes, _ := inv.references([]string{name}, vip.name)
		if yes {
			ex.Groups = append(ex.Groups, display(name))
		}
	}
	sort.Strings(ex.Groups)
	supported := knownVersion && vip.parent.name == "firewall vip" && ex.Type == "static-nat" && backendOK == nil && backendIP.Is4() && portOK && externalPortOK && (protocol == "tcp" || protocol == "udp" || protocol == "sctp")
	if _, err := netip.ParseAddr(externalIP); err != nil {
		supported = false
	}
	if ex.Type != "static-nat" {
		if !inv.appendNote(&ex, len("This VIP type is inventoried with its policy references, but its translation/proxy semantics require manual validation."), func() string {
			return "This VIP type is inventoried with its policy references, but its translation/proxy semantics require manual validation."
		}) {
			return ex
		}
	}
	if vip.parent.name != "firewall vip" {
		ex.Type = vip.parent.name + " / " + ex.Type
		if !inv.appendNote(&ex, len("IPv6/NAT46/NAT64 mappings are inventoried; this evaluator does not prove their policy outcomes."), func() string {
			return "IPv6/NAT46/NAT64 mappings are inventoried; this evaluator does not prove their policy outcomes."
		}) {
			return ex
		}
	}
	if !portOK || !externalPortOK || backendOK != nil {
		if !inv.appendNote(&ex, len("The mapping contains an address/port range or unresolved backend that requires additional validation."), func() string {
			return "The mapping contains an address/port range or unresolved backend that requires additional validation."
		}) {
			return ex
		}
	}
	if !knownVersion {
		if !inv.appendNote(&ex, len("Firmware, configuration syntax, or operating mode is outside the validated static evaluator."), func() string {
			return "Firmware, configuration syntax, or operating mode is outside the validated static evaluator."
		}) {
			return ex
		}
	}
	if len(vip.values["src-filter"]) > 0 || vip.get("service") != "" || vip.get("service-filter") == "enable" || vip.get("srcintf-filter") != "" {
		supported = false
		if !inv.appendNote(&ex, 256+displayByteBound(vip.get("srcintf-filter")), func() string {
			return "VIP source, service, or ingress filters are present; their combined DNAT applicability requires validation. Source interface filter: " + display(vip.get("srcintf-filter"))
		}) {
			return ex
		}
	}
	// Both VIP and virtual-server entries participate in the DNAT order. Even
	// a possible overlap blocks a positive conclusion when filters are unresolved.
	for earlier := 0; !disabled && earlier < index; earlier++ {
		if !inv.work.take() {
			return ex
		}
		other := inv.vips[earlier]
		if other.parent.name != vip.parent.name || other.get("status") == "disable" || !inv.mayOverlapAddresses(other, vip) {
			continue
		}
		otherPort, ok := portRange(other.get("extport"))
		if other.get("portforward") != "enable" {
			otherPort = interval{1, 65535}
			ok = true
		}
		if !ok || !externalPortOK || otherPort.lo <= externalPort.hi && externalPort.lo <= otherPort.hi {
			if other.value("protocol", "tcp") == protocol || other.get("portforward") != "enable" || !portforward {
				supported = false
				if !inv.appendNote(&ex, 128+displayByteBound(other.name), func() string {
					return "An earlier DNAT object overlaps this listener: " + display(other.name) + ". Translation selection requires review."
				}) {
					return ex
				}
			}
		}
	}
	mappingKnown := supported
	if inv.central {
		if !inv.appendNote(&ex, len("Central NAT: policy correlation uses mapped backend addresses, not VIP-name references."), func() string {
			return "Central NAT: policy correlation uses mapped backend addresses, not VIP-name references."
		}) {
			return ex
		}
	}
	type policyInfo struct {
		n           *node
		sequence    int
		direct      bool
		coverage    string
		source      selector
		conditional bool
	}
	var related []policyInfo
	enabledReferences := 0
	unknownReference := false
	for i, policy := range inv.policies {
		if !inv.work.take() {
			return ex
		}
		direct, unknown := inv.references(policy.values["dstaddr"], vip.name)
		if inv.central {
			if backendOK == nil {
				direct, unknown = inv.addressMatch(policy.values["dstaddr"], backendIP)
			} else {
				direct = false
				unknown = true
			}
		}
		// A non-VIP destination selector in a deny may overlap the translated
		// backend. Keep it as uncertain until that mode's destination semantics
		// can be proved, rather than silently ignoring a possible earlier deny.
		if !inv.central && !direct && policy.value("action", "deny") == "deny" && backendOK == nil && !contains(policy.values["dstaddr"], "all") {
			matches, unresolved := inv.addressMatch(policy.values["dstaddr"], backendIP)
			unknown = unknown || matches || unresolved
		}
		if unknown && policy.get("status") != "disable" {
			unknownReference = true
		}
		if direct && policy.get("status") != "disable" {
			enabledReferences++
		}
		source := inv.sources(policy.values["srcaddr"])
		genericDeny := policy.value("action", "deny") == "deny" && (contains(policy.values["dstaddr"], "all") || unknown)
		if !direct && !genericDeny && !unknown {
			continue
		}
		coverage, u := serviceCoverage(inv.servicesFor(policy.values["service"]), protocol, port)
		conditional := unsupportedPolicy(policy) || policy.value("schedule", "unknown") != "always" || source.unknown || u || unknown || len(policy.values["srcintf"]) == 0 || len(policy.values["dstintf"]) == 0
		if policy.get("srcaddr-negate") == "enable" {
			conditional = true
		}
		info := policyInfo{policy, i + 1, direct, coverage, source, conditional}
		related = append(related, info)
		trace := reportmodel.PolicyTrace{Sequence: i + 1, ID: display(policy.name), Name: display(policy.get("name")), Action: policy.value("action", "deny"), Source: display(strings.Join(policy.values["srcaddr"], ", ")), Destination: display(strings.Join(policy.values["dstaddr"], ", ")), Service: display(strings.Join(policy.values["service"], ", ")), Schedule: display(policy.value("schedule", "unknown")), Status: policy.value("status", "enable (default)"), VIPMatch: policy.value("match-vip", "omitted / not established"), Evidence: policy.evidence(), SourceInterface: display(strings.Join(policy.values["srcintf"], ", ")), DestinationInterface: display(strings.Join(policy.values["dstintf"], ", ")), Logging: display(policy.value("logtraffic", "not explicit")), Profiles: policyProfiles(policy)}
		if len(source.countries) > 0 {
			trace.Source += " [countries: " + strings.Join(source.countries, ", ") + "]"
		}
		switch {
		case disabled:
			trace.Effect = "VIP is explicitly disabled; this policy is listed for configuration reference only."
		case policy.get("status") == "disable":
			trace.Effect = "Disabled policy; does not establish an active path."
		case genericDeny && !inv.central && policy.get("match-vip") == "disable":
			trace.Effect = "Generic deny explicitly disables VIP matching; does not establish a VIP block."
		case genericDeny && !inv.central && policy.get("match-vip") == "":
			trace.Effect = "Generic deny has no explicit match-vip setting; applicability is indeterminate."
		case coverage == "none" && !u:
			trace.Effect = "Service does not match the evaluated translated backend port."
		case conditional:
			trace.Effect = "Conditional or unresolved selector; verify schedule, source, and advanced matching settings."
		case direct:
			trace.Effect = "Related policy; conclusion is scoped to this policy's interface and source conditions."
		default:
			trace.Effect = "Candidate deny; must precede and cover an accepting policy's conditions."
		}
		ex.Trace = append(ex.Trace, trace)
		if direct {
			ex.PolicyIDs = append(ex.PolicyIDs, display(policy.name))
		}
	}
	// The object-level status applies independently of NAT mode. Preserve the
	// mapping and related rules above, but do not evaluate a disabled VIP as an
	// active publication or claim that geographic rules protect its traffic.
	if disabled {
		ex.Outcome = "Disabled"
		ex.GeoStatus = "Not applicable"
		if !inv.appendNote(&ex, len("The VIP is explicitly disabled. Its mapping and related policies are retained as configuration inventory; no active forwarding or geographic protection is inferred."), func() string {
			return "The VIP is explicitly disabled. Its mapping and related policies are retained as configuration inventory; no active forwarding or geographic protection is inferred."
		}) {
			return ex
		}
		ex.Notes = unique(ex.Notes)
		return ex
	}
	if enabledReferences == 0 && !inv.central {
		ex.Outcome = "No enabled policy reference"
		if !inv.appendNote(&ex, len("No enabled policy references this VIP in the supported non-central-NAT correlation. This does not imply the object has no ARP/local-address effects."), func() string {
			return "No enabled policy references this VIP in the supported non-central-NAT correlation. This does not imply the object has no ARP/local-address effects."
		}) {
			return ex
		}
		if !supported || unknownReference {
			ex.Outcome = "Indeterminate"
		}
		return ex
	}
	if unknownReference {
		supported = false
		if !inv.appendNote(&ex, len("A policy destination or group reference could not be resolved completely."), func() string { return "A policy destination or group reference could not be resolved completely." }) {
			return ex
		}
	}
	accepts, allowed, blocked, geoCovered, geoPartial := 0, 0, 0, 0, 0
	conditionalSource := false
	geoSeen, geoUnknown := false, false
	for _, p := range related {
		if len(p.source.countries) > 0 && p.n.value("action", "deny") == "deny" {
			geoSeen = true
		}
	}
	for _, permit := range related {
		if !inv.work.take() {
			return ex
		}
		if !permit.direct || permit.n.value("action", "deny") != "accept" || permit.n.get("status") == "disable" {
			continue
		}
		if permit.coverage == "none" && !permit.conditional {
			continue
		}
		accepts++
		if permit.conditional || permit.coverage != "full" {
			supported = false
			if unsupportedPolicy(permit.n) || permit.source.unknown {
				geoUnknown = geoSeen
			}
		}
		covered, partly, fullDeny, priorAccept := false, false, false, false
		for _, prior := range related {
			if !inv.work.take() {
				return ex
			}
			if prior.sequence >= permit.sequence {
				break
			}
			if prior.n.get("status") == "disable" {
				continue
			}
			if prior.n.value("action", "deny") == "accept" && prior.direct && prior.coverage != "none" {
				priorAccept = true
				continue
			}
			if prior.n.value("action", "deny") != "deny" || prior.coverage == "none" && !prior.conditional {
				continue
			}
			srcCoverage := inv.interfaceCoverage(prior.n.values["srcintf"], permit.n.values["srcintf"])
			dstCoverage := inv.interfaceCoverage(prior.n.values["dstintf"], permit.n.values["dstintf"])
			if srcCoverage == "none" || dstCoverage == "none" {
				continue
			}
			if srcCoverage != "full" || dstCoverage != "full" {
				if len(prior.source.countries) > 0 {
					partly = true
				}
				if srcCoverage == "unknown" || dstCoverage == "unknown" {
					geoUnknown = true
					supported = false
				}
				continue
			}
			if !inv.central && !prior.direct {
				if prior.n.get("match-vip") == "disable" {
					continue
				}
				if prior.n.get("match-vip") != "enable" {
					if len(prior.source.countries) > 0 {
						geoUnknown = true
					}
					supported = false
					continue
				}
			}
			if prior.conditional || prior.coverage != "full" {
				geoUnknown = geoUnknown || prior.source.unknown || unsupportedPolicy(prior.n)
				if len(prior.source.countries) > 0 {
					partly = true
					geoUnknown = geoUnknown || prior.source.unknown
				}
				supported = false
				continue
			}
			sameSource := strings.Join(unique(prior.n.values["srcaddr"]), "\x00") == strings.Join(unique(permit.n.values["srcaddr"]), "\x00")
			if (prior.source.all || sameSource) && !priorAccept {
				fullDeny = true
			} else if len(prior.source.countries) == 0 {
				conditionalSource = true
			}
			if len(prior.source.countries) > 0 {
				if priorAccept {
					partly = true
				} else {
					covered = true
				}
				if !inv.appendNote(&ex, geoNoteBound(prior.n.name, permit.n.name, prior.source.countries), func() string {
					return fmt.Sprintf("Policy %s precedes permit %s and denies configured country selectors %s for the evaluated interface/service conditions%s.", display(prior.n.name), display(permit.n.name), strings.Join(prior.source.countries, ", "), map[bool]string{true: "; earlier permit exceptions also exist", false: ""}[priorAccept])
				}) {
					return ex
				}
			}
		}
		if fullDeny {
			blocked++
		} else {
			allowed++
		}
		if covered {
			geoCovered++
		}
		if partly {
			geoPartial++
		}
	}
	switch {
	case geoUnknown:
		ex.GeoStatus = "Indeterminate"
	case geoCovered > 0 && geoCovered == accepts && geoPartial == 0:
		ex.GeoStatus = "Applicable"
	case geoCovered > 0 || geoPartial > 0:
		ex.GeoStatus = "Partial"
	case geoSeen:
		ex.GeoStatus = "Not applicable"
	}
	switch {
	case !supported:
		ex.Outcome = "Indeterminate"
	case accepts == 0:
		ex.Outcome = "Conditional"
		if !inv.appendNote(&ex, len("No supported accepting policy path was established for this mapping."), func() string { return "No supported accepting policy path was established for this mapping." }) {
			return ex
		}
	case blocked == accepts:
		ex.Outcome = "Configured deny"
	case allowed > 0 && blocked > 0 || conditionalSource:
		ex.Outcome = "Conditional"
	default:
		ex.Outcome = "Configured permit"
	}
	if !portforward && ex.Outcome == "Indeterminate" {
		if !inv.appendNote(&ex, len("One-to-one mappings with narrower policy services require per-service review; no full-range permit is inferred."), func() string {
			return "One-to-one mappings with narrower policy services require per-service review; no full-range permit is inferred."
		}) {
			return ex
		}
	}
	if !mappingKnown || unknownReference {
		if geoSeen || unknownReference {
			ex.GeoStatus = "Indeterminate"
		}
	}
	ex.Notes = unique(ex.Notes)
	return ex
}

func unsupportedPolicy(n *node) bool {
	for _, key := range []string{"srcaddr-negate", "dstaddr-negate", "service-negate", "internet-service", "internet-service-src", "nat46", "nat64"} {
		if n.get(key) == "enable" {
			return true
		}
	}
	for _, key := range []string{"users", "groups", "fsso-groups", "internet-service-name", "internet-service-src-name", "srcaddr6", "dstaddr6", "ztna-ems-tag", "ztna-ems-tag-secondary", "src-vendor-mac"} {
		if len(n.values[key]) > 0 {
			return true
		}
	}
	return false
}

func (inv *inventory) appendNote(ex *reportmodel.Exposure, maxBytes int, build func() string) bool {
	if !inv.work.reserveNote(maxBytes) {
		return false
	}
	text := build()
	if len(text) > maxBytes {
		inv.work.err = fmt.Errorf("report note exceeded its reserved output bound")
		return false
	}
	ex.Notes = append(ex.Notes, text)
	return true
}

// display emits at most 300 four-byte runes and an ellipsis. The smaller
// input-based bound also covers replacement of invalid UTF-8 with RuneError.
func displayByteBound(value string) int {
	if len(value) >= 300 {
		return 1203
	}
	return 4*len(value) + 3
}

func geoNoteBound(denyID, permitID string, countries []string) int {
	size := 256 + displayByteBound(denyID) + displayByteBound(permitID)
	for _, country := range countries {
		size += len(country) + 2
		if size > 1<<20 {
			return size
		}
	}
	return size
}

func policyProfiles(n *node) string {
	var result []string
	for _, key := range []string{"utm-status", "inspection-mode", "profile-group", "ssl-ssh-profile", "av-profile", "ips-sensor", "webfilter-profile", "dnsfilter-profile", "application-list", "waf-profile"} {
		if value := n.get(key); value != "" {
			result = append(result, key+"="+display(value))
		}
	}
	return strings.Join(result, "; ")
}

func exposureFindings(ex reportmodel.Exposure) []reportmodel.Finding {
	if ex.Outcome == "Disabled" {
		return nil
	}
	var result []reportmodel.Finding
	key := ex.VDOM + ":" + ex.Name
	if ex.GeoStatus == "Not applicable" || ex.GeoStatus == "Partial" || ex.GeoStatus == "Indeterminate" {
		result = append(result, reportmodel.Finding{ID: "geo-coverage:" + key, VDOM: ex.VDOM, Category: "publications", Exposure: ex.Name, Priority: "Medium", Title: "Review geographic restriction coverage", TitleDE: "Geografische Einschränkungen prüfen", Detail: "A configured geographic restriction does not establish complete coverage of every related publication path.", DetailDE: "Eine geografische Einschränkung belegt nicht die vollständige Abdeckung aller zugehörigen Veröffentlichungspfade.", Recommendation: "Review rule order, VIP matching, interfaces, services, schedules, and earlier exceptions.", RecommendationDE: "Reihenfolge, VIP-Zuordnung, Schnittstellen, Dienste, Zeitpläne und frühere Ausnahmen prüfen.", Evidence: ex.Evidence})
	}
	for _, trace := range ex.Trace {
		if trace.Action == "accept" && trace.Status != "disable" && trace.Source == "all" {
			result = append(result, reportmodel.Finding{ID: "broad-source:" + key, VDOM: ex.VDOM, Category: "publications", Exposure: ex.Name, Priority: "Medium", Title: "Review broad source permissions", TitleDE: "Breite Quellfreigaben prüfen", Detail: "A publication has a related allow policy with an unrestricted source selector; other restrictions may still apply.", DetailDE: "Eine Veröffentlichung hat eine zugehörige Freigaberegel ohne Quelleinschränkung; weitere Einschränkungen können gelten.", Recommendation: "Confirm the service owner and intended audience, and validate whether a narrower source scope is appropriate.", RecommendationDE: "Dienstverantwortliche und Zielgruppe bestätigen und mögliche Quelleinschränkungen bewerten.", Evidence: trace.Evidence})
			break
		}
	}
	for _, note := range ex.Notes {
		if strings.Contains(note, "earlier DNAT object overlaps") {
			result = append(result, reportmodel.Finding{ID: "overlap:" + key, VDOM: ex.VDOM, Category: "publications", Exposure: ex.Name, Priority: "Medium", Title: "Review overlapping publication mappings", TitleDE: "Überlappende Veröffentlichungen prüfen", Detail: "An earlier translation object may select the same listener before this mapping.", DetailDE: "Ein früheres Übersetzungsobjekt kann denselben Listener vor dieser Zuordnung auswählen.", Recommendation: "Validate DNAT object order and the selected backend for the intended service.", RecommendationDE: "DNAT-Objektreihenfolge und ausgewähltes Backend für den vorgesehenen Dienst prüfen.", Evidence: ex.Evidence})
			break
		}
	}
	return result
}

func publicationKind(vip *node) string {
	switch vip.parent.name {
	case "firewall vip6":
		return "ipv6"
	case "firewall vip46":
		return "nat46"
	case "firewall vip64":
		return "nat64"
	}
	switch vip.value("type", "static-nat") {
	case "static-nat":
		return "static_nat"
	case "load-balance", "server-load-balance":
		return "virtual_server"
	case "fqdn":
		return "fqdn"
	case "access-proxy":
		return "access_proxy"
	case "dns-translation":
		return "dns_translation"
	default:
		return "other"
	}
}
