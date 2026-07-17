package fgt_confgen

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	icmpTypeRegex = regexp.MustCompile(`^[0-9]+$`)
)

// validatePortRange checks that s is a comma-separated list of ports or
// port ranges (e.g. "80", "80,443", "1024-2048") where every port
// number is between 1 and 65535 and range starts do not exceed ends.
func validatePortRange(s string) error {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("empty component in port range: %q", s)
		}
		if idx := strings.Index(part, "-"); idx >= 0 {
			startStr := strings.TrimSpace(part[:idx])
			endStr := strings.TrimSpace(part[idx+1:])
			// ASCII digits only: Atoi would also accept a leading sign
			// ("+80"), which passes the range check but is emitted verbatim
			// into the CLI where FortiOS rejects it.
			if !isNumericID(startStr) {
				return fmt.Errorf("invalid port number %q in range %q", startStr, s)
			}
			if !isNumericID(endStr) {
				return fmt.Errorf("invalid port number %q in range %q", endStr, s)
			}
			start, err := strconv.Atoi(startStr)
			if err != nil {
				return fmt.Errorf("invalid port number %q in range %q", startStr, s)
			}
			end, err := strconv.Atoi(endStr)
			if err != nil {
				return fmt.Errorf("invalid port number %q in range %q", endStr, s)
			}
			if start < 1 || start > 65535 {
				return fmt.Errorf("port %d out of range (1-65535) in %q", start, s)
			}
			if end < 1 || end > 65535 {
				return fmt.Errorf("port %d out of range (1-65535) in %q", end, s)
			}
			if start > end {
				return fmt.Errorf("start port %d exceeds end port %d in %q", start, end, s)
			}
		} else {
			if !isNumericID(part) {
				return fmt.Errorf("invalid port number %q in %q", part, s)
			}
			port, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid port number %q in %q", part, s)
			}
			if port < 1 || port > 65535 {
				return fmt.Errorf("port %d out of range (1-65535) in %q", port, s)
			}
		}
	}
	return nil
}

func hasControlOrQuote(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' || c == '`' || c == '\\' || c == '\r' || c == '\n' || c < 32 || c == 127 {
			return true
		}
	}
	return false
}

func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// normalizePolicy fills empty enum fields with the same defaults the UI form
// displays for them (scripts.js selectPolicy), so templates saved by older
// builds or imported without these fields generate exactly what the form
// shows instead of failing validation.
func normalizePolicy(p Policy) Policy {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&p.Action, "accept")
	def(&p.InspectionMode, "flow")
	def(&p.LogTraffic, "all")
	def(&p.LogTrafficStart, "enable")
	def(&p.AutoAsicOffload, "enable")
	def(&p.Nat, "disable")
	return p
}

func validatePolicy(p Policy, services []Service) error {
	fields := []string{
		p.PolicyID, p.PolicyName, p.PolicyComment, p.SSLSSHProfile, p.WebfilterProfile,
		p.AVProfile, p.ApplicationList, p.IPSSensor, p.IPPool,
	}
	for _, f := range fields {
		if hasControlOrQuote(f) {
			return fmt.Errorf("invalid characters in field value")
		}
	}

	lists := [][]string{
		p.SrcInterfaces, p.DstInterfaces, p.SrcAddresses, p.SrcAddressGroups, p.SrcVIPs,
		p.SrcInternetServices, p.DstAddresses, p.DstAddressGroups, p.DstVIPs, p.DstInternetServices,
		p.Users, p.Groups,
	}
	for _, list := range lists {
		for _, item := range list {
			if hasControlOrQuote(item) {
				return fmt.Errorf("invalid characters in list item: %q", item)
			}
		}
	}

	action := strings.ToLower(p.Action)
	if action != "accept" && action != "deny" {
		return fmt.Errorf("invalid action: %q", p.Action)
	}

	insMode := strings.ToLower(p.InspectionMode)
	if insMode != "flow" && insMode != "proxy" {
		return fmt.Errorf("invalid inspection mode: %q", p.InspectionMode)
	}

	logTraffic := strings.ToLower(p.LogTraffic)
	if logTraffic != "all" && logTraffic != "utm" && logTraffic != "disable" {
		return fmt.Errorf("invalid logtraffic: %q", p.LogTraffic)
	}

	logTrafficStart := strings.ToLower(p.LogTrafficStart)
	if logTrafficStart != "enable" && logTrafficStart != "disable" {
		return fmt.Errorf("invalid logtraffic-start: %q", p.LogTrafficStart)
	}

	autoAsic := strings.ToLower(p.AutoAsicOffload)
	if autoAsic != "enable" && autoAsic != "disable" {
		return fmt.Errorf("invalid auto-asic-offload: %q", p.AutoAsicOffload)
	}

	nat := strings.ToLower(p.Nat)
	if nat != "enable" && nat != "disable" {
		return fmt.Errorf("invalid nat: %q", p.Nat)
	}

	for i, svc := range services {
		if hasControlOrQuote(svc.Name) || hasControlOrQuote(svc.Type) || hasControlOrQuote(svc.Protocol) || hasControlOrQuote(svc.Port) {
			return fmt.Errorf("invalid characters in service %q", svc.Name)
		}

		if svc.Name == "" {
			// Blank row (the UI's untouched "Add Service" default) — the
			// generators skip these, so validation must too.
			continue
		}

		// Canonicalize type early so downstream branches (GenerateOutput2,
		// GenerateOutput3, GenerateSinglePolicyCLI) match reliably.
		services[i].Type = strings.ToLower(svc.Type)
		svc = services[i]

		// The frontend sends "template" (predefined service), "group"
		// (service group) or "custom"; "predefined" is kept for
		// compatibility with stored templates.
		if svc.Type != "custom" && svc.Type != "predefined" && svc.Type != "template" && svc.Type != "group" {
			return fmt.Errorf("invalid service type: %q", svc.Type)
		}

		if svc.Type == "custom" {
			protocol := strings.ToUpper(svc.Protocol)
			if protocol != "TCP" && protocol != "UDP" && protocol != "SCTP" && protocol != "ICMP" {
				return fmt.Errorf("unsupported protocol: %s", svc.Protocol)
			}

			if protocol == "ICMP" {
				if !icmpTypeRegex.MatchString(svc.Port) {
					return fmt.Errorf("invalid ICMP type: %q", svc.Port)
				}
				var val int
				if _, err := fmt.Sscanf(svc.Port, "%d", &val); err != nil || val < 0 || val > 255 {
					return fmt.Errorf("ICMP type out of range (0-255): %q", svc.Port)
				}
			} else {
				if err := validatePortRange(svc.Port); err != nil {
					return fmt.Errorf("invalid port range for service %q: %w", svc.Name, err)
				}
			}
		}
	}

	return nil
}

// GenerateOutput1 generates all-in-one policies.
func GenerateOutput1(p Policy) (string, error) {
	p = normalizePolicy(p)
	if err := validatePolicy(p, p.Services); err != nil {
		return "", err
	}
	return GenerateSinglePolicyCLI(p, p.PolicyName, p.Services)
}

// GenerateOutput2 generates one policy per service.
func GenerateOutput2(p Policy) (string, error) {
	p = normalizePolicy(p)
	if err := validatePolicy(p, p.Services); err != nil {
		return "", err
	}
	var filteredServices []Service
	for _, svc := range p.Services {
		if svc.Name != "" {
			filteredServices = append(filteredServices, svc)
		}
	}
	if len(filteredServices) == 0 {
		return "", fmt.Errorf("no services defined for this policy")
	}
	var sb strings.Builder
	for _, svc := range filteredServices {
		name := svc.Name
		if svc.Type == "custom" {
			name = "custom_" + svc.Name
		}
		policyName := limitString(fmt.Sprintf("%s-%s", p.PolicyName, name), 32)
		cli, err := GenerateSinglePolicyCLI(p, policyName, []Service{svc})
		if err != nil {
			return "", err
		}
		sb.WriteString(cli)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// GenerateOutput3 generates one policy per source interface, destination interface, and service combination.
func GenerateOutput3(p Policy) (string, error) {
	p = normalizePolicy(p)
	if err := validatePolicy(p, p.Services); err != nil {
		return "", err
	}
	var srcIntfs []string
	for _, src := range p.SrcInterfaces {
		if src != "" {
			srcIntfs = append(srcIntfs, src)
		}
	}
	var dstIntfs []string
	for _, dst := range p.DstInterfaces {
		if dst != "" {
			dstIntfs = append(dstIntfs, dst)
		}
	}
	var filteredServices []Service
	for _, svc := range p.Services {
		if svc.Name != "" {
			filteredServices = append(filteredServices, svc)
		}
	}

	if len(srcIntfs) == 0 {
		return "", fmt.Errorf("no source interfaces defined")
	}
	if len(dstIntfs) == 0 {
		return "", fmt.Errorf("no destination interfaces defined")
	}
	if len(filteredServices) == 0 {
		return "", fmt.Errorf("no services defined")
	}

	var sb strings.Builder
	for _, src := range srcIntfs {
		for _, dst := range dstIntfs {
			for _, svc := range filteredServices {
				name := svc.Name
				if svc.Type == "custom" {
					name = "custom_" + svc.Name
				}
				policyName := limitString(fmt.Sprintf("%s-%s-%s-%s", p.PolicyName, src, dst, name), 32)

				pCopy := p
				pCopy.SrcInterfaces = []string{src}
				pCopy.DstInterfaces = []string{dst}

				cli, err := GenerateSinglePolicyCLI(pCopy, policyName, []Service{svc})
				if err != nil {
					return "", err
				}
				sb.WriteString(cli)
				sb.WriteString("\n")
			}
		}
	}
	return sb.String(), nil
}

// GenerateSinglePolicyCLI generates the actual FortiGate config CLI commands.
func GenerateSinglePolicyCLI(p Policy, policyName string, services []Service) (string, error) {
	// Normalize service types so case-insensitive comparisons work for
	// callers that bypass validatePolicy (unlikely but defensive).
	for i := range services {
		services[i].Type = strings.ToLower(services[i].Type)
	}
	var srcIntfs []string
	for _, intf := range p.SrcInterfaces {
		if intf != "" {
			srcIntfs = append(srcIntfs, intf)
		}
	}
	var dstIntfs []string
	for _, intf := range p.DstInterfaces {
		if intf != "" {
			dstIntfs = append(dstIntfs, intf)
		}
	}

	var srcAddrs []string
	for _, a := range p.SrcAddresses {
		if a != "" {
			srcAddrs = append(srcAddrs, a)
		}
	}
	var srcAddrGroups []string
	for _, a := range p.SrcAddressGroups {
		if a != "" {
			srcAddrGroups = append(srcAddrGroups, a)
		}
	}
	var srcVIPs []string
	for _, a := range p.SrcVIPs {
		if a != "" {
			srcVIPs = append(srcVIPs, a)
		}
	}
	var srcISDB []string
	for _, a := range p.SrcInternetServices {
		if a != "" {
			srcISDB = append(srcISDB, a)
		}
	}

	var dstAddrs []string
	for _, a := range p.DstAddresses {
		if a != "" {
			dstAddrs = append(dstAddrs, a)
		}
	}
	var dstAddrGroups []string
	for _, a := range p.DstAddressGroups {
		if a != "" {
			dstAddrGroups = append(dstAddrGroups, a)
		}
	}
	var dstVIPs []string
	for _, a := range p.DstVIPs {
		if a != "" {
			dstVIPs = append(dstVIPs, a)
		}
	}
	var dstISDB []string
	for _, a := range p.DstInternetServices {
		if a != "" {
			dstISDB = append(dstISDB, a)
		}
	}

	var filteredServices []Service
	for _, svc := range services {
		if svc.Name != "" {
			filteredServices = append(filteredServices, svc)
		}
	}

	if len(srcIntfs) == 0 {
		return "", fmt.Errorf("no source interfaces defined")
	}
	if len(dstIntfs) == 0 {
		return "", fmt.Errorf("no destination interfaces defined")
	}
	hasSrcAddr := len(srcAddrs) > 0 || len(srcAddrGroups) > 0 || len(srcVIPs) > 0
	hasDstAddr := len(dstAddrs) > 0 || len(dstAddrGroups) > 0 || len(dstVIPs) > 0
	if !hasSrcAddr && len(srcISDB) == 0 {
		return "", fmt.Errorf("no source addresses or internet services defined")
	}
	if !hasDstAddr && len(dstISDB) == 0 {
		return "", fmt.Errorf("no destination addresses or internet services defined")
	}
	if len(filteredServices) == 0 {
		return "", fmt.Errorf("no services defined")
	}

	var sb strings.Builder

	for _, svc := range filteredServices {
		if svc.Type == "custom" {
			protocol := strings.ToUpper(svc.Protocol)
			sb.WriteString("config firewall service custom\n")
			fmt.Fprintf(&sb, "edit \"custom_%s\"\n", svc.Name)
			if protocol == "ICMP" {
				sb.WriteString("set protocol ICMP\n")
				fmt.Fprintf(&sb, "set icmptype %s\n", svc.Port)
			} else {
				sb.WriteString("set protocol TCP/UDP/SCTP\n")
				fmt.Fprintf(&sb, "set %s-portrange %s\n", strings.ToLower(protocol), svc.Port)
			}
			sb.WriteString("next\nend\n")
		}
	}

	sb.WriteString("config firewall policy\n")
	sb.WriteString("edit 0\n")
	fmt.Fprintf(&sb, "set name \"%s\"\n", limitString(policyName, 32))
	if p.PolicyComment != "" {
		fmt.Fprintf(&sb, "set comments \"%s\"\n", p.PolicyComment)
	}

	var quotedSrcIntfs []string
	for _, intf := range srcIntfs {
		quotedSrcIntfs = append(quotedSrcIntfs, fmt.Sprintf("\"%s\"", intf))
	}
	sb.WriteString("set srcintf " + strings.Join(quotedSrcIntfs, " ") + "\n")

	var quotedDstIntfs []string
	for _, intf := range dstIntfs {
		quotedDstIntfs = append(quotedDstIntfs, fmt.Sprintf("\"%s\"", intf))
	}
	sb.WriteString("set dstintf " + strings.Join(quotedDstIntfs, " ") + "\n")

	var quotedSrcAddrs []string
	for _, a := range srcAddrs {
		quotedSrcAddrs = append(quotedSrcAddrs, fmt.Sprintf("\"%s\"", a))
	}
	for _, a := range srcAddrGroups {
		quotedSrcAddrs = append(quotedSrcAddrs, fmt.Sprintf("\"%s\"", a))
	}
	for _, a := range srcVIPs {
		quotedSrcAddrs = append(quotedSrcAddrs, fmt.Sprintf("\"%s\"", a))
	}
	if len(quotedSrcAddrs) > 0 {
		sb.WriteString("set srcaddr " + strings.Join(quotedSrcAddrs, " ") + "\n")
	}

	if len(srcISDB) > 0 {
		sb.WriteString("set internet-service-src enable\n")
		var ids []string
		var names []string
		for _, val := range srcISDB {
			if isNumericID(val) {
				ids = append(ids, fmt.Sprintf("\"%s\"", val))
			} else {
				names = append(names, fmt.Sprintf("\"%s\"", val))
			}
		}
		if len(ids) > 0 {
			// Source side uses the -src- keys (internet-service-id is the
			// destination-side key and would match the wrong traffic).
			sb.WriteString("set internet-service-src-id " + strings.Join(ids, " ") + "\n")
		}
		if len(names) > 0 {
			sb.WriteString("set internet-service-src-name " + strings.Join(names, " ") + "\n")
		}
	}

	var quotedDstAddrs []string
	for _, a := range dstAddrs {
		quotedDstAddrs = append(quotedDstAddrs, fmt.Sprintf("\"%s\"", a))
	}
	for _, a := range dstAddrGroups {
		quotedDstAddrs = append(quotedDstAddrs, fmt.Sprintf("\"%s\"", a))
	}
	for _, a := range dstVIPs {
		quotedDstAddrs = append(quotedDstAddrs, fmt.Sprintf("\"%s\"", a))
	}
	if len(quotedDstAddrs) > 0 {
		sb.WriteString("set dstaddr " + strings.Join(quotedDstAddrs, " ") + "\n")
	}

	if len(dstISDB) > 0 {
		sb.WriteString("set internet-service enable\n")
		var ids []string
		var names []string
		for _, val := range dstISDB {
			if isNumericID(val) {
				ids = append(ids, fmt.Sprintf("\"%s\"", val))
			} else {
				names = append(names, fmt.Sprintf("\"%s\"", val))
			}
		}
		if len(ids) > 0 {
			sb.WriteString("set internet-service-id " + strings.Join(ids, " ") + "\n")
		}
		if len(names) > 0 {
			sb.WriteString("set internet-service-name " + strings.Join(names, " ") + "\n")
		}
	}

	if len(p.Users) > 0 {
		var usersList []string
		for _, u := range p.Users {
			if u != "" {
				usersList = append(usersList, fmt.Sprintf("\"%s\"", u))
			}
		}
		if len(usersList) > 0 {
			sb.WriteString("set users " + strings.Join(usersList, " ") + "\n")
		}
	}
	if len(p.Groups) > 0 {
		var groupsList []string
		for _, g := range p.Groups {
			if g != "" {
				groupsList = append(groupsList, fmt.Sprintf("\"%s\"", g))
			}
		}
		if len(groupsList) > 0 {
			sb.WriteString("set groups " + strings.Join(groupsList, " ") + "\n")
		}
	}

	var svcsList []string
	for _, svc := range filteredServices {
		name := svc.Name
		if svc.Type == "custom" {
			name = "custom_" + svc.Name
		}
		if name != "" {
			svcsList = append(svcsList, fmt.Sprintf("\"%s\"", name))
		}
	}
	sb.WriteString("set service " + strings.Join(svcsList, " ") + "\n")

	fmt.Fprintf(&sb, "set action %s\n", p.Action)
	sb.WriteString("set schedule \"always\"\n")
	fmt.Fprintf(&sb, "set inspection-mode %s\n", p.InspectionMode)

	isDeny := strings.ToLower(p.Action) == "deny"
	hasProfiles := p.SSLSSHProfile != "" ||
		(p.WebfilterProfile != "" && p.WebfilterEnabled) ||
		(p.AVProfile != "" && p.AVEnabled) ||
		(p.ApplicationList != "" && p.ApplicationListEnabled) ||
		(p.IPSSensor != "" && p.IPSSensorEnabled)

	if !isDeny && hasProfiles {
		sb.WriteString("set utm-status enable\n")
	}
	if !isDeny && p.SSLSSHProfile != "" {
		fmt.Fprintf(&sb, "set ssl-ssh-profile \"%s\"\n", p.SSLSSHProfile)
	}
	if !isDeny && p.WebfilterProfile != "" && p.WebfilterEnabled {
		fmt.Fprintf(&sb, "set webfilter-profile \"%s\"\n", p.WebfilterProfile)
	}
	if !isDeny && p.AVProfile != "" && p.AVEnabled {
		fmt.Fprintf(&sb, "set av-profile \"%s\"\n", p.AVProfile)
	}
	if !isDeny && p.ApplicationList != "" && p.ApplicationListEnabled {
		fmt.Fprintf(&sb, "set application-list \"%s\"\n", p.ApplicationList)
	}
	if !isDeny && p.IPSSensor != "" && p.IPSSensorEnabled {
		fmt.Fprintf(&sb, "set ips-sensor \"%s\"\n", p.IPSSensor)
	}

	fmt.Fprintf(&sb, "set logtraffic %s\n", p.LogTraffic)
	fmt.Fprintf(&sb, "set logtraffic-start %s\n", p.LogTrafficStart)
	fmt.Fprintf(&sb, "set auto-asic-offload %s\n", p.AutoAsicOffload)
	fmt.Fprintf(&sb, "set nat %s\n", p.Nat)

	if strings.ToLower(p.Nat) == "enable" && p.IPPool != "" {
		sb.WriteString("set ippool enable\n")
		fmt.Fprintf(&sb, "set poolname \"%s\"\n", p.IPPool)
	}

	sb.WriteString("next\nend\n")
	return sb.String(), nil
}

func limitString(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}
