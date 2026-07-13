package fgt_confgen

import (
	"fmt"
	"strings"
)

// GenerateOutput1 generates all-in-one policies.
func GenerateOutput1(p Policy) string {
	return GenerateSinglePolicyCLI(p, p.PolicyName, p.Services)
}

// GenerateOutput2 generates one policy per service.
func GenerateOutput2(p Policy) string {
	if len(p.Services) == 0 {
		return "No services defined for this policy."
	}
	var sb strings.Builder
	for _, svc := range p.Services {
		name := svc.Name
		if svc.Type == "custom" {
			name = "custom_" + svc.Name
		}
		policyName := limitString(fmt.Sprintf("%s-%s", p.PolicyName, name), 32)
		sb.WriteString(GenerateSinglePolicyCLI(p, policyName, []Service{svc}))
		sb.WriteString("\n")
	}
	return sb.String()
}

// GenerateOutput3 generates one policy per source interface, destination interface, and service combination.
func GenerateOutput3(p Policy) string {
	if len(p.SrcInterfaces) == 0 || len(p.DstInterfaces) == 0 || len(p.Services) == 0 {
		return "No valid source interfaces, destination interfaces, or services defined."
	}

	var sb strings.Builder
	for _, src := range p.SrcInterfaces {
		if src == "" {
			continue
		}
		for _, dst := range p.DstInterfaces {
			if dst == "" {
				continue
			}
			for _, svc := range p.Services {
				name := svc.Name
				if svc.Type == "custom" {
					name = "custom_" + svc.Name
				}
				policyName := limitString(fmt.Sprintf("%s-%s-%s-%s", p.PolicyName, src, dst, name), 32)
				sb.WriteString(GenerateSinglePolicyCLI(p, policyName, []Service{svc}))
				sb.WriteString("\n")
			}
		}
	}
	return sb.String()
}

// GenerateSinglePolicyCLI generates the actual FortiGate config CLI commands.
func GenerateSinglePolicyCLI(p Policy, policyName string, services []Service) string {
	if len(p.SrcInterfaces) == 0 || len(p.DstInterfaces) == 0 {
		return ""
	}
	hasSrcAddr := len(p.SrcAddresses) > 0 || len(p.SrcAddressGroups) > 0 || len(p.SrcVIPs) > 0
	hasDstAddr := len(p.DstAddresses) > 0 || len(p.DstAddressGroups) > 0 || len(p.DstVIPs) > 0
	if !hasSrcAddr && len(p.SrcInternetServices) == 0 {
		return ""
	}
	if !hasDstAddr && len(p.DstInternetServices) == 0 {
		return ""
	}
	if len(services) == 0 {
		return ""
	}

	var sb strings.Builder

	// Create custom services first if needed
	for _, svc := range services {
		if svc.Type == "custom" {
			sb.WriteString("config firewall service custom\n")
			fmt.Fprintf(&sb, "edit \"custom_%s\"\n", svc.Name)
			fmt.Fprintf(&sb, "set %s %s\n", strings.ToLower(svc.Protocol), svc.Port)
			sb.WriteString("next\nend\n")
		}
	}

	sb.WriteString("config firewall policy\n")
	sb.WriteString("edit 0\n")
	fmt.Fprintf(&sb, "set name \"%s\"\n", limitString(policyName, 32))
	if p.PolicyComment != "" {
		fmt.Fprintf(&sb, "set comments \"%s\"\n", p.PolicyComment)
	}

	// Interfaces
	var srcIntfs []string
	for _, intf := range p.SrcInterfaces {
		if intf != "" {
			srcIntfs = append(srcIntfs, fmt.Sprintf("\"%s\"", intf))
		}
	}
	sb.WriteString("set srcintf " + strings.Join(srcIntfs, " ") + "\n")

	var dstIntfs []string
	for _, intf := range p.DstInterfaces {
		if intf != "" {
			dstIntfs = append(dstIntfs, fmt.Sprintf("\"%s\"", intf))
		}
	}
	sb.WriteString("set dstintf " + strings.Join(dstIntfs, " ") + "\n")

	// Source addresses / ISDB
	var srcAddrs []string
	for _, a := range p.SrcAddresses {
		if a != "" {
			srcAddrs = append(srcAddrs, fmt.Sprintf("\"%s\"", a))
		}
	}
	for _, a := range p.SrcAddressGroups {
		if a != "" {
			srcAddrs = append(srcAddrs, fmt.Sprintf("\"%s\"", a))
		}
	}
	for _, a := range p.SrcVIPs {
		if a != "" {
			srcAddrs = append(srcAddrs, fmt.Sprintf("\"%s\"", a))
		}
	}
	if len(srcAddrs) > 0 {
		sb.WriteString("set srcaddr " + strings.Join(srcAddrs, " ") + "\n")
	}

	if len(p.SrcInternetServices) > 0 {
		sb.WriteString("set internet-service-src enable\n")
		var isdbs []string
		for _, id := range p.SrcInternetServices {
			if id != "" {
				isdbs = append(isdbs, fmt.Sprintf("\"%s\"", id))
			}
		}
		sb.WriteString("set internet-service-id " + strings.Join(isdbs, " ") + "\n")
	}

	// Destination addresses / ISDB
	var dstAddrs []string
	for _, a := range p.DstAddresses {
		if a != "" {
			dstAddrs = append(dstAddrs, fmt.Sprintf("\"%s\"", a))
		}
	}
	for _, a := range p.DstAddressGroups {
		if a != "" {
			dstAddrs = append(dstAddrs, fmt.Sprintf("\"%s\"", a))
		}
	}
	for _, a := range p.DstVIPs {
		if a != "" {
			dstAddrs = append(dstAddrs, fmt.Sprintf("\"%s\"", a))
		}
	}
	if len(dstAddrs) > 0 {
		sb.WriteString("set dstaddr " + strings.Join(dstAddrs, " ") + "\n")
	}

	if len(p.DstInternetServices) > 0 {
		sb.WriteString("set internet-service enable\n")
		var isdbs []string
		for _, id := range p.DstInternetServices {
			if id != "" {
				isdbs = append(isdbs, fmt.Sprintf("\"%s\"", id))
			}
		}
		sb.WriteString("set internet-service-id " + strings.Join(isdbs, " ") + "\n")
	}

	// Users / Groups
	if len(p.Users) > 0 {
		var usersList []string
		for _, u := range p.Users {
			if u != "" {
				usersList = append(usersList, fmt.Sprintf("\"%s\"", u))
			}
		}
		sb.WriteString("set users " + strings.Join(usersList, " ") + "\n")
	}
	if len(p.Groups) > 0 {
		var groupsList []string
		for _, g := range p.Groups {
			if g != "" {
				groupsList = append(groupsList, fmt.Sprintf("\"%s\"", g))
			}
		}
		sb.WriteString("set groups " + strings.Join(groupsList, " ") + "\n")
	}

	// Services
	var svcsList []string
	for _, svc := range services {
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
	return sb.String()
}

func limitString(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}
