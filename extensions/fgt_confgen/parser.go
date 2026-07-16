package fgt_confgen

import (
	"regexp"
	"strings"
)

var (
	editRe         = regexp.MustCompile(`^edit\s+"([^"]+)"`)
	setMemberRe    = regexp.MustCompile(`^set member\s+(.+)`)
	setSvcProtoRe  = regexp.MustCompile(`^set\s+(\w+)-portrange\s+(.+)`)
	setSvcProto2Re = regexp.MustCompile(`^set\s+(\w+)\s+(.+)`)
	setAddrRe      = regexp.MustCompile(`^set (?:srcaddr|dstaddr)\s+(.+)`)
	setIsdbRe      = regexp.MustCompile(`^set internet-service-id\s+(.+)`)
	setPoolRe      = regexp.MustCompile(`^set poolname\s+(.+)`)
	setServiceRe   = regexp.MustCompile(`^set service\s+(.+)`)
)

// KnownServices maps standard service names to protocol and port.
var KnownServices = map[string]Service{
	"HTTP":      {Name: "HTTP", Protocol: "TCP", Port: "80"},
	"HTTPS":     {Name: "HTTPS", Protocol: "TCP", Port: "443"},
	"SSH":       {Name: "SSH", Protocol: "TCP", Port: "22"},
	"DNS":       {Name: "DNS", Protocol: "UDP", Port: "53"},
	"RDP":       {Name: "RDP", Protocol: "TCP", Port: "3389"},
	"ALL_ICMP":  {Name: "ALL_ICMP", Protocol: "ICMP", Port: "0"},
	"ALL_ICMP6": {Name: "ALL_ICMP6", Protocol: "ICMP6", Port: "0"},
	"PING":      {Name: "PING", Protocol: "ICMP", Port: "0"},
	"RADIUS":    {Name: "RADIUS", Protocol: "UDP", Port: "1812"},
	"SMB":       {Name: "SMB", Protocol: "TCP", Port: "445"},
	"SAMBA":     {Name: "SAMBA", Protocol: "TCP", Port: "445"},
	"SMTP":      {Name: "SMTP", Protocol: "TCP", Port: "25"},
	"SMTPS":     {Name: "SMTPS", Protocol: "TCP", Port: "465"},
	"IMAP":      {Name: "IMAP", Protocol: "TCP", Port: "143"},
	"IMAPS":     {Name: "IMAPS", Protocol: "TCP", Port: "993"},
	"NTP":       {Name: "NTP", Protocol: "UDP", Port: "123"},
}

type stackElem struct {
	isConfig bool
	name     string
}

func getSupportedSection(sec string) string {
	switch sec {
	case "system interface", "firewall address", "firewall addrgrp",
		"firewall internet-service-name", "firewall vip", "firewall ippool",
		"firewall service custom", "firewall service group", "user local",
		"user group", "firewall ssl-ssh-profile", "webfilter profile",
		"antivirus profile", "application list", "ips sensor":
		return sec
	default:
		return ""
	}
}

func getActiveContext(stack []stackElem) (string, string) {
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

	sec := getSupportedSection(stack[configIdx].name)
	if sec == "" {
		return "", ""
	}

	for i := configIdx + 1; i < len(stack); i++ {
		if !stack[i].isConfig {
			return sec, stack[i].name
		}
	}

	return sec, ""
}

// ParseConfig converts a raw FortiGate configuration string into security components.
func ParseConfig(content string) ParsedConfig {
	var (
		interfaces        []string
		addresses         []string
		addressGroups     []string
		internetServices  []string
		vips              []string
		ipPools           []string
		services          []Service
		serviceGroups     = make(map[string][]string)
		sslSshProfiles    []string
		webfilterProfiles []string
		avProfiles        []string
		applicationLists  []string
		ipsSensors        []string
		users             []string
		groups            []string

		intfSet    = make(map[string]bool)
		addrSet    = make(map[string]bool)
		addrGrpSet = make(map[string]bool)
		isdbSet    = make(map[string]bool)
		vipSet     = make(map[string]bool)
		poolSet    = make(map[string]bool)
		svcSet     = make(map[string]bool)
		sslSshSet  = make(map[string]bool)
		wfSet      = make(map[string]bool)
		avSet      = make(map[string]bool)
		appSet     = make(map[string]bool)
		ipsSet     = make(map[string]bool)
		userSet    = make(map[string]bool)
		groupSet   = make(map[string]bool)
	)

	lines := strings.Split(content, "\n")

	svcProtocol := "TCP"
	svcPort := "0"

	addInterface := func(name string) {
		if name != "" && !intfSet[name] {
			intfSet[name] = true
			interfaces = append(interfaces, name)
		}
	}

	addAddress := func(name string) {
		if name != "" && !addrSet[name] {
			addrSet[name] = true
			addresses = append(addresses, name)
		}
	}

	addAddrGrp := func(name string) {
		if name != "" {
			addAddress(name)
			if !addrGrpSet[name] {
				addrGrpSet[name] = true
				addressGroups = append(addressGroups, name)
			}
		}
	}

	addIsdb := func(name string) {
		if name != "" && !isdbSet[name] {
			isdbSet[name] = true
			internetServices = append(internetServices, name)
		}
	}

	addVip := func(name string) {
		if name != "" {
			addAddress(name)
			if !vipSet[name] {
				vipSet[name] = true
				vips = append(vips, name)
			}
		}
	}

	addIpPool := func(name string) {
		if name != "" && !poolSet[name] {
			poolSet[name] = true
			ipPools = append(ipPools, name)
		}
	}

	addSvc := func(name, protocol, port string) {
		if name != "" && !svcSet[name] {
			svcSet[name] = true
			services = append(services, Service{
				Name:     name,
				Protocol: protocol,
				Port:     port,
			})
		}
	}

	parseSpaceDelimited := func(val string) []string {
		var out []string
		var current strings.Builder
		inQuotes := false
		for i := 0; i < len(val); i++ {
			c := val[i]
			if c == '"' {
				inQuotes = !inQuotes
			} else if c == ' ' && !inQuotes {
				if current.Len() > 0 {
					out = append(out, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(c)
			}
		}
		if current.Len() > 0 {
			out = append(out, current.String())
		}
		return out
	}

	var stack []stackElem

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "config ") {
			secName := strings.TrimSpace(strings.TrimPrefix(line, "config "))
			stack = append(stack, stackElem{isConfig: true, name: secName})
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
			activeSec, outerEdit := getActiveContext(stack)
			if activeSec == "firewall service custom" && outerEdit != "" {
				addSvc(outerEdit, svcProtocol, svcPort)
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
			match := editRe.FindStringSubmatch(line)
			if len(match) > 1 {
				editName := strings.Trim(match[1], `"`)
				stack = append(stack, stackElem{isConfig: false, name: editName})

				activeSec, outerEdit := getActiveContext(stack)
				if activeSec != "" && outerEdit == editName {
					svcProtocol = "TCP"
					svcPort = "0"

					switch activeSec {
					case "system interface":
						addInterface(editName)
					case "firewall address":
						addAddress(editName)
					case "firewall addrgrp":
						addAddrGrp(editName)
					case "firewall internet-service-name":
						addIsdb(editName)
					case "firewall vip":
						addVip(editName)
					case "firewall ippool":
						addIpPool(editName)
					case "user local":
						if !userSet[editName] {
							userSet[editName] = true
							users = append(users, editName)
						}
					case "user group":
						if !groupSet[editName] {
							groupSet[editName] = true
							groups = append(groups, editName)
						}
					case "firewall ssl-ssh-profile":
						if !sslSshSet[editName] {
							sslSshSet[editName] = true
							sslSshProfiles = append(sslSshProfiles, editName)
						}
					case "webfilter profile":
						if !wfSet[editName] {
							wfSet[editName] = true
							webfilterProfiles = append(webfilterProfiles, editName)
						}
					case "antivirus profile":
						if !avSet[editName] {
							avSet[editName] = true
							avProfiles = append(avProfiles, editName)
						}
					case "application list":
						if !appSet[editName] {
							appSet[editName] = true
							applicationLists = append(applicationLists, editName)
						}
					case "ips sensor":
						if !ipsSet[editName] {
							ipsSet[editName] = true
							ipsSensors = append(ipsSensors, editName)
						}
					}
				}
			}
			continue
		}

		activeSec, outerEdit := getActiveContext(stack)

		// Parse settings inside edits
		if activeSec == "firewall service custom" && outerEdit != "" && strings.HasPrefix(line, "set ") {
			if m := setSvcProtoRe.FindStringSubmatch(line); len(m) > 2 {
				svcProtocol = strings.ToUpper(m[1])
				svcPort = strings.TrimSpace(m[2])
			} else if m := setSvcProto2Re.FindStringSubmatch(line); len(m) > 2 {
				proto := strings.ToLower(m[1])
				if proto == "tcp" || proto == "udp" || proto == "sctp" {
					svcProtocol = strings.ToUpper(m[1])
					svcPort = strings.TrimSpace(m[2])
				}
			}
			continue
		}

		if activeSec == "firewall service group" && outerEdit != "" && strings.HasPrefix(line, "set member ") {
			match := setMemberRe.FindStringSubmatch(line)
			if len(match) > 1 {
				members := parseSpaceDelimited(match[1])
				serviceGroups[outerEdit] = members
			}
			continue
		}

		// Fallbacks for references in firewall policies
		if strings.HasPrefix(line, "set ") {
			if m := setAddrRe.FindStringSubmatch(line); len(m) > 1 {
				for _, addr := range parseSpaceDelimited(m[1]) {
					addAddress(addr)
				}
			} else if m := setIsdbRe.FindStringSubmatch(line); len(m) > 1 {
				for _, isdb := range parseSpaceDelimited(m[1]) {
					addIsdb(isdb)
				}
			} else if m := setPoolRe.FindStringSubmatch(line); len(m) > 1 {
				for _, pool := range parseSpaceDelimited(m[1]) {
					addIpPool(pool)
				}
			} else if m := setServiceRe.FindStringSubmatch(line); len(m) > 1 {
				for _, svcName := range parseSpaceDelimited(m[1]) {
					if !svcSet[svcName] && serviceGroups[svcName] == nil {
						if kSvc, ok := KnownServices[svcName]; ok {
							addSvc(svcName, kSvc.Protocol, kSvc.Port)
						} else {
							addSvc(svcName, "TCP", "0")
						}
					}
				}
			}
		}
	}

	return ParsedConfig{
		Interfaces:        interfaces,
		Addresses:         addresses,
		AddressGroups:     addressGroups,
		InternetServices:  internetServices,
		VIPs:              vips,
		IPPools:           ipPools,
		Services:          services,
		ServiceGroups:     serviceGroups,
		SSLSSHProfiles:    sslSshProfiles,
		WebfilterProfiles: webfilterProfiles,
		AVProfiles:        avProfiles,
		ApplicationLists:  applicationLists,
		IPSSensors:        ipsSensors,
		Users:             users,
		Groups:            groups,
	}
}
