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
	)

	// Helper sets to avoid duplicates
	intfSet := make(map[string]bool)
	addrSet := make(map[string]bool)
	addrGrpSet := make(map[string]bool)
	isdbSet := make(map[string]bool)
	vipSet := make(map[string]bool)
	poolSet := make(map[string]bool)
	svcSet := make(map[string]bool)
	sslSshSet := make(map[string]bool)
	wfSet := make(map[string]bool)
	avSet := make(map[string]bool)
	appSet := make(map[string]bool)
	ipsSet := make(map[string]bool)
	userSet := make(map[string]bool)
	groupSet := make(map[string]bool)

	lines := strings.Split(content, "\n")

	var (
		inInterface       bool
		inAddress         bool
		inAddrgrp         bool
		inInternetService bool
		inVip             bool
		inIppool          bool
		inService         bool
		inServiceGroup    bool
		inUser            bool
		inGroup           bool
		inSslSsh          bool
		inWebfilter       bool
		inAv              bool
		inApplication     bool
		inIps             bool

		nestedLevel int
		currentEdit string
		svcProtocol string
		svcPort     string
	)

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

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "config ") {
			if nestedLevel > 0 || inInterface || inAddress || inAddrgrp || inInternetService || inVip || inIppool || inService || inServiceGroup || inUser || inGroup || inSslSsh || inWebfilter || inAv || inApplication || inIps {
				nestedLevel++
				continue
			}

			switch {
			case strings.HasPrefix(line, "config system interface"):
				inInterface = true
			case strings.HasPrefix(line, "config firewall address"):
				inAddress = true
			case strings.HasPrefix(line, "config firewall addrgrp"):
				inAddrgrp = true
			case strings.HasPrefix(line, "config firewall internet-service-name"):
				inInternetService = true
			case strings.HasPrefix(line, "config firewall vip"):
				inVip = true
			case strings.HasPrefix(line, "config firewall ippool"):
				inIppool = true
			case strings.HasPrefix(line, "config firewall service custom"):
				inService = true
			case strings.HasPrefix(line, "config firewall service group"):
				inServiceGroup = true
			case strings.HasPrefix(line, "config user local"):
				inUser = true
			case strings.HasPrefix(line, "config user group"):
				inGroup = true
			case strings.HasPrefix(line, "config firewall ssl-ssh-profile"):
				inSslSsh = true
			case strings.HasPrefix(line, "config webfilter profile"):
				inWebfilter = true
			case strings.HasPrefix(line, "config antivirus profile"):
				inAv = true
			case strings.HasPrefix(line, "config application list"):
				inApplication = true
			case strings.HasPrefix(line, "config ips sensor"):
				inIps = true
			default:
				nestedLevel++
			}
			continue
		}

		if line == "end" {
			if nestedLevel > 0 {
				nestedLevel--
			} else {
				inInterface = false
				inAddress = false
				inAddrgrp = false
				inInternetService = false
				inVip = false
				inIppool = false
				inService = false
				inServiceGroup = false
				inUser = false
				inGroup = false
				inSslSsh = false
				inWebfilter = false
				inAv = false
				inApplication = false
				inIps = false
			}
			continue
		}

		// Edit matching
		if strings.HasPrefix(line, "edit ") {
			match := editRe.FindStringSubmatch(line)
			if len(match) > 1 {
				currentEdit = match[1]
				svcProtocol = "TCP"
				svcPort = "0"

				switch {
				case inInterface:
					addInterface(currentEdit)
				case inAddress:
					addAddress(currentEdit)
				case inAddrgrp:
					addAddrGrp(currentEdit)
				case inInternetService:
					addIsdb(currentEdit)
				case inVip:
					addVip(currentEdit)
				case inIppool:
					addIpPool(currentEdit)
				case inUser:
					if !userSet[currentEdit] {
						userSet[currentEdit] = true
						users = append(users, currentEdit)
					}
				case inGroup:
					if !groupSet[currentEdit] {
						groupSet[currentEdit] = true
						groups = append(groups, currentEdit)
					}
				case inSslSsh:
					if !sslSshSet[currentEdit] {
						sslSshSet[currentEdit] = true
						sslSshProfiles = append(sslSshProfiles, currentEdit)
					}
				case inWebfilter:
					if !wfSet[currentEdit] {
						wfSet[currentEdit] = true
						webfilterProfiles = append(webfilterProfiles, currentEdit)
					}
				case inAv:
					if !avSet[currentEdit] {
						avSet[currentEdit] = true
						avProfiles = append(avProfiles, currentEdit)
					}
				case inApplication:
					if !appSet[currentEdit] {
						appSet[currentEdit] = true
						applicationLists = append(applicationLists, currentEdit)
					}
				case inIps:
					if !ipsSet[currentEdit] {
						ipsSet[currentEdit] = true
						ipsSensors = append(ipsSensors, currentEdit)
					}
				}
			}
			continue
		}

		if line == "next" {
			if inService && currentEdit != "" {
				addSvc(currentEdit, svcProtocol, svcPort)
			}
			currentEdit = ""
			continue
		}

		// Parse settings inside edits
		if inService && currentEdit != "" && strings.HasPrefix(line, "set ") {
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

		if inServiceGroup && currentEdit != "" && strings.HasPrefix(line, "set member ") {
			match := setMemberRe.FindStringSubmatch(line)
			if len(match) > 1 {
				members := parseSpaceDelimited(match[1])
				serviceGroups[currentEdit] = members
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
