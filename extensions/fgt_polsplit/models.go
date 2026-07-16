// Package fgt_polsplit is the policy split advisor: it analyzes the traffic a
// FortiGate policy actually carries (from Graylog traffic logs) and recommends
// how to split an overly-open policy into smaller, tightly-scoped ones,
// emitting ready-to-paste FortiGate CLI.
package fgt_polsplit

// FirewallRef represents a reference to a firewall in the main database.
type FirewallRef struct {
	ID   int    `json:"id"`
	FQDN string `json:"fqdn"`
}

// TrafficTuple is one aggregated src→dst/service combination observed in the
// policy's traffic logs.
type TrafficTuple struct {
	SrcIP    string `json:"srcip"`
	DstIP    string `json:"dstip"`
	Proto    string `json:"proto"` // tcp|udp|sctp|icmp|icmp6|ip-<n>
	Port     int    `json:"port"`  // 0 for portless protocols
	Service  string `json:"service"`
	Hits     int64  `json:"hits"`
	LastSeen string `json:"last_seen,omitempty"`
	IPv6     bool   `json:"ipv6"`
}

// Entity is one side member of a recommended policy: a single host or a
// rolled-up subnet.
type Entity struct {
	Value string `json:"value"` // "10.1.2.3" or "10.1.2.0/24"
	IsNet bool   `json:"is_net"`
	Hosts int    `json:"hosts"` // observed hosts represented (1 for plain hosts)
}

// ServiceSpec is a normalized service observed in the logs.
type ServiceSpec struct {
	Key     string `json:"key"`   // canonical "tcp/443", "icmp", "ip/47"
	Proto   string `json:"proto"` // tcp|udp|sctp|icmp|icmp6|ip-<n>
	Port    int    `json:"port"`  // 0 when portless
	LogName string `json:"log_name,omitempty"`
}

// RecPolicy is one recommended replacement policy.
type RecPolicy struct {
	Name     string        `json:"name"`
	ID       int           `json:"id"` // allocated new policy ID (0 until generated)
	Src      []Entity      `json:"src"`
	Dst      []Entity      `json:"dst"`
	Services []ServiceSpec `json:"services"`
	Hits     int64         `json:"hits"`
}

// NewObject is one address/service object that does not exist in the current
// config and must be created for the recommendation to work. The UI lists
// these explicitly next to the full CLI.
type NewObject struct {
	Kind  string `json:"kind"` // address | addrgrp | service
	Name  string `json:"name"`
	Value string `json:"value"` // human-readable definition ("10.1.2.0/24", "tcp/8443", member list)
}

// Strategy is one complete split recommendation with its generated CLI.
type Strategy struct {
	Key         string      `json:"key"` // per_service | per_destination
	Label       string      `json:"label"`
	Recommended bool        `json:"recommended"`
	Policies    []RecPolicy `json:"policies"`
	NewObjects  []NewObject `json:"new_objects"`
	Config      string      `json:"config"`
}

// OrigPolicy is the target policy as parsed from the latest config backup.
type OrigPolicy struct {
	ID       int      `json:"id"`
	VDOM     string   `json:"vdom,omitempty"`
	Name     string   `json:"name"`
	SrcIntf  []string `json:"srcintf"`
	DstIntf  []string `json:"dstintf"`
	SrcAddr  []string `json:"srcaddr"`
	DstAddr  []string `json:"dstaddr"`
	Services []string `json:"services"`
	Action   string   `json:"action"` // "" = deny (FortiOS default)
	Schedule string   `json:"schedule"`
	NAT      string   `json:"nat"`
	Status   string   `json:"status"` // "" = enable (FortiOS default)
	Comments string   `json:"comments"`

	// CloneLines are verbatim `set …` lines (srcintf/dstintf/action/schedule/
	// NAT/UTM profiles/…) carried unchanged into every split policy.
	CloneLines []string `json:"-"`
}

// ParsedBackup holds everything the analyzer/generator needs from the latest
// decrypted config backup.
type ParsedBackup struct {
	Policy      *OrigPolicy // requested policy, nil when not found
	PolicyVDOMs []string    // VDOMs where the requested ID matched (>1 = ambiguous)

	// UsedPolicyIDs are all policy IDs in the matched policy's VDOM, for
	// allocating free IDs for the split policies.
	UsedPolicyIDs []int

	// AddrByCIDR maps "10.1.2.3/32" / "10.1.2.0/24" to the names of existing
	// address objects covering exactly that host/subnet (sorted).
	AddrByCIDR map[string][]string
	// SvcByKey maps a canonical service key ("tcp/443", "icmp") to the names of
	// existing single-port service objects matching it exactly (sorted).
	SvcByKey map[string][]string
	// SvcNames maps lowercased service/service-group names to their exact name.
	SvcNames map[string]string

	// TakenNames is every existing address/addrgrp/service/service-group name
	// (lowercased), so newly generated object names never collide.
	TakenNames map[string]bool
}
