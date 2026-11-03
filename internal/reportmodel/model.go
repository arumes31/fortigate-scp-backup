// Package reportmodel is the renderer-neutral, secret-free reporting contract.
package reportmodel

import "time"

const (
	Version       = "2"
	SchemaVersion = 2
)

// Source pins a report set to one committed backup, never a mutable latest file.
type Source struct {
	FirewallID  int       `json:"firewall_id"`
	Firewall    string    `json:"firewall"`
	BackupID    int       `json:"backup_id"`
	BackupAt    time.Time `json:"backup_at"`
	Checksum    string    `json:"checksum"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Assessment contains allowlisted configuration facts, not raw configuration.
type Assessment struct {
	Firmware  string     `json:"firmware"`
	Hostname  string     `json:"hostname"`
	VDOMs     []string   `json:"vdoms"`
	Complete  bool       `json:"complete"`
	Warnings  []string   `json:"warnings"`
	Exposures []Exposure `json:"exposures"`
	Sections  []Section  `json:"sections"`
	Findings  []Finding  `json:"findings"`
	Telemetry *Telemetry `json:"telemetry,omitempty"`
}

type Exposure struct {
	VDOM              string        `json:"vdom"`
	Name              string        `json:"name"`
	Type              string        `json:"type"`
	Kind              string        `json:"kind"`
	External          string        `json:"external"`
	ExternalInterface string        `json:"external_interface"`
	Backends          []string      `json:"backends"`
	Groups            []string      `json:"groups"`
	PolicyIDs         []string      `json:"policy_ids"`
	Outcome           string        `json:"outcome"`
	GeoStatus         string        `json:"geo_status"`
	Notes             []string      `json:"notes"`
	Evidence          string        `json:"evidence"`
	Trace             []PolicyTrace `json:"trace"`
}

type PolicyTrace struct {
	Sequence             int    `json:"sequence"`
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Action               string `json:"action"`
	Source               string `json:"source"`
	SourceInterface      string `json:"source_interface"`
	DestinationInterface string `json:"destination_interface"`
	Destination          string `json:"destination"`
	Service              string `json:"service"`
	Schedule             string `json:"schedule"`
	Status               string `json:"status"`
	VIPMatch             string `json:"vip_match"`
	Profiles             string `json:"profiles"`
	Logging              string `json:"logging"`
	Effect               string `json:"effect"`
	Evidence             string `json:"evidence"`
}

type Section struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	TitleDE string `json:"title_de"`
	Rows    []Row  `json:"rows"`
}

type Row struct {
	VDOM     string `json:"vdom"`
	Label    string `json:"label"`
	Value    string `json:"value"`
	Evidence string `json:"evidence"`
}

type Finding struct {
	ID               string `json:"id"`
	VDOM             string `json:"vdom"`
	Category         string `json:"category"`
	Exposure         string `json:"exposure,omitempty"`
	Priority         string `json:"priority"`
	Title            string `json:"title"`
	TitleDE          string `json:"title_de"`
	Detail           string `json:"detail"`
	DetailDE         string `json:"detail_de"`
	Recommendation   string `json:"recommendation"`
	RecommendationDE string `json:"recommendation_de"`
	Evidence         string `json:"evidence"`
}
