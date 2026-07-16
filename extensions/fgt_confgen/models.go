package fgt_confgen

// FirewallRef represents a reference to a firewall in the main database.
type FirewallRef struct {
	ID   int    `json:"id"`
	FQDN string `json:"fqdn"`
}

// Service represents a network service reference in a policy.
type Service struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
}

// Policy represents a single FortiGate policy configured in the UI.
type Policy struct {
	PolicyID               string    `json:"policy_id"`
	PolicyName             string    `json:"policy_name"`
	PolicyComment          string    `json:"policy_comment"`
	SrcInterfaces          []string  `json:"src_interfaces"`
	DstInterfaces          []string  `json:"dst_interfaces"`
	SrcAddresses           []string  `json:"src_addresses"`
	SrcAddressGroups       []string  `json:"src_address_groups"`
	SrcInternetServices    []string  `json:"src_internet_services"`
	SrcVIPs                []string  `json:"src_vips"`
	DstAddresses           []string  `json:"dst_addresses"`
	DstAddressGroups       []string  `json:"dst_address_groups"`
	DstInternetServices    []string  `json:"dst_internet_services"`
	DstVIPs                []string  `json:"dst_vips"`
	Services               []Service `json:"services"`
	Action                 string    `json:"action"`
	InspectionMode         string    `json:"inspection_mode"`
	SSLSSHProfile          string    `json:"ssl_ssh_profile"`
	WebfilterProfile       string    `json:"webfilter_profile"`
	WebfilterEnabled       bool      `json:"webfilter_enabled"`
	AVProfile              string    `json:"av_profile"`
	AVEnabled              bool      `json:"av_enabled"`
	ApplicationList        string    `json:"application_list"`
	ApplicationListEnabled bool      `json:"application_list_enabled"`
	IPSSensor              string    `json:"ips_sensor"`
	IPSSensorEnabled       bool      `json:"ips_sensor_enabled"`
	LogTraffic             string    `json:"logtraffic"`
	LogTrafficStart        string    `json:"logtraffic_start"`
	AutoAsicOffload        string    `json:"auto_asic_offload"`
	Nat                    string    `json:"nat"`
	IPPool                 string    `json:"ip_pool"`
	Users                  []string  `json:"users"`
	Groups                 []string  `json:"groups"`
}

// TemplateData matches the JSON structure stored inside templates.data.
type TemplateData struct {
	Policies []Policy `json:"policies"`
}

// Template represents a saved template database row.
type Template struct {
	Username string       `json:"username"`
	Name     string       `json:"name"`
	Data     TemplateData `json:"data"`
}

// ParsedConfig holds the elements extracted from a raw FortiGate configuration.
type ParsedConfig struct {
	Interfaces        []string            `json:"interfaces"`
	Addresses         []string            `json:"addresses"`
	AddressGroups     []string            `json:"address_groups"`
	InternetServices  []string            `json:"internet_services"`
	VIPs              []string            `json:"vips"`
	IPPools           []string            `json:"ip_pools"`
	Services          []Service           `json:"services"`
	ServiceGroups     map[string][]string `json:"service_groups"`
	SSLSSHProfiles    []string            `json:"ssl_ssh_profiles"`
	WebfilterProfiles []string            `json:"webfilter_profiles"`
	AVProfiles        []string            `json:"av_profiles"`
	ApplicationLists  []string            `json:"application_lists"`
	IPSSensors        []string            `json:"ips_sensors"`
	Users             []string            `json:"users"`
	Groups            []string            `json:"groups"`
}
