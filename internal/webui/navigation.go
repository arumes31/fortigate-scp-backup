package webui

// NavGroup is one named group in the permanent desktop navigation rail.
type NavGroup struct {
	Label string
	Items []NavItem
}

// NavItem is a stable presentation-only navigation link.
type NavItem struct {
	Key     string
	Label   string
	Href    string
	Current bool
}

// NavigationOptions describes host-authorized feature visibility. Disabled
// extensions are omitted rather than rendered as unavailable links.
type NavigationOptions struct {
	Active   string
	IsRadius bool
	AdmVPN   bool
	ConfGen  bool
	PolSplit bool
	ConfConv bool
	ConfTail bool
}

// Navigation builds a fresh grouped navigation model for one request.
func Navigation(options NavigationOptions) []NavGroup {
	current := func(key, label, href string) NavItem {
		return NavItem{Key: key, Label: label, Href: href, Current: options.Active == key}
	}
	groups := []NavGroup{
		{Label: "Overview", Items: []NavItem{
			current("dashboard", "Dashboard", "/dashboard"),
			current("firewalls", "Firewalls", "/"),
		}},
		{Label: "Network data", Items: []NavItem{
			current("audit", "Audit", "/audit"),
			current("topology", "Topology", "/topology"),
			current("ipam", "IPAM", "/ipam"),
			current("licenses", "Licenses", "/licenses"),
			current("activity", "Activity log", "/activity_log"),
		}},
	}

	tools := []NavItem{current("search", "Search", "/search")}
	if options.AdmVPN {
		tools = append(tools, current("admvpn", "ADM VPN Config", "/fgt-adm-vpn-conf/"))
	}
	if options.ConfGen {
		tools = append(tools, current("configgen", "Policy Generator", "/fgt-confgen/"))
	}
	if options.PolSplit {
		tools = append(tools, current("polsplit", "Policy Split", "/fgt-polsplit/"))
	}
	if options.ConfConv {
		tools = append(tools, current("confconv", "Config Converter", "/fgt-confconv/"))
	}
	if options.ConfTail {
		tools = append(tools, current("conftail", "Configuration Tail", "/fgt-conftail/"))
	}
	groups = append(groups, NavGroup{Label: "Tools", Items: tools})
	if !options.IsRadius {
		groups = append(groups, NavGroup{Label: "Utilities", Items: []NavItem{
			current("password", "Change password", "/change_password"),
		}})
	}
	return groups
}
