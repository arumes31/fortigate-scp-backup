package webui

// NavGroup is one named group in the permanent desktop navigation rail.
type NavGroup struct {
	Key   string
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
	Lang     string
	Active   string
	AdmVPN   bool
	ConfGen  bool
	PolSplit bool
	ConfConv bool
	ConfTail bool
}

// Navigation builds a fresh grouped navigation model for one request.
func Navigation(options NavigationOptions) []NavGroup {
	labels := navigationText(options.Lang)
	current := func(key, label, href string) NavItem {
		return NavItem{Key: key, Label: label, Href: href, Current: options.Active == key}
	}
	groups := []NavGroup{
		{Key: "overview", Label: labels.overview, Items: []NavItem{
			current("dashboard", labels.dashboard, "/dashboard"),
			current("firewalls", labels.firewalls, "/"),
			current("search", labels.search, "/search"),
			current("audit", labels.audit, "/audit"),
			current("topology", labels.topology, "/topology"),
		}},
		{Key: "network", Label: labels.networkData, Items: []NavItem{
			current("ipam", labels.ipam, "/ipam"),
			current("licenses", labels.licenses, "/licenses"),
			current("activity", labels.activity, "/activity_log"),
		}},
	}

	tools := make([]NavItem, 0, 5)
	if options.AdmVPN {
		tools = append(tools, current("admvpn", labels.admVPN, "/fgt-adm-vpn-conf/"))
	}
	if options.ConfGen {
		tools = append(tools, current("configgen", labels.confGen, "/fgt-confgen/"))
	}
	if options.PolSplit {
		tools = append(tools, current("polsplit", labels.polSplit, "/fgt-polsplit/"))
	}
	if options.ConfConv {
		tools = append(tools, current("confconv", labels.confConv, "/fgt-confconv/"))
	}
	if options.ConfTail {
		tools = append(tools, current("conftail", labels.confTail, "/fgt-conftail/"))
	}
	if len(tools) > 0 {
		groups = append(groups, NavGroup{Key: "tools", Label: labels.tools, Items: tools})
	}
	return groups
}

type navigationLabels struct {
	overview, networkData, tools                  string
	dashboard, firewalls, search, audit, topology string
	ipam, licenses, activity                      string
	admVPN, confGen, polSplit, confConv, confTail string
}

func navigationText(lang string) navigationLabels {
	if lang == "de" {
		return navigationLabels{
			overview: "Übersicht", networkData: "Netzwerkdaten", tools: "Werkzeuge",
			dashboard: "Dashboard", firewalls: "Firewalls", search: "Suche", audit: "Audit", topology: "Topologie",
			ipam: "IPAM", licenses: "Lizenzen", activity: "Aktivitätsprotokoll",
			admVPN: "ADM-VPN-Konfiguration", confGen: "Richtliniengenerator", polSplit: "Richtlinienaufteilung",
			confConv: "Konfigurationskonverter", confTail: "Konfigurationsänderungen",
		}
	}
	return navigationLabels{
		overview: "Overview", networkData: "Network data", tools: "Tools",
		dashboard: "Dashboard", firewalls: "Firewalls", search: "Search", audit: "Audit", topology: "Topology",
		ipam: "IPAM", licenses: "Licenses", activity: "Activity log",
		admVPN: "ADM VPN Config", confGen: "Policy Generator", polSplit: "Policy Split",
		confConv: "Config Converter", confTail: "Configuration Tail",
	}
}
