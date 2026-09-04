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
	Icon    string
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
	current := func(key, label, href, icon string) NavItem {
		return NavItem{Key: key, Label: label, Href: href, Icon: icon, Current: options.Active == key}
	}
	groups := []NavGroup{
		{Key: "overview", Label: labels.overview, Items: []NavItem{
			current("dashboard", labels.dashboard, "/dashboard", "nav-dashboard"),
			current("firewalls", labels.firewalls, "/", "nav-firewalls"),
			current("search", labels.search, "/search", "nav-search"),
			current("audit", labels.audit, "/audit", "nav-audit"),
			current("topology", labels.topology, "/topology", "nav-topology"),
		}},
		{Key: "network", Label: labels.networkData, Items: []NavItem{
			current("ipam", labels.ipam, "/ipam", "nav-ipam"),
			current("licenses", labels.licenses, "/licenses", "nav-licenses"),
			current("activity", labels.activity, "/activity_log", "nav-activity"),
		}},
	}

	tools := make([]NavItem, 0, 5)
	if options.AdmVPN {
		tools = append(tools, current("admvpn", labels.admVPN, "/fgt-adm-vpn-conf/", "nav-admvpn"))
	}
	if options.ConfGen {
		tools = append(tools, current("configgen", labels.confGen, "/fgt-confgen/", "nav-configgen"))
	}
	if options.PolSplit {
		tools = append(tools, current("polsplit", labels.polSplit, "/fgt-polsplit/", "nav-polsplit"))
	}
	if options.ConfConv {
		tools = append(tools, current("confconv", labels.confConv, "/fgt-confconv/", "nav-confconv"))
	}
	if options.ConfTail {
		tools = append(tools, current("conftail", labels.confTail, "/fgt-conftail/", "nav-conftail"))
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
