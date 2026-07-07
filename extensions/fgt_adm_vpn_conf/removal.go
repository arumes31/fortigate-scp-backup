package fgtadmvpnconf

import (
	"fmt"
	"strings"
)

// buildRemovalCommands returns the FortiGate CLI needed to tear down everything
// renderConfigFiles created for this config, so an operator can remove the config
// from the device(s) before the entry is deleted from the app.
//
// It mirrors renderConfigFiles: the RADIUS/HCI objects are only included when
// RADIUSMGT is YES. Named objects are deleted in dependency-safe order (policies
// before the interfaces/services they reference; phase2 before phase1; admins
// before groups before RADIUS servers). Firewall policies and static routes are
// created with "edit 0" (FortiGate auto-assigns their IDs), so those are listed
// as commented targets for the operator to remove by ID rather than by name.
func buildRemovalCommands(c *VpnConfig) string {
	k := c.Kundenname
	s := c.Standort
	ike := c.Ike2Username
	radiusYes := strings.ToUpper(c.Radiusmgt) == "YES"

	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p("# =====================================================================\n")
	p("# FortiGate config REMOVAL for %s - %s (%s)\n", k, s, c.RemoteipFull)
	p("# Run these on the matching device(s) BEFORE deleting the entry here.\n")
	p("# Review each block: an object still referenced elsewhere refuses to delete.\n")
	p("# =====================================================================\n\n")

	// ---- Customer firewall (<k>.<s>.FW_kunde.txt) --------------------------------
	p("# ---- Customer firewall (%s) ----\n", c.DnsNameFull)
	if radiusYes {
		p("# Firewall policies were created with 'edit 0' (auto ID). Find their IDs\n")
		p("#   show firewall policy | grep -f \"EX-adm\"\n")
		p("# then delete each by ID inside this block:\n")
		p("config firewall policy\n")
		p("#   delete <id>   # \"EX-adm https/ssh ro\"\n")
		p("#   delete <id>   # \"EX-adm radius ro\"\n")
		p("#   delete <id>   # \"EX-adm https/ssh hc\"\n")
		p("#   delete <id>   # \"EX-adm radius hc\"\n")
		p("end\n\n")

		p("# Static routes were also created with 'edit 0'. Find and delete by ID:\n")
		p("config router static\n")
		p("#   delete <id>   # dst 10.12.34.0/24 dev VPN_EX-ADMRO\n")
		p("#   delete <id>   # dst 10.250.11.192/26 dev VPN_EX-ADMHCI\n")
		p("end\n\n")

		p("config system admin\n")
		p("delete \"sg-ADM_FGT_Auth_1st-Level\"\n")
		p("delete \"sg-ADM_FGT_Auth_2nd-Level\"\n")
		p("end\n\n")

		p("config user group\n")
		p("delete \"sg-ADM_FGT_Auth_1st-Level\"\n")
		p("delete \"sg-ADM_FGT_Auth_2nd-Level\"\n")
		p("end\n\n")

		p("config user radius\n")
		p("delete \"RAD-EXADM-1stlvl_1\"\n")
		p("delete \"RAD-EXADM-1stlvl_2\"\n")
		p("delete \"RAD-EXADM-2ndlvl_1\"\n")
		p("delete \"RAD-EXADM-2ndlvl_2\"\n")
		p("end\n\n")

		p("config system accprofile\n")
		p("delete \"Readonly\"\n")
		p("end\n\n")
	}

	p("config vpn ipsec phase2-interface\n")
	p("delete \"VPN_EX-ADMRO-2nd\"\n")
	p("delete \"VPN_EX-ADMRO-1st\"\n")
	if radiusYes {
		p("delete \"VPN_EX-ADMHCI-2nd\"\n")
		p("delete \"VPN_EX-ADMHCI-1st\"\n")
	}
	p("end\n\n")

	p("config vpn ipsec phase1-interface\n")
	p("delete \"VPN_EX-ADMRO\"\n")
	if radiusYes {
		p("delete \"VPN_EX-ADMHCI\"\n")
	}
	p("end\n\n")

	p("config system interface\n")
	p("delete \"LB-EXADM\"\n")
	p("end\n\n")

	p("config firewall service custom\n")
	p("delete \"TCP9443\"\n")
	p("delete \"TCP9422\"\n")
	p("delete \"RADIUS\"\n")
	p("delete \"PING\"\n")
	p("end\n\n")

	p("# NOTE: 'set remoteauthtimeout 180' (config system global) was applied on this\n")
	p("# firewall. Reset it to your standard value if no other config still needs it.\n\n")

	// ---- EX firewall (<k>.<s>.FW_EX.txt) ----------------------------------------
	p("# ---- EX firewall (external gateway %s) ----\n", gwRO)
	if radiusYes {
		p("config vpn ipsec phase2-interface\n")
		p("delete \"VPN_ADM_%s-%s_2nd\"\n", k, s)
		p("delete \"VPN_ADM_%s-%s_1st\"\n", k, s)
		p("end\n")
	}
	p("config user local\n")
	p("delete \"%s\"\n", ike)
	p("end\n")
	p("# Also remove user \"%s\" from firewall group IPSEC_VPN_ADM_RO if it was added.\n\n", ike)

	if radiusYes {
		// ---- RZP / HCI firewall (<k>.<s>.FW_rzp.txt) ----------------------------
		p("# ---- RZP / HCI firewall (external gateway %s) ----\n", gwHCI)
		p("config vpn ipsec phase2-interface\n")
		p("delete \"VPN_ADM_%s-%s_2nd\"\n", k, s)
		p("delete \"VPN_ADM_%s-%s_1st\"\n", k, s)
		p("end\n")
		p("config user local\n")
		p("delete \"%s\"\n", ike)
		p("end\n")
		p("# Also remove user \"%s\" from firewall group IPSEC_VPN_ADM_HC if it was added.\n\n", ike)

		// ---- External (not FortiGate) ------------------------------------------
		p("# ---- External clean-up (not FortiGate) ----\n")
		p("# The generated *.radiuscfg.txt also created NPS RADIUS clients on\n")
		p("# ADM-NPS01/02 and DNS A-records for %s. Remove those separately.\n", c.DnsNameFull)
	}

	return b.String()
}
