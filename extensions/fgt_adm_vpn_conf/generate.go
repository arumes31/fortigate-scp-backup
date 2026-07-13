package fgtadmvpnconf

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Fixed remote gateways used by the generated FortiGate config.
const (
	gwRO  = "80.122.63.44"
	gwHCI = "83.164.150.12"
)

// configFile is one generated file (name + content), in bundle order.
type configFile struct {
	name    string
	content string
}

// buildConfigZip reproduces the Python generate_single() output byte-for-byte.
// Only the randomly generated PSK/RADIUS secrets differ per run; all fixed text,
// blank lines, umlauts and COPYBREAK separators are identical.
func (e *Extension) buildConfigZip(c *VpnConfig) (*bytes.Buffer, error) {
	// Passwords are generated in the same order as the Python code.
	pskRo := c.IpsecPskRo
	pskHci := c.IpsecPskHci
	if strings.ToLower(c.IpsecPskRo) == "psauto" {
		pskRo = getRandomPassword(34, 4, 4, 2, 2)
	}
	if strings.ToLower(c.IpsecPskHci) == "psauto" {
		pskHci = getRandomPassword(34, 4, 4, 2, 2)
	}
	radiusro1 := getRandomPassword(20, 4, 4, 2, 2)
	radiusro2 := getRandomPassword(20, 4, 4, 2, 2)
	radiushci1 := getRandomPassword(20, 4, 4, 2, 2)
	radiushci2 := getRandomPassword(20, 4, 4, 2, 2)

	files := renderConfigFiles(c, pskRo, pskHci, radiusro1, radiusro2, radiushci1, radiushci2)

	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for _, f := range files {
		if err := addFile(zw, f.name, f.content); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}

// renderConfigFiles builds the five config files' contents given fixed
// passwords. Separating this from password generation keeps the safety-critical
// text deterministic and testable against the Python reference output.
func renderConfigFiles(c *VpnConfig, pskRo, pskHci, radiusro1, radiusro2, radiushci1, radiushci2 string) []configFile {
	k := c.Kundenname
	s := c.Standort
	ike := c.Ike2Username
	rip := c.RemoteipFull
	rip1 := c.RemoteipFull1st
	wan := c.WanInterface
	dnsFull := c.DnsNameFull
	radiusYes := strings.ToUpper(c.Radiusmgt) == "YES"

	// ---- File 1: <k>.<s>.FW_EX.txt ----
	configEx := ""
	if radiusYes {
		configEx += fmt.Sprintf(`config vpn ipsec phase2-interface
edit VPN_ADM_%s-%s_2nd
set phase1name "VPN_ADM_RO"
set proposal aes256-sha512
set dhgrp 18
set src-subnet 10.12.34.0 255.255.255.0
set dst-subnet %s 255.255.255.255
next
end

config vpn ipsec phase2-interface
edit VPN_ADM_%s-%s_1st
set phase1name "VPN_ADM_RO"
set proposal aes256-sha512
set dhgrp 18
set src-subnet 10.12.34.0 255.255.255.0
set dst-subnet %s 255.255.255.255
next
end
`, k, s, rip, k, s, rip1)
	}
	configEx += fmt.Sprintf(`
config user local
edit %s
set type password
set passwd %s
next
end

##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_RO HINZUGEFÜGT WERDEN
##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_RO HINZUGEFÜGT WERDEN
`, ike, pskRo)

	// ---- File 2: <k>.<s>.FW_rzp.txt ----
	configHci := "MGT DISABLED IN XLSX - NO HCI CONFIG"
	if radiusYes {
		configHci = fmt.Sprintf(`config vpn ipsec phase2-interface
edit VPN_ADM_%s-%s_2nd
set phase1name "VPN_ADM-RZP"
set proposal aes256-sha512
set dhgrp 21
set src-subnet 10.250.11.192 255.255.255.192
set dst-subnet %s 255.255.255.255
next
end

config vpn ipsec phase2-interface
edit VPN_ADM_%s-%s_1st
set phase1name "VPN_ADM-RZP"
set proposal aes256-sha512
set dhgrp 21
set src-subnet 10.250.11.192 255.255.255.192
set dst-subnet %s 255.255.255.255
next
end

config user local
edit %s
set type password
set passwd %s
next
end

##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_HC HINZUGEFÜGT WERDEN
##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_HC HINZUGEFÜGT WERDEN
`, k, s, rip, k, s, rip1, ike, pskHci)
	}

	// ---- File 3: <k>.<s>.FW_kunde.txt ----
	configcu := fmt.Sprintf(`config system global
set remoteauthtimeout 180
end

config vpn ipsec phase1-interface
edit "VPN_EX-ADMRO"
set interface %s
set ike-version 2
set peertype any
set net-device disable
set proposal aes256-sha512
set localid %s
set dpd on-idle
set dhgrp 18
set remote-gw %s
set psksecret %s
set dpd-retrycount 10
set dpd-retryinterval 900
next
end
`, wan, ike, gwRO, pskRo)

	if radiusYes {
		configcu += fmt.Sprintf(`
config vpn ipsec phase2-interface
edit "VPN_EX-ADMRO-2nd"
set phase1name "VPN_EX-ADMRO"
set proposal aes256-sha512
set dhgrp 18
set keepalive enable
set auto-negotiate enable
set src-subnet %s 255.255.255.255
set dst-subnet 10.12.34.0 255.255.255.0
next
end

config vpn ipsec phase2-interface
edit "VPN_EX-ADMRO-1st"
set phase1name "VPN_EX-ADMRO"
set proposal aes256-sha512
set dhgrp 18
set keepalive enable
set auto-negotiate enable
set src-subnet %s 255.255.255.255
set dst-subnet 10.12.34.0 255.255.255.0
next
end
`, rip, rip1)
	}

	configcu += fmt.Sprintf(`
config system interface
edit "LB-EXADM"
set vdom "root"
set ip %s 255.255.255.255
set allowaccess ping https ssh http
set role dmz
set type loopback
set secondary-IP enable
config secondaryip
edit 1
set ip %s 255.255.255.255
next
end
next
end

config firewall service custom
edit "TCP9443"
set tcp-portrange 9443
next
end
config firewall service custom
edit "TCP9422"
set tcp-portrange 9422
next
end
config firewall service custom
edit "RADIUS"
set category "Authentication"
set udp-portrange 1812 1813
next
end
config firewall service custom
edit "PING"
set category "Network Services"
set protocol ICMP
set icmptype 8
unset icmptype
next
end
`, rip, rip1)

	if radiusYes {
		configcu += `
config firewall policy
edit 0
set name "EX-adm https/ssh ro"
set srcintf "VPN_EX-ADMRO"
set dstintf "LB-EXADM"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "TCP9443" "TCP9422" "PING"
next
end

config firewall policy
edit 0
set name "EX-adm radius ro"
set srcintf "LB-EXADM"
set dstintf "VPN_EX-ADMRO"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "RADIUS"
next
end

config router static
edit 0
set dst 10.12.34.0 255.255.255.0
set device "VPN_EX-ADMRO"
next
end
`
	}

	sep := strings.Repeat("#", 92)
	configcu += "\n" + sep + "\n" +
		strings.Repeat("#", 32) + "COPYBREAK" + strings.Repeat("#", 51) + "\n" +
		sep + "\n"

	if radiusYes {
		configcu += fmt.Sprintf(`
config system global
set remoteauthtimeout 180
end

config vpn ipsec phase1-interface
edit "VPN_EX-ADMHCI"
set interface %s
set ike-version 2
set peertype any
set net-device disable
set proposal aes256-sha512
set localid %s
set dpd on-idle
set dhgrp 21
set remote-gw %s
set psksecret %s
set dpd-retrycount 10
set dpd-retryinterval 900
next
end

config vpn ipsec phase2-interface
edit "VPN_EX-ADMHCI-2nd"
set phase1name "VPN_EX-ADMHCI"
set proposal aes256-sha512
set dhgrp 21
set keepalive enable
set auto-negotiate enable
set src-subnet %s 255.255.255.255
set dst-subnet 10.250.11.192 255.255.255.192
next
end

config vpn ipsec phase2-interface
edit "VPN_EX-ADMHCI-1st"
set phase1name "VPN_EX-ADMHCI"
set proposal aes256-sha512
set dhgrp 21
set keepalive enable
set auto-negotiate enable
set src-subnet %s 255.255.255.255
set dst-subnet 10.250.11.192 255.255.255.192
next
end

config system interface
edit "LB-EXADM"
set vdom "root"
set ip %s 255.255.255.255
set allowaccess ping https ssh http
set role dmz
set type loopback
set secondary-IP enable
config secondaryip
edit 1
set ip %s 255.255.255.255
next
end
next
end

config firewall service custom
edit "TCP9443"
set tcp-portrange 9443
next
end
config firewall service custom
edit "TCP9422"
set tcp-portrange 9422
next
end
config firewall service custom
edit "RADIUS"
set category "Authentication"
set udp-portrange 1812 1813
next
end
config firewall service custom
edit "PING"
set category "Network Services"
set protocol ICMP
set icmptype 8
unset icmptype
next
end

config firewall policy
edit 0
set name "EX-adm https/ssh hc"
set srcintf "VPN_EX-ADMHCI"
set dstintf "LB-EXADM"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "TCP9443" "TCP9422" "PING"
next
end

config firewall policy
edit 0
set name "EX-adm radius hc"
set srcintf "LB-EXADM"
set dstintf "VPN_EX-ADMHCI"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "RADIUS"
next
end

config router static
edit 0
set dst 10.250.11.192 255.255.255.192
set device "VPN_EX-ADMHCI"
next
end
`, wan, ike, gwHCI, pskHci, rip, rip1, rip, rip1)
	}

	configcu += "\n" + sep + "\n" +
		strings.Repeat("#", 32) + "COPYBREAK-2" + strings.Repeat("#", 49) + "\n" +
		sep + "\n"

	if radiusYes {
		configcu += fmt.Sprintf(`
config system accprofile
edit "Readonly"
set secfabgrp read
set ftviewgrp read
set authgrp read
set sysgrp read
set netgrp read
set loggrp read
set fwgrp read
set vpngrp read
set utmgrp read
set wifi read
next
end

config user radius
edit "RAD-EXADM-1stlvl_1"
set server "10.250.11.201"
set secret %s
set nas-ip %s
set auth-type ms_chap_v2
set source-ip "%s"
next
end

config user radius
edit "RAD-EXADM-1stlvl_2"
set server "10.12.34.201"
set secret %s
set nas-ip %s
set auth-type ms_chap_v2
set source-ip "%s"
next
end

config user group
edit "sg-ADM_FGT_Auth_1st-Level"
set member "RAD-EXADM-1stlvl_1" "RAD-EXADM-1stlvl_2"
next
end

config system admin
edit "sg-ADM_FGT_Auth_1st-Level"
set vdom "root"
set trusthost1 10.12.34.0 255.255.255.0
set trusthost2 10.250.11.192 255.255.255.192
set remote-auth enable
set accprofile "Readonly"
set wildcard enable
set remote-group "sg-ADM_FGT_Auth_1st-Level"
next
end

config user radius
edit "RAD-EXADM-2ndlvl_1"
set server "10.250.11.201"
set secret %s
set nas-ip %s
set auth-type ms_chap_v2
set source-ip "%s"
next
end

config user radius
edit "RAD-EXADM-2ndlvl_2"
set server "10.12.34.201"
set secret %s
set nas-ip %s
set auth-type ms_chap_v2
set source-ip "%s"
next
end

config user group
edit "sg-ADM_FGT_Auth_2nd-Level"
set member "RAD-EXADM-2ndlvl_1" "RAD-EXADM-2ndlvl_2"
next
end

config system admin
edit "sg-ADM_FGT_Auth_2nd-Level"
set vdom "root"
set trusthost1 10.12.34.0 255.255.255.0
set trusthost2 10.250.11.192 255.255.255.192
set remote-auth enable
set accprofile "super_admin"
set wildcard enable
set remote-group "sg-ADM_FGT_Auth_2nd-Level"
next
end
`, radiushci1, rip1, rip1, radiusro1, rip1, rip1, radiushci2, rip, rip, radiusro2, rip, rip)
	}

	// ---- File 4: <k>.<s>.radiuscfg.txt ----
	radiuscfg := "RADIUS CONFIG DISABLED"
	if radiusYes {
		radiuscfg = fmt.Sprintf(`$CustomCred = Get-Credential

#~~~~~~~~~~~~~~~~~~~~~~~~~~#
#RUN ON ADM-NPS02 RO
Invoke-Command -ComputerName ADM-NPS02.adm.eworx.at -ScriptBlock {
New-NpsRadiusClient -Address "%s" -Name "%s-%s_2nd" -SharedSecret "%s" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "%s" -Name "%s-%s_2nd" -SharedSecret "%s" -AuthAttributeRequired $False
New-NpsRadiusClient -Address "%s" -Name "%s-%s_1st" -SharedSecret "%s" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "%s" -Name "%s-%s_1st" -SharedSecret "%s" -AuthAttributeRequired $False
Restart-Service IAS
} -Credential $CustomCred

#~~~~~~~~~~~~~~~~~~~~~~~~~~#
#RUN ON ADM-NPS01 HCI
Invoke-Command -ComputerName ADM-NPS01.adm.eworx.at -ScriptBlock {
New-NpsRadiusClient -Address "%s" -Name "%s-%s_2nd" -SharedSecret "%s" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "%s" -Name "%s-%s_2nd" -SharedSecret "%s" -AuthAttributeRequired $False
New-NpsRadiusClient -Address "%s" -Name "%s-%s_1st" -SharedSecret "%s" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "%s" -Name "%s-%s_1st" -SharedSecret "%s" -AuthAttributeRequired $False
Restart-Service IAS
} -Credential $CustomCred

#~~~~~~~~~~~~~~~~~~~~~~~~~~#
#RUN ON ANY DC
Invoke-Command -ComputerName ADM-DC01.adm.eworx.at -ScriptBlock {
Add-DnsServerResourceRecordA -Name "%s" -ZoneName "adm.eworx.at" -IPv4Address "%s"
} -Credential $CustomCred
Invoke-Command -ComputerName ADM-DC02.adm.eworx.at -ScriptBlock {
Add-DnsServerResourceRecordA -Name "%s" -ZoneName "adm.eworx.at" -IPv4Address "%s"
} -Credential $CustomCred

#~~~~~~~~~ACCESS-URLs~~~~~~#
https://%s:9443
https://%s:9443
`,
			rip, k, s, radiusro2,
			rip, k, s, radiusro2,
			rip1, k, s, radiusro1,
			rip1, k, s, radiusro1,
			rip, k, s, radiushci2,
			rip, k, s, radiushci2,
			rip1, k, s, radiushci1,
			rip1, k, s, radiushci1,
			dnsFull, rip,
			dnsFull, rip,
			rip, dnsFull)
	}

	// ---- File 5: <k>.<s>.finalconfig.txt ----
	configfinal := "NO RADIUS CONFIG - NO FINAL CONFIG"
	if radiusYes {
		configfinal = `ADMIN USER KONTROLLIEREN / TRUSTED HOSTS ANPASSEN
Es darf keine Admins ohne Trusted Hosts geben, externe IP darf nur unser Jumphost 193.104.82.251/32 erlaubt werden

VORHER ADM LOGIN TESTEN

config system admin
edit "admin"
set trusthost1 193.104.82.251 255.255.255.255
next
end
`
	}

	return []configFile{
		{fmt.Sprintf("%s.%s.FW_EX.txt", k, s), configEx},
		{fmt.Sprintf("%s.%s.FW_rzp.txt", k, s), configHci},
		{fmt.Sprintf("%s.%s.FW_kunde.txt", k, s), configcu},
		{fmt.Sprintf("%s.%s.radiuscfg.txt", k, s), radiuscfg},
		{fmt.Sprintf("%s.%s.finalconfig.txt", k, s), configfinal},
	}
}

// addFile writes one stored (uncompressed) entry, matching Python's default
// ZIP_STORED writestr.
func addFile(zw *zip.Writer, name, content string) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, content)
	return err
}
