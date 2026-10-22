package fgtadmvpnconf

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/netutil"
)

// Every value below is pasted unquoted into FortiOS CLI scripts, the NPS
// PowerShell script, DNS names and the Graylog DSV feed. Restricting them to a
// token character set means no value can terminate a command, open a quote or
// start a new CLI line.
var (
	// reCLIName covers customer, site and firewall names (used in object
	// names, DNS labels and file names).
	reCLIName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)
	// reCLIInterface covers FortiOS interface names.
	reCLIInterface = regexp.MustCompile(`^[A-Za-z0-9._-]{1,35}$`)
	// reCLISecret covers PSKs: printable ASCII without whitespace, quotes or
	// backslashes. Empty is tolerated for legacy rows (it cannot inject).
	reCLISecret = regexp.MustCompile(`^[!#-&(-\[\]-~]{0,100}$`)
)

// validateVpnConfigFields rejects any value that could break out of the
// generated FortiOS CLI, PowerShell or DSV output.
func validateVpnConfigFields(c *VpnConfig) error {
	for _, field := range []struct{ name, value string }{
		{"Kundenname", c.Kundenname},
		{"Standort", c.Standort},
		{"Firewallname", c.Firewallname},
	} {
		if !reCLIName.MatchString(field.value) {
			return fmt.Errorf("%s may only contain letters, digits, '.', '_' and '-' (1-63 characters)", field.name)
		}
	}
	for _, field := range []struct{ name, value string }{
		{"WAN interface", c.WanInterface},
		{"LAN interface", c.LanInterface},
	} {
		if !reCLIInterface.MatchString(field.value) {
			return fmt.Errorf("%s may only contain letters, digits, '.', '_' and '-' (1-35 characters)", field.name)
		}
	}
	for _, field := range []struct{ name, value string }{
		{"IPsec PSK RO", c.IpsecPskRo},
		{"IPsec PSK HCI", c.IpsecPskHci},
	} {
		if !reCLISecret.MatchString(field.value) {
			return fmt.Errorf("%s must be at most 100 printable ASCII characters without spaces, quotes or backslashes", field.name)
		}
	}
	for _, field := range []struct{ name, value string }{
		{"Remote IP", c.RemoteipFull},
		{"Remote IP (1st)", c.RemoteipFull1st},
	} {
		if net.ParseIP(field.value).To4() == nil {
			return fmt.Errorf("%s must be a valid IPv4 address", field.name)
		}
	}
	for _, host := range splitHostnames(c.ClusterHostnames) {
		if !reCLIName.MatchString(host) {
			return errors.New("cluster hostnames may only contain letters, digits, '.', '_' and '-'")
		}
	}
	return nil
}

// dsvAuthorized enforces the optional ADM_VPN_DSV_TOKEN and
// ADM_VPN_DSV_ALLOWED_CIDRS restrictions on the Graylog DSV feed. With neither
// configured the feed stays public for backwards compatibility (a startup
// warning is logged).
func (e *Extension) dsvAuthorized(r *http.Request) bool {
	if e.cfg.AdmVpnDSVAllowedCIDRs != "" {
		allowed, err := netutil.ParseCIDRList(e.cfg.AdmVpnDSVAllowedCIDRs)
		if err != nil || !netutil.ContainsAddr(allowed, netutil.ClientIP(r, e.cfg.TrustProxyHeaders)) {
			return false
		}
	}
	if e.cfg.AdmVpnDSVToken != "" {
		provided := r.URL.Query().Get("token")
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			provided = strings.TrimPrefix(auth, "Bearer ")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(e.cfg.AdmVpnDSVToken)) != 1 {
			return false
		}
	}
	return true
}

// csvSafeCell neutralizes spreadsheet formula prefixes in exported cells.
func csvSafeCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// csvUnescapeCell reverses csvSafeCell on import so an export round-trips.
func csvUnescapeCell(value string) string {
	if len(value) > 1 && value[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(value[1])) {
		return value[1:]
	}
	return value
}
