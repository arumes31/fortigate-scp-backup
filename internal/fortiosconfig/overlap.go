package fortiosconfig

import (
	"net/netip"
	"strings"
)

type addressInterval struct{ first, last netip.Addr }

// listenerAddresses resolves only explicit addresses/ranges and a static
// interface address. FQDN, missing, dynamic and unrecognized formats remain
// unknown; two unknown listeners must not be assumed disjoint.
func (inv *inventory) listenerAddresses(vip *node) (addressInterval, bool) {
	value := vip.get("extip")
	if value == "0.0.0.0" {
		iface := inv.interfaces[vip.get("extintf")]
		if iface == nil || iface.value("mode", "static") != "static" || len(iface.values["ip"]) == 0 {
			return addressInterval{}, false
		}
		value = iface.values["ip"][0]
		if value == "0.0.0.0" {
			return addressInterval{}, false
		}
	}
	parts := strings.Fields(strings.ReplaceAll(value, "-", " "))
	if len(parts) < 1 || len(parts) > 2 {
		return addressInterval{}, false
	}
	first, err := netip.ParseAddr(parts[0])
	if err != nil {
		return addressInterval{}, false
	}
	last := first
	if len(parts) == 2 {
		last, err = netip.ParseAddr(parts[1])
		if err != nil {
			return addressInterval{}, false
		}
	}
	if first.Is4() != last.Is4() || first.Compare(last) > 0 {
		return addressInterval{}, false
	}
	return addressInterval{first, last}, true
}

func (inv *inventory) mayOverlapAddresses(a, b *node) bool {
	left, lKnown := inv.listenerAddresses(a)
	right, rKnown := inv.listenerAddresses(b)
	if !lKnown || !rKnown {
		return true
	}
	if left.first.Is4() != right.first.Is4() {
		return false
	}
	return left.first.Compare(right.last) <= 0 && right.first.Compare(left.last) <= 0
}
