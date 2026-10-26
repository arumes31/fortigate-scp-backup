// Package netutil holds small HTTP networking helpers shared across layers.
package netutil

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

// DefaultTrustedProxies is the peer allowlist used when TRUSTED_PROXIES is not
// configured: loopback plus the private ranges a same-host reverse proxy or a
// container bridge network presents as the connection source.
const DefaultTrustedProxies = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"

var trustedProxies atomic.Pointer[[]netip.Prefix]

func init() {
	prefixes, err := ParseCIDRList(DefaultTrustedProxies)
	if err != nil {
		panic("netutil: invalid default trusted proxies: " + err.Error())
	}
	trustedProxies.Store(&prefixes)
}

// ParseCIDRList parses a comma-separated list of CIDR prefixes or bare IP
// addresses (treated as single-host prefixes).
func ParseCIDRList(value string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", item, err)
			}
			out = append(out, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", item, err)
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
	}
	return out, nil
}

// SetTrustedProxies replaces the peer allowlist whose X-Forwarded-For header
// is honoured. It is called once at startup from configuration.
func SetTrustedProxies(prefixes []netip.Prefix) {
	cp := append([]netip.Prefix(nil), prefixes...)
	trustedProxies.Store(&cp)
}

// ContainsAddr reports whether host (an IP address string) falls inside any of
// the given prefixes.
func ContainsAddr(prefixes []netip.Prefix, host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// PeerIP returns the address of the directly connected peer (RemoteAddr
// without the port), ignoring every forwarding header.
func PeerIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ClientIP returns the best-guess client address. X-Forwarded-For is honoured
// only when trustProxy is set (the app is behind a trusted reverse proxy) and
// the connection comes from an address in the trusted-proxy allowlist;
// otherwise the header is ignored so a direct client cannot spoof (or freeze)
// its address by sending a fixed header. Shared by the login rate limiter and
// session IP pinning so the two stay aligned.
func ClientIP(r *http.Request, trustProxy bool) string {
	peer := PeerIP(r)
	if trustProxy && ContainsAddr(*trustedProxies.Load(), peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// XFF is appended left-to-right by each hop, so the leftmost
			// entries are client-supplied and spoofable. With a single trusted
			// reverse proxy the rightmost entry is the peer address that proxy
			// actually observed, so use it as the source IP.
			if i := strings.LastIndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[i+1:])
			}
			return strings.TrimSpace(xff)
		}
	}
	return peer
}
