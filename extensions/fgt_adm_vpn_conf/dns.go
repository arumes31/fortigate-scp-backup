package fgtadmvpnconf

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// DNS check statuses persisted in vpn_config.last_dns_status. The check
// verifies that dns_name_full actually resolves to remoteip_full, as seen by
// this container's resolver.
const (
	dnsStatusOK         = "ok"         // some returned record equals remoteip_full
	dnsStatusMismatch   = "mismatch"   // resolves, but no record matches
	dnsStatusUnresolved = "unresolved" // NXDOMAIN / no such host
	dnsStatusError      = "error"      // resolver infrastructure failure (timeout, SERVFAIL)
	dnsStatusUnknown    = "unknown"    // not yet checked, or nothing to validate
)

// dnsLookupTimeout bounds one resolution, matching the Graylog HTTP timeout.
const dnsLookupTimeout = 5 * time.Second

// Re-check cadence, per current status: a record that resolved correctly is
// retested at most once per 24 h; anything not confirmed OK (wrong IP, no
// record, resolver error, never checked) is retested every 10 minutes.
const (
	dnsRecheckHealthy   = 24 * time.Hour
	dnsRecheckUnhealthy = 10 * time.Minute

	// dnsWorkerInterval is how often the worker scans for due devices; it bounds
	// how far past its nominal cadence a check can slip.
	dnsWorkerInterval = time.Minute
)

// dnsResolvedMaxLen caps the stored resolved-address list to its VARCHAR(255)
// column; the value is display-only (tooltip / dashboard detail).
const dnsResolvedMaxLen = 255

// dnsStatusUnhealthy reports whether a DNS status is actionable — the states
// ListDNSIssues surfaces on the dashboard. Resolver errors are deliberately
// excluded: a brief resolver outage would otherwise flag the whole fleet.
func dnsStatusUnhealthy(status string) bool {
	return status == dnsStatusMismatch || status == dnsStatusUnresolved
}

// computeDNSStatus resolves c.DnsNameFull and compares the result against
// c.RemoteipFull. It returns the status plus the comma-joined addresses the
// name resolved to (normalised, "" when resolution failed). Rows with no DNS
// name or no valid expected IP have nothing to validate and stay "unknown".
func (e *Extension) computeDNSStatus(c *VpnConfig) (status, resolved string) {
	name := strings.TrimSpace(c.DnsNameFull)
	expected := net.ParseIP(strings.TrimSpace(c.RemoteipFull))
	if name == "" || expected == nil {
		return dnsStatusUnknown, ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	addrs, err := e.lookupHost(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return dnsStatusUnresolved, ""
		}
		return dnsStatusError, ""
	}

	// Normalise every returned address; any match against the expected IP is a
	// pass (multi-record answers, or A+AAAA mixes, are fine).
	want := expected.String()
	match := false
	var list []string
	for _, a := range addrs {
		ip := net.ParseIP(strings.TrimSpace(a))
		if ip == nil {
			continue
		}
		list = append(list, ip.String())
		if ip.String() == want {
			match = true
		}
	}
	resolved = strings.Join(list, ", ")
	if len(resolved) > dnsResolvedMaxLen {
		resolved = resolved[:dnsResolvedMaxLen]
	}
	if match {
		return dnsStatusOK, resolved
	}
	if len(list) == 0 {
		// Lookup "succeeded" but yielded nothing usable — treat as unresolved.
		return dnsStatusUnresolved, ""
	}
	return dnsStatusMismatch, resolved
}

// dnsCheckDue reports whether a device's DNS record is due for a re-check:
// never-checked rows immediately, OK rows after dnsRecheckHealthy, everything
// else after dnsRecheckUnhealthy.
func dnsCheckDue(c *VpnConfig, now time.Time) bool {
	if c.LastDnsCheck == nil {
		return true
	}
	interval := dnsRecheckUnhealthy
	if c.LastDnsStatus == dnsStatusOK {
		interval = dnsRecheckHealthy
	}
	return now.Sub(*c.LastDnsCheck) >= interval
}

// dnsSweep runs one pass over all devices and re-checks those due. Devices
// with nothing to validate (no DNS name / no valid expected IP) only get their
// stale status reset to unknown — no lookup, no timestamp churn.
func (e *Extension) dnsSweep() error {
	configs, err := e.allConfigs()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, c := range configs {
		if strings.TrimSpace(c.DnsNameFull) == "" || net.ParseIP(strings.TrimSpace(c.RemoteipFull)) == nil {
			if c.LastDnsStatus != dnsStatusUnknown {
				if err := e.updateDNSStatus(c.ID, now, dnsStatusUnknown, ""); err != nil {
					return err
				}
			}
			continue
		}
		if !dnsCheckDue(c, now) {
			continue
		}
		status, resolved := e.computeDNSStatus(c)
		if status != c.LastDnsStatus && (dnsStatusUnhealthy(status) || dnsStatusUnhealthy(c.LastDnsStatus)) {
			e.logger.Info("dns status transition", "firewall", c.Firewallname,
				"dns_name", c.DnsNameFull, "from", c.LastDnsStatus, "to", status, "resolved", resolved)
		}
		if err := e.updateDNSStatus(c.ID, time.Now().UTC(), status, resolved); err != nil {
			return err
		}
	}
	return nil
}

// dnsWorker runs the DNS record check on its own cadence, decoupled from the
// Graylog sweep: healthy records back off to one check per day, failing ones
// keep being retested every 10 minutes. It starts after a short delay so the
// app is fully up, and never returns.
func (e *Extension) dnsWorker() {
	time.Sleep(10 * time.Second)
	// Ensure schema is migrated before querying the newer columns.
	if err := e.ensureMigrations(); err != nil {
		e.logger.Error("dns worker: migrations failed", "err", err)
	}
	for {
		if err := e.dnsSweep(); err != nil {
			e.logger.Error("Error in dns_status_worker loop", "err", err)
		}
		time.Sleep(dnsWorkerInterval)
	}
}
