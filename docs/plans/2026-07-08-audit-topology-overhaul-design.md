# Audit & Topology Overhaul — Design

Date: 2026-07-08
Branch: v3.0.6

## Goals

1. Audit page loads instantly; results computed async and cached.
2. Standalone interactive topology page (D3 tree) with device faceplates.
3. Fix upgrade-path logic (no more `7.6.7 -> 7.6.0` downgrades).
4. Findings show the exact config block (matched line ±3 lines) with highlight.
5. Expand audit to a curated ~30-check set from Fortinet hardening docs and
   community best practices; refresh CVE data through 2025/2026.
6. Fix logic errors found along the way; add tests.

## 1. Audit performance

**Cache table** in the insights SQLite DB:

```sql
CREATE TABLE IF NOT EXISTS audit_cache (
  fw_id INTEGER PRIMARY KEY,
  backup_filename TEXT NOT NULL,
  computed_at TEXT NOT NULL,
  results_json TEXT NOT NULL
);
```

`results_json` holds the full per-firewall result: raw findings (with line
context), model/version, interfaces, routes, policies, switches, upgrade
path, compliance scores.

**Compute pipeline**: single `computeAudit(fwID, filename, plain)` used by:

1. **Backup hook** — after a successful backup the engine audits in a
   goroutine and stores the result (pre-warmed cache).
2. **Lazy fallback** — `GET /audit/results/{fwID}` returns cache; on miss
   computes, stores, returns.
3. **Manual recompute** — per-firewall button busts the cache entry.

Exemptions and custom-rule filtering are applied at read time on cached raw
findings, so toggling an exemption never recomputes. Custom-rule CRUD busts
all cache entries (rules affect raw findings).

**Page flow**: `handleAudit` renders only the shell (skeleton rows, custom
rules/exemptions panels). JS fetches `/audit/results/{fwID}` per firewall
(max ~4 concurrent), fills rows as they arrive, updates summary counters and
the version chart incrementally. Pending rows show a spinner; failures show
an error state with retry.

**Fix**: `initInsightsDB` currently opens SQLite on every request — open once
at server start and reuse the handle.

## 2. Topology page

- New route `GET /topology` + nav entry, template `topology.html`.
- Data endpoint `GET /topology/data/{fwID}` served from the audit cache.
- Topology section removed from the audit page.
- Vendored `d3.v7.min.js` in `static/` (self-contained binary, no CDN).

**Tree** (left-to-right, collapsible):

```
Internet cloud → FortiGate → per-interface branches
                              ├─ FortiSwitch (fortilink) → ports/VLANs
                              ├─ VLANs (subinterfaces)
                              └─ LAN segments (interface + subnet)
```

WAN interfaces (role wan / default-route) attach to the Internet cloud.
Interactions: d3.zoom pan/zoom, collapsible branches, hover tooltips
(IP, subnet, status, VLAN ID, policy count), firewall selector, edge labels,
per-type SVG icons matching the terminal theme.

**Faceplates**: clicking a firewall/switch slides in a panel with a generic
auto-generated schematic front panel — one port cell per interface/switch
port, colored by state/VLAN role, labels, hover details. Generated from the
parsed config; works for every model.

## 3. Checks, upgrade paths, config context

**Block scanner**: parser tracks `config … / edit … / next / end` structure
with 1-based line numbers. Each finding gets `CheckID`, `Line`, and
`Context` (matched line ±3 lines). Checks move from bare `strings.Contains`
to block-scoped matching (kills substring false positives). UI: findings
expandable to a mini code view, matched line highlighted, gutter line
numbers.

**Upgrade path**: data table of FortiOS trains (6.0 → 6.2 → 6.4 → 7.0 →
7.2 → 7.4 → 7.6 → 8.0) with latest patch per train, following Fortinet's
official upgrade-path logic. Already-current versions show "up to date" or
only their train's newer patch. Never a downgrade.

**Curated checks (~30)**, grouped: admin access (trusted hosts, WAN mgmt,
default GUI ports, lockout, idle timeout, maintainer), protocol hygiene
(weak ciphers, TLS < 1.2, telnet, HTTP no-redirect), SSL-VPN exposure,
services (SNMP v1/v2c public, NTP, DNS, USB auto-install), logging
(FortiAnalyzer/syslog absent, no login audit), policy hygiene
(all/all/all accept, no-log policies). Each: stable `check_id`, severity,
German text (existing style), CLI remediation, line context.

**CVEs** updated through 2025/2026 (CVE-2024-21762, CVE-2024-47575,
CVE-2024-55591, CVE-2025-24472, …), table-driven.

## 4. Fixes, tests, delivery

Fixes: upgrade-path downgrade; exemptions match on stable `check_id` +
firewall instead of exact text (with migration); shared insights DB handle;
compliance scores consume structured findings instead of duplicate
`strings.Contains` logic.

Tests: block-scanner units against `example.conf`; table-driven
vulnerable/clean pairs per check; upgrade-path cases (7.6.7, 7.4.0, 6.0.x,
unknown); cache hit/miss/bust; handler tests for shell, results JSON, and
topology JSON.

Verification: build, seed with `example.conf`, drive audit + topology pages
in a browser, fix what breaks.

Files: split `audit.go` into `audit.go` / `audit_checks.go` /
`audit_cache.go` / `topology.go`; new `topology.html`; vendored
`d3.v7.min.js`; migrations; README update.
