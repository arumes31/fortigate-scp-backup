# Firewall reports, profiles, and Graylog observations

FortiSafe generates a current report set for each firewall after a successful configuration backup. The **Reports / Berichte** tab is available to authenticated administrators and operators. The latest successful set is retained; there is no report history.

| Report | Source and contents |
| --- | --- |
| **Port Forwarding & Exposure** | VIP and virtual-server overview followed by per-VIP details, mapped backends, geographic restrictions, evidence, and a five-column policy table in configuration order. Deny actions are red and Allow/Accept actions are green; the action text remains visible. |
| **Technical Configuration** | Allowlisted configuration inventory, findings, recommendations, source references, selected count charts, and analysis coverage. |
| **Traffic & Security Observations** | Received FortiGate traffic, UTM, and VPN observations from the configured Graylog source, with collection time, field coverage, grouping limits, and dataset-specific status. When Graylog is absent or disabled, the report explains that state. |

Each report has **PDF, HTML, CSV, JSON, and XML** downloads. Non-PDF downloads are produced from the saved assessment and the profile captured with that set. Opening an export does not fetch new logs, reanalyze another backup, or silently adopt newer settings.

**Inspect findings** opens the selected forwarding inventory, technical evidence, captured profile and filters, and a compact Graylog coverage overview. **Report settings** edits the profile for one firewall. **Report catalog** shows implemented datasets and the dependencies or missing implementations of other report families. **Generation schedule** lists the next scheduled run per firewall.

## Configuration and first use

| Variable | Default | Meaning |
| --- | --- | --- |
| `EXT_FGT_REPORTS` | `true` | Mount the extension and run automatic reporting. |
| `REPORTS_LANGUAGE` | `en` | Default report language, `en` or `de`, for firewalls without a saved profile. A saved profile has its own language. |
| `GRAYLOG_URL` | Unset | Existing shared Graylog base URL. Reporting uses its absolute-search and aggregation API endpoints. |
| `GRAYLOG_TOKEN` / `GRAYLOG_TOKEN_FILE` | Unset | Existing shared Graylog access token. A direct value takes precedence over the file fallback. |
| `ALLOW_INSECURE_HTTP_INTEGRATIONS` | `false` | Existing integration policy: HTTPS is required unless plain HTTP is explicitly allowed. |

No new Graylog environment variables, separate reporting service, LLM, browser-based PDF engine, or firewall login are required. The report collector reuses the existing Graylog connection and source mapping. Configuration-only reporting works without Graylog.

After enabling reporting:

1. Open **Reports** after at least one successful backup. Startup also backfills the newest retained backup for existing firewalls.
2. Open a firewall's **Report settings** to choose language, content, filters, charts, branding, and an optional schedule.
3. For log observations, ensure the Graylog source is correctly attributed to that firewall and extracts the canonical FortiGate fields described below. The catalog's “Graylog configured” badge confirms configuration exists; it does not prove that a query succeeded or that every field is present.
4. Save the profile. FortiSafe queues a replacement set, keeping the previous successful set available until publication succeeds.
5. Inspect the report's source backup, captured profile, Graylog window, and dataset status before interpreting its contents.

The browser follows the signed-in user's language. Report language belongs to the captured profile, so everyone downloading a particular set receives the same report language. Technical CLI values and some source-specific explanations retain their canonical English form.

## Profiles, branding, and scope

A firewall has one current, encrypted profile. It controls:

- Profile name, company, customer display name, subtitle, introduction, and footer.
- Report language, portrait/landscape A4 orientation, accent color, optional cover, table of contents, and logo.
- Findings, technical inventory, and policy-trace visibility.
- Selected and ordered inventory sections and count charts. Arrow controls change section/chart order; an exported profile retains that order.
- VDOM, publication type, configured outcome, and finding-priority filters.
- Whether to collect Graylog observations, their rolling lookback window, and an additional generation schedule.

Empty filter lists mean all values. Empty section or chart selections mean those sections or charts are omitted. Filtering happens **after** the complete configuration analysis: selecting an exposure does not remove its earlier policies or recompute a more favorable outcome from a reduced rule set. Appliance-wide context and analysis limitations remain visible. The report detail shows selected versus original counts and the profile captured at generation time.

VDOM filters also constrain Graylog queries through the canonical `vd` field. Publication-type, policy-outcome, and finding-priority filters affect configuration analysis only. The backup timestamp and the Graylog observation window describe different sources and are displayed separately.

Company and customer labels are explicit operator input used for report branding and text placeholders. All remaining reports retain their technical detail; branding does not reduce the exported data scope.

### Logos and text placeholders

Logos must be complete PNG or JPEG images, at most **256 KiB** and **1,024 × 1,024 pixels**. The profile contains the image itself; reports do not retrieve an external logo URL. Exported profile definitions include the logo.

Subtitle, introduction, and footer support these exact plain-text placeholders:

| Placeholder | Value |
| --- | --- |
| `{{firewall}}` | Firewall display name. |
| `{{firewall_id}}` | FortiSafe firewall ID. |
| `{{backup_id}}` | Source backup ID. |
| `{{backup_at}}` | Source backup time. |
| `{{generated_at}}` | Report generation time. |
| `{{publication_count}}` | Selected configured publication count. |
| `{{finding_count}}` | Selected finding count. |
| `{{vdom_count}}` | Selected VDOM count. |
| `{{organization}}` | Explicit company label. |
| `{{customer}}` | Explicit customer label. |
| `{{report_title}}` | The selected report's title. |

Use no whitespace inside the braces. Placeholders do not execute expressions, HTML, scripts, or templates. Expanded text remains bounded to 240 subtitle, 4,000 introduction, and 300 footer Unicode characters.

### Export, import, copy, and reset

**Download profile** exports the saved JSON definition, including filters, schedule, and any logo. **Import profile** replaces this firewall's profile with a validated FortiSafe profile document. Start from an exported document when editing JSON; the format and schema are checked, and unknown fields or executable query definitions are not accepted. Profile documents are bounded to 512 KiB.

**Copy another profile** copies the saved settings from another registered firewall with a successful backup. **Restore default profile** removes the saved customization and returns to the application defaults, including automatic backup-triggered generation without an additional calendar schedule.

The editor, import, copy, and reset forms carry a revision value. A conflicting concurrent edit is rejected instead of silently overwriting newer settings. Reload the current profile before applying the intended change. Profile changes invalidate in-flight work using older settings and queue a replacement set.

## Automatic lifecycle and scheduling

A successful backup emits a committed-backup event after its database commit. The existing status/SSE hook is preserved. An optional indexed metadata lookup is bounded to two seconds and cannot turn a successful backup into a failure. The reporting callback only wakes a bounded background worker.

At startup and every minute, reconciliation selects the newest committed backup per registered firewall. This backfills existing installations and recovers missed notifications. A job pins the firewall ID, backup ID, timestamp, checksum, and profile generation. It reads that exact encrypted backup through ownership, path-confinement, size, and integrity checks. It never substitutes another backup if the pinned source is missing.

One worker creates the assessment and **all three PDFs**. The captured profile, assessment, observation metadata, and PDF set are published atomically. A newer backup or profile supersedes older in-flight work. The latest-report row is replaced; no report-history rows, artifact directories, or PDF caches are created. A successful backup with unchanged configuration still replaces the set so its provenance and observation window remain current.

The former **Customer Review & Roadmap** report has been removed. Upgrading securely removes its stored PDF column, and its former download URLs return 404. The supported report snapshots remain available while version-based reconciliation queues replacement sets with the new forwarding layout and Graylog collection. Customer display names remain optional branding fields for the three supported reports.

A failed job retains the prior successful set. Failed jobs have at most three attempts with minute-based backoff; a new source, profile change, scheduled occurrence, or explicit regeneration can queue new work. Interrupted running jobs are requeued after restart. Parser and renderer panics are contained as job failures.

**No additional schedule** means reporting runs after new backups and explicit regeneration. Daily, weekly, and monthly schedules supplement this behavior; they do not disable backup-triggered generation or initiate a new backup. They regenerate against the newest saved configuration and refresh enabled Graylog observations.

Schedules use an IANA time zone, local hour/minute, and the selected weekday or month day. Days 29–31 are clamped to the last day of shorter months. Local-time transitions follow the selected time zone. The schedule overview displays the calculated next occurrence. Due work is queued on the next reconciliation and can wait behind other firewalls in the single sequential worker; the selected time is not a rendering-completion guarantee. Occurrences are persisted, and missed runs are coalesced into one latest-source request rather than creating historical report sets. A queued or running generation can satisfy a coincident scheduled occurrence.

Removing a firewall or its last backup removes its report state during reconciliation. Every preview and download also checks the current source catalog, so a removed firewall's reports become inaccessible before that cleanup.

## Graylog source attribution and field requirements

Reporting reads the existing `DATA_DIR/fgt-adm-vpn-conf-db.db` source mapping without modifying it. Matching is case-insensitive, with this precedence:

1. Exact registered firewall name against `vpn_config.dns_name_full`.
2. Exact registered name against `firewallname` or `dns_name`.
3. When the registered name is an FQDN, an unambiguous short-name match against those mapping fields.

A matched mapping supplies comma-separated `cluster_hostnames` when present, so an HA cluster can include both explicitly mapped member sources. Otherwise it supplies `firewallname`. A populated cluster list containing only blanks or commas is invalid; it cannot silently switch to the firewall name. With no mapping, collection uses the hostname in the captured backup, then the short registered firewall name if the snapshot has no hostname. At most 16 distinct, bounded configured identities are accepted.

For each identity, the query includes its original spelling and its lowercase equivalent, matching the source handling in the existing ConfTail collector. Duplicates are removed, so at most 32 exact source spellings are queried. This supports installations where ADM VPN Config contains mixed-case hostnames while Graylog receives lowercase sources. The variants are checked against the effective source names of other ADM entries; a case-insensitive ownership conflict stops collection before any HTTP request.

For a registered FQDN, an alias or short-name match cannot override a different, populated canonical FQDN in `dns_name_full`. Canonical comparisons ignore case and a single terminal DNS dot; Graylog source names retain their original spelling. A conflicting mapping fails collection before any Graylog request. Correct the canonical mapping or the registered firewall identity when an alternate FQDN was previously used. Unambiguous registered short names and legacy mappings with an empty or short canonical name remain supported.

An ambiguous, unreadable, malformed, or unusable existing mapping fails closed. It does not widen the query or fall back to all devices. Each query retains quoted exact source identities, any selected VDOMs, and an absolute UTC time window. Profile documents cannot supply arbitrary Graylog queries or alternate service URLs.

The traffic overview and report capture the actual queried hostnames, their origin (ADM cluster names, ADM firewall name, configuration hostname, or registered short name), the ADM matching method, selected VDOMs, and the base Graylog query. These diagnostics remain available when a valid query finds no records; older saved snapshots without them omit the additional fields. The captured query is bounded to 320 KiB and contains only the source/VDOM/time selector, without credentials, API URLs, or raw log messages.

For **No matching records**, expand **Graylog source query** and copy it into Graylog Search using the same absolute observation window. Check the displayed ADM hostnames against received `source` values, then the selected `vd` values, extraction, forwarding, retention, and the token's search permissions. Dataset-specific queries add their own event and field filters. A missing result never removes the selected VDOM constraint or switches to another firewall; it does not establish that no activity occurred.

Graylog must expose canonical extracted FortiGate fields. There is no custom report-field mapping editor in this release. Configure the existing Graylog parsing/extraction pipeline to supply the appropriate names and numeric values:

| Scope | Required fields |
| --- | --- |
| All observations | `source`, `timestamp`, and category fields `type`, `subtype`. |
| A selected VDOM | `vd`. |
| Forward-traffic grouping | Depending on the dataset: `action`, `app`, `srcip`, `dstip`, or `vd` plus `policyid`. |
| Security-event grouping | `subtype` and `action` on `type:utm` records. |
| VPN-event grouping | `vpntunnel` and `action` on `type:event`, `subtype:vpn` records. |
| Terminal-session byte counters | Canonical `logid:"0000000013"`, with both numeric `sentbyte` and `rcvdbyte`, on forward-traffic records. |

The collector uses the existing Graylog token with the absolute-search and server-aggregation endpoints. It needs permission to search the relevant messages and aggregate the listed fields. A service version or API shape that does not support those operations is reported as a collection error; results are not replaced with locally counted samples. Redirects are rejected, and each response is size-bounded.

### Observed datasets

The profile chooses a rolling **last 24 hours, last 7 days, or last 30 days** window, pinned once at collection start. Log times are absolute UTC; this window is independent of the configuration backup's time and the schedule's display time zone.

The universal absolute-search response must supply matching top-level `from` and `to` bounds, including when its count is zero. If Graylog shortens the requested range through its Query Time Range Limit, or omits valid bounds, collection fails instead of labeling the full requested period as having no data. Configure Graylog to permit the selected report window. Aggregation responses use their separate effective-window metadata contract.

| Dataset ID | Records and calculation |
| --- | --- |
| `traffic_actions` | Received `type:traffic`, `subtype:forward` records grouped by `action`. |
| `applications` | The same forward-traffic class grouped by `app`. |
| `source_ips` | The same class grouped by `srcip`. |
| `destination_ips` | The same class grouped by `dstip`. |
| `policies` | The same class grouped by the pair `vd`, `policyid`. |
| `security_events` | Received `type:utm` records grouped by `subtype`, `action`. |
| `vpn_events` | Received `type:event`, `subtype:vpn` records grouped by `vpntunnel`, `action`. |
| `reported_bytes` | Sums of `sentbyte` and `rcvdbyte` on received canonical forward-session-end records, `logid:"0000000013"`. |
| `traffic_trend` | Forward-traffic record counts in 12 adjacent, equal, half-open UTC intervals `[start, end)`. Shared boundaries are counted once. |

Counts mean **received log records**, not distinct sessions, attacks, users, connections, or successful business transactions. The datasets overlap: for example, action and application tables describe many of the same records. Do not add their totals together.

For grouped datasets, `Total` is the matching category's record count. Up to 20 real groups are displayed; `Returned` counts real groups. An “Other / not returned” row accounts for covered records outside those groups, and a “Missing required fields” row accounts for records lacking grouping fields. `Truncated` identifies an unreturned-group remainder. `MissingFields` lists the required field set when one or more are absent; it does not prove every listed field is missing from every affected record.

Byte totals are **reported terminal-session counters**, not verified transferred traffic or bandwidth. Start/stat records and delta fields are excluded. Duplicate logs, multiple HA observations, missing logs, and session lifetimes crossing the observation window are not deduplicated or apportioned. These counters are not throughput, utilization, or billing evidence. A missing counter is not converted to zero bytes.

### Missing data and failures

| Status | Interpretation |
| --- | --- |
| `available` | The supported query completed for received records in the stated scope. It does not establish complete forwarding, retention, or unique-session accounting. |
| `partial` | Useful observations exist, but returned-group limits, missing fields, or some collection failures limit coverage. Inspect each dataset. |
| `no_data` | No supported matching records were found in the stated source/VDOM/window. Check extraction, permissions, retention, forwarding, and source identity before concluding there was no activity. |
| `missing_fields` | Matching records exist, but required canonical fields are absent or incomplete. Missing coverage is not a zero-activity result. |
| `not_configured` | The shared Graylog URL or token is absent. Configuration reports and an explanatory traffic report can still be generated. |
| `disabled` | Graylog collection is disabled in this profile. |
| `error` | Mapping, transport, permission, API, consistency, or resource checks failed. An overall telemetry error fails the job and preserves the prior complete report set. |

A partial collection may publish a new set with explicit limitations when useful observations exist. Complete collection failure never overwrites the prior successful set with an apparently empty success. The browser overview shows dataset coverage and limits without dumping all raw result rows; the traffic downloads contain the detailed bounded dataset rows.

## Configuration analysis and its boundaries

The parser preserves nested configuration, multiline quoted values, VDOM ownership, policy/VIP sequence, and source references. Names and policy IDs in different VDOMs remain distinct. It uses explicit setting allowlists; passwords, PSKs, credential blobs, private keys, arbitrary scripts, and comments are excluded.

Definite policy conclusions target simple static IPv4 TCP/UDP/SCTP port forwards with recognized FortiOS 7.0/7.2/7.4/7.6 headers and resolvable selectors. This is configuration-derived analysis backed by fixtures, not certified emulation of every FortiOS datapath.

One-to-one static mappings are evaluated across all IP protocols. A TCP-only or other narrower service cannot establish denial or geographic protection for the whole mapping. Explicit standard services using `protocol IP` with protocol number `0` have all-protocol scope; a customized service named `ALL` retains its configured meaning. Non-default destination IP-range or FQDN restrictions on custom services remain indeterminate until their address semantics can be established, rather than supplying an affirmative protection result.

VIP/VIP-group references, central NAT backend-address correlation, external versus mapped service ports, prior denies, and earlier allow exceptions are considered. Policy sequence is separate from numeric ID. Explicitly disabled VIPs remain inventoried without active-publication claims. A generic deny with `match-vip disable` does not establish VIP protection; omitted `match-vip` remains uncertain across firmware/export histories.

Virtual servers, IPv6/NAT46/NAT64 objects, advanced/proxy VIP types, dynamic addresses, identity/negated selectors, unsupported modes, and unknown versions remain visible. Where their semantics cannot be established, outcomes and dependent geographic claims are indeterminate. Complete inventory does not mean complete policy evaluation.

Inventory sections cover interfaces/zones, routing, SD-WAN, DHCP/DNS, VPN, HA, administration, logging, time synchronization, policies, local-in policies, and inspection metadata. Saved configuration does not establish current Internet reachability, backend health, HA failover, tunnel state, dynamic DNS/GeoIP membership, support/subscription state, or compliance certification. Observed log events do not remove these boundaries.

## Catalog and dependencies beyond this implementation

The catalog is a capability and dependency map, not a claim of full FortiAnalyzer parity. It separates implemented configuration/profile/export workflows, Graylog-backed observations, integrations requiring additional evidence, and features not implemented here.

Static dataset IDs are `source`, `publications`, `policy_traces`, `technical_inventory`, `findings`, and `configuration_counts`. Catalog entries `traffic`, `security_events`, and `vpn_events` describe the Graylog report families above. The registry is maintained in [internal/reportmodel/registry.go](../internal/reportmodel/registry.go).

Measured SD-WAN SLA, system performance/throughput accounting, endpoint vulnerabilities, security ratings/compliance, correlated Fabric incidents, Shadow IT/AI classifications, other Fortinet product analytics, and AI-assisted investigations require additional normalized sources, services, or entitlements. A saved probe, tunnel, or policy definition does not supply those measurements.

Arbitrary SQL datasets, email/remote-server distribution, and combined fleet reports are explicitly **not implemented**. Imported profiles cannot execute SQL, create delivery destinations, or configure credentials. Reports remain per firewall and available through authenticated downloads.

## Storage, access, and resource bounds

The private `DATA_DIR/fgt-reports.db` SQLite database stores encrypted profile documents, the captured assessment, and three PDFs using the application's shared AES-GCM cipher. Files have restrictive permissions. Atomic replacement, secure deletion, and incremental reclamation avoid logical historical report sets. The main PostgreSQL schema remains compatible; committed-backup lookup uses an existing indexed key.

All report routes—including profile operations, catalog, schedule, data, and every export format—require an authenticated administrator or operator. Viewer users are denied server-side. Responses use `Cache-Control: private, no-store`. Generation, profile changes, and downloads are audited using identifiers rather than configuration or log payloads. No public sharing endpoint is created.

The host accepts at most 16 MiB of complete decrypted configuration and verifies integrity. Parsing bounds nesting, object counts, selector traversal, relationship expansion, and generated explanation output. Jobs have a two-minute context deadline. Rendering checks input budgets before allocating table content and bounds text/page counts. A complete set is limited to 64 MiB before encryption; exceeding a limit preserves the prior set.

PDF text cleaning and wrapping observe cancellation during their work. Wrapping measures glyph widths incrementally, so long Unicode or zero-width sequences do not trigger repeated measurement of an ever-growing line. Long multiline rows and unbroken labels remain supported within the existing document and page limits; resource failures never publish a truncated PDF.

Graylog collection is bounded to **75 seconds**, **40 requests**, **two concurrent requests**, **45 seconds per request**, and **2 MiB per response**. Real group output is capped at 20 groups per grouping dataset; byte counters have one aggregate result and the trend has 12 buckets. These bounds are reported or fail explicitly rather than silently converting a sampled prefix into a whole-window result.

The native Go PDF renderer embeds licensed DejaVu fonts and supports searchable Unicode text, repeated table headers, split long rows, and page totals. Unsupported glyphs are represented by Unicode code points. Deployment remains CGO-free.

## Verification and synthetic preview

Run the normal repository gates:

```bash
go build ./...
go vet ./...
go test -race ./...
golangci-lint run
```

Focused tests cover committed backup notifications, pinned-source integrity, queue recovery, atomic replacement, profile revisions and scheduling, latest-set retention, authorization, parser redaction, escaped and formula-safe exports, ordering, Graylog source/field coverage, aggregation consistency, and PDF layout/Unicode. Poppler round-trip text checks run when `pdftotext` is installed.

Generate synthetic PDF previews outside the repository:

```bash
FORTISAFE_REPORT_PREVIEW_DIR=/tmp/fortisafe-report-previews \
  go test ./extensions/fgt_reports/renderpdf -run TestWritePreviewFixtures -count=1
```

For browser review of the real Reports templates and handlers, including profile editing, import/export, schedules, and all report formats:

```bash
FORTISAFE_REPORTS_PREVIEW=1 \
  go test ./extensions/fgt_reports -run TestReportsBrowserPreview -count=1 -v
```

Open `http://127.0.0.1:18906/reports/`. The opt-in fixture uses synthetic devices and observations, the actual analyzer/renderers, and isolated encrypted storage. It has no production account, configuration, Graylog connection, or customer data and listens only on loopback. Stop it with a POST to `/__fixture/stop`; it also stops after ten minutes. The preview environment variable is for tests only.

### Interpretation references

- [VIP policy priority and match-vip](https://docs.fortinet.com/document/fortigate/7.2.0/best-practices/862226/policies)
- [7.2.4 default-behavior change for new deny policies](https://docs.fortinet.com/document/fortigate/7.2.4/fortios-release-notes/230510/changes-in-default-behavior)
- [DNAT object order before policy access checks](https://community.fortinet.com/fortigate-3/technical-tip-fortios-destination-nat-dnat-logic-when-central-nat-is-disabled-191339)
- [Firewall service matching a translated backend port](https://community.fortinet.com/fortigate-3/troubleshooting-tip-firewall-policy-with-specified-service-for-virtual-ip-not-being-matched-170558)
- [Central DNAT](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/448790/central-dnat)
- [Canonical forward-session-end log ID 13](https://docs.fortinet.com/document/fortigate/7.6.0/fortios-log-message-reference/13/13-log-id-traffic-end-forward)
- [Implemented Graylog collection semantics](../internal/reportlogs/collect.go)
