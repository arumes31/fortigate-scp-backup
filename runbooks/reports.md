# Automatic firewall reports

FortiSafe generates three PDFs from each firewall's newest successful configuration backup:

1. **Port Forwarding & Exposure** — all detected VIP/virtual-server definitions, mapped backends, related policies in configuration order, source/service restrictions, and geographic-deny explanations.
2. **Technical Configuration** — configuration inventory, findings, recommendations, source references, and analysis coverage.
3. **Customer Review & Roadmap** — a reduced, customer-facing summary with configured-object counts, curated discussion topics, and proposed next steps. It does not contain management addresses, backend addresses, object names, rule traces, or raw findings prose. Its device reference is the FortiSafe firewall ID.

The **Reports / Berichte** navigation item is available to administrators and operators. The table shows the newest backup, the source of the currently available report set, generation state, limitations, and three download links. **Inspect findings** opens a searchable forwarding inventory and technical evidence. **Regenerate latest** retries the current source; historical backups cannot be selected.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `EXT_FGT_REPORTS` | `true` | Mount the extension and run automatic reporting. |
| `REPORTS_LANGUAGE` | `en` | PDF layout/narrative language, `en` or `de`. Technical CLI values and some analysis explanations retain their canonical English form. |

The browser page follows the user's EN/DE preference. The configured PDF language is stable for everyone downloading that set. Changing the PDF language or report schema version queues replacement sets, including after an application restart. To change analysis semantics or templates in a later release, increment `internal/reportmodel.Version`.

## Automatic lifecycle and retention

- A successful backup publishes a committed-backup event without replacing the existing SSE/audit hook. The optional indexed metadata lookup is bounded to two seconds and cannot turn a successful backup into a failure.
- The report observer only signals a bounded background worker. It does not parse configurations or render PDFs in the backup callback.
- On startup and every minute, the worker reconciles the newest committed backup for each registered firewall. This backfills existing installations and repairs missed notifications.
- Each job pins the backup ID, firewall ID, recorded timestamp, and checksum. It reads that exact source through the host's authenticated-encryption/ownership/path checks. A missing source is an error; another backup is never silently substituted.
- One worker produces an assessment and all three PDFs. The complete encrypted set is published in one transaction. Before publication the catalog is reconciled again; comparison against the desired source prevents superseded work from replacing newer work.
- There is exactly one desired-job row and one latest-report row per firewall. Replacement overwrites all three PDFs and their assessment together; there are no report-history rows, artifact directories, or PDF caches.
- A failed job keeps the prior successful set. The UI explicitly distinguishes its source from the newest backup. Failed jobs have at most three attempts, with minute-based backoff, until a new source or an explicit retry is requested.
- Interrupted running jobs are requeued after restart. Parser/renderer panics are contained as safe job failures.
- Removing a firewall or its last backup removes its report state on reconciliation. Every preview/data/PDF request also checks the current source catalog, so a deleted firewall's report is inaccessible before that cleanup.

Reports also regenerate for a new successful backup whose configuration checksum is unchanged; the new set carries the new backup timestamp and identity. A failed backup does not queue a new report.

## Storage and access

The extension follows FortiSafe's private SQLite extension-storage pattern in `DATA_DIR/fgt-reports.db`, with restrictive filesystem permissions. The assessment and three PDF blobs are encrypted using the application's shared AES-GCM cipher. SQLite secure deletion and incremental reclamation avoid keeping logical historical report sets. Main PostgreSQL schema remains compatible; the only new core database operation is an indexed backup-row lookup.

All report routes—including preview, JSON, PDF, and regeneration—require an authenticated administrator or operator. Viewer users are denied server-side and do not see the navigation item. Responses use `Cache-Control: private, no-store`. Downloads and generation are recorded in the existing activity log using IDs, never configuration text.

The technical model uses explicit setting allowlists. Passwords, PSKs, credential blobs, private keys, raw scripts, and comments are excluded. Customer rendering applies another data projection before PDF creation, accepting aggregate counts and curated finding categories rather than raw technical text. Customer names and commercial estimates are not inferred.

## What the analysis establishes

The parser preserves nested configuration structure, multiline quoted values, VDOM ownership, policy sequence, VIP sequence, and source line references. Object names and policy IDs in different VDOMs remain distinct.

The current evaluator targets simple static IPv4 TCP/UDP/SCTP port forwards with exact recognized FortiOS 7.0/7.2/7.4/7.6 headers and resolvable selectors. These are configuration-derived conclusions supported by regression fixtures, not a certified emulation of every FortiOS datapath.

The analyzer handles ordinary VIP/VIP-group references and central NAT backend-address correlation, distinguishes external and mapped service ports, and examines earlier denies and allow exceptions. It distinguishes applicable, partial, ineffective, absent, and indeterminate geographic restrictions. Policy position is separate from numeric policy ID. A generic deny with explicit `match-vip disable` is not treated as protection for VIP traffic; omitted `match-vip` is reported as uncertain rather than guessed across firmware/export histories.

Virtual servers and their real servers, IPv6/NAT46/NAT64 objects, advanced/proxy VIP types, dynamic addresses, identity/negated selectors, source filters, unsupported modes, and unknown versions remain visible. Where their semantics cannot be established, outcomes and dependent geographic claims are marked indeterminate. Complete inventory does not imply complete policy evaluation.

Technical sections include allowlisted interface/zone, static/policy routing, BGP/OSPF settings, SD-WAN members/rules/checks, DHCP/DNS, VPN, HA, administrator, logging, NTP, policy, local-in, and security-profile metadata. They do not evaluate every nested security profile or reuse a potentially unrelated latest-audit cache for a selected source.

Saved configuration does not establish current Internet reachability, backend health, HA failover, tunnel state, dynamic DNS/GeoIP/feed membership, traffic counts, utilization, subscriptions, support expiry, or compliance certification. The reports state that scope explicitly. No live firewall query, external renderer, or LLM is required.

### Fortinet references for the interpretation boundaries

- [VIP policy priority and match-vip](https://docs.fortinet.com/document/fortigate/7.2.0/best-practices/862226/policies)
- [7.2.4 default-behavior change for new deny policies](https://docs.fortinet.com/document/fortigate/7.2.4/fortios-release-notes/230510/changes-in-default-behavior)
- [DNAT object order before policy access checks](https://community.fortinet.com/fortigate-3/technical-tip-fortios-destination-nat-dnat-logic-when-central-nat-is-disabled-191339)
- [Firewall service matching a translated backend port](https://community.fortinet.com/fortigate-3/troubleshooting-tip-firewall-policy-with-specified-service-for-virtual-ip-not-being-matched-170558)
- [Central DNAT](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/448790/central-dnat)

## Resource bounds and rendering

The host accepts at most 16 MiB of complete decrypted configuration; it never silently truncates the source. The parser also bounds nesting, object counts, selector traversal, relationship expansion, and generated explanations before they can amplify into a large report. Each report job has a two-minute context deadline. The renderer checks a presentation-input budget before allocating table content, then bounds text and page counts. A complete set is limited to 64 MiB before encryption. Exceeding a limit is a visible failure that preserves the prior set.

The native Go renderer uses embedded, licensed DejaVu fonts, searchable Unicode text, A4 pages, repeated table headers, split long rows, and page totals. Unsupported font glyphs are represented by their Unicode code points. It preserves the static, CGO-free application deployment.

## Verification

Run the repository's normal gates:

```bash
go build ./...
go vet ./...
go test -race ./...
golangci-lint run
```

Focused tests cover source ownership/checksums/path confinement, committed backup notifications, queue recovery/deduplication, atomic replacement, stale completion, failure preservation, bounded retry, authorization, parser semantics and redaction, and PDF pagination/Unicode. Poppler round-trip text checks run when `pdftotext` is installed.

To create synthetic PDF previews outside the repository:

```bash
FORTISAFE_REPORT_PREVIEW_DIR=/tmp/fortisafe-report-previews \
  go test ./extensions/fgt_reports/renderpdf -run TestWritePreviewFixtures -count=1
```

For a local browser review of the real Reports templates, analyzer, renderer, encrypted storage, and download handlers:

```bash
FORTISAFE_REPORTS_PREVIEW=1 \
  go test ./extensions/fgt_reports -run TestReportsBrowserPreview -count=1 -v
```

Open `http://127.0.0.1:18906/reports/`. This isolated test fixture contains synthetic devices, has no production login, and only listens on loopback. Stop it with a POST to `/__fixture/stop`; it also stops after ten minutes. The preview environment variable is for tests only.

No production firewall backups are included in fixtures or generated test evidence.
