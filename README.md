# FortiSafe

<p align="center">
  <img src="internal/web/static/logo.png" alt="FortiSafe Logo" width="240">
</p>

<p align="center">
  <strong>Secure, scheduled, self-contained backups for FortiGate firewalls.</strong>
</p>

<p align="center">
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8.svg?style=flat-square&logo=go" alt="Go Version"></a>
  <a href="https://github.com/arumes31/fortigate-scp-backup/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/arumes31/fortigate-scp-backup/ci.yml?branch=main&style=flat-square&logo=github" alt="CI Build Status"></a>
  <a href="https://github.com/arumes31/fortigate-scp-backup/pkgs/container/fortigate-scp-backup"><img src="https://img.shields.io/badge/Container-GHCR-blue?style=flat-square&logo=docker" alt="Docker Registry"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/arumes31/fortigate-scp-backup?style=flat-square" alt="License"></a>
</p>

---

## 📖 Overview

**FortiSafe** is a web-based management tool and automation engine that backs up FortiGate firewall configurations securely over SSH/SCP. It compiles into a **single, fully static binary** that runs the web interface, the backup scheduler, and every extension's background worker as concurrent goroutines in one process — no external task queue, application server, or sidecar required.

Point it at your firewalls, set a schedule, and FortiSafe pulls each configuration on a cron/interval basis, stores it (optionally encrypted at rest), keeps a configurable number of copies, and emails you when a run fails.

### Highlights
* **Single-process model** — the web server, cron scheduler, and extension workers all run as lightweight goroutines inside one binary.
* **Fully static & lightweight** — ships as a distroless container holding only the compiled binary and root CA certificates.
* **No CGO required** — pure-Go drivers (e.g. `modernc.org/sqlite` for extensions) keep cross-compilation and container builds clean.
* **Configured entirely by environment** — every setting is an environment variable; there are no config files to template.
* **Same-origin by default** — the UI, styles, and self-hosted fonts are served from the app itself under a strict Content-Security-Policy; no external CDNs are contacted at runtime.

---

## 🏗️ Process Architecture

```mermaid
graph TD
    User([User / Browser]) -->|HTTP / SSE| WebServer[Web Server / Chi Router]
    Firewall[(FortiGate Firewall)] <-->|SSH / SCP| BackupEngine[Backup Engine]

    subgraph FortiSafe ["FortiSafe Process"]
        WebServer
        Scheduler[Cron Scheduler] -->|Triggers| BackupEngine
        BackupEngine -->|Save backups| FileSystem[(File System / backups/)]
        BackupEngine -->|Log events| Postgres[(PostgreSQL DB)]
        WebServer -->|Read/Write| Postgres

        subgraph Extension ["fgt_adm_vpn_conf Extension"]
            ExtRoutes[Extension Web Routes]
            ExtWorker[Graylog Status Worker] -->|Status events| HookWise([HookWise Webhook])
            ExtWorker -->|Read config| SQLite[(SQLite DB)]
            ExtRoutes -->|Read/Write| SQLite
        end

        %% Cross-boundary edge kept outside the Extension subgraph so the Web
        %% Server stays in the parent cluster instead of being drawn inside it.
        WebServer -->|Mount routes| ExtRoutes
    end

    Graylog([Graylog Server]) <-->|API check| ExtWorker
```

---

## ✨ Features

- 🛡️ **Firewall Management**: Register and monitor multiple firewalls, each with its own credentials, SSH port, retention count, and backup schedule. Add them individually or in bulk via CSV.
- ⏰ **Automated Scheduling**: Cron or interval-based backups, with staggered runs on startup to avoid traffic spikes. Trigger any backup on demand and test connectivity from the UI.
- 🔐 **Hardened Security**:
  - **AES-256-GCM at rest**: Optional encryption for every stored backup and firewall SSH password.
  - **Local passwords hashed with bcrypt**, plus a forced password change on first login.
  - **Session guard**: Signed sessions, idle timeouts, and X-Forwarded-For pinning.
  - **Multi-factor auth**: Optional TOTP and RADIUS (PAP). The login screen surfaces a mobile-approval hint and allows up to 60 s for push/MFA prompts.
  - **Brute-force lockout**: Per-IP + username rate limiting with a configurable lockout window.
- 🔎 **Configuration Search**: Full-text, wildcard search across the newest saved configuration of every firewall, with a built-in library of example queries (hostnames, policies, VPN, admin/security review, and more).
- 📊 **Dashboard & Activity Log**: At-a-glance health summary, failing-firewall shortlist, a **Graylog logging-issues** card (VPN devices whose logging is offline / errored / unconfigured, surfaced from the FGT ADM VPN Config module), and an audited activity trail with optional age-based pruning.
- 📡 **Real-time Updates**: Live status propagation to the UI via Server-Sent Events (SSE).
- 🔍 **Security Auditing & Insights**:
  - **Instant, cached audits**: The audit page renders immediately; per-firewall results are computed asynchronously, cached in SQLite, and pre-warmed right after each successful backup. A per-firewall "re-check" recomputes on demand.
  - **~30 curated hardening checks** based on the Fortinet hardening guide and community best practices: admin access (2FA, trusted hosts, default account, idle timeout, maintainer account), protocol hygiene (Telnet, SSHv1, weak TLS, static ciphers), SSL-VPN exposure (default port, source restriction, TLS floor), SNMP default communities, USB auto-install, NTP, remote logging, any/any/ALL policies, and more.
  - **Exact config context**: Every finding points at the exact configuration block — the detected line ±3 lines with the block ending, rendered with a highlighted line and gutter numbers.
  - **Shadow Rule Finder**: Identifies firewall policies shadowed or blocked by preceding rules.
  - **Weak Crypto Policy Flags**: Scans IPsec VPN configurations for weak encryption/integrity settings (DES, 3DES, MD5, weak DH groups) and global outdated TLS settings.
  - **Security Fabric Audit**: Flags missing Fortinet Security Fabric (CSF) setups.
  - **CVE Correlation & Upgrade Paths**: Maps the detected FortiOS version to known exploited CVEs (2022–2025, e.g. CVE-2022-42475, CVE-2023-27997, CVE-2024-21762, CVE-2024-55591) and computes correct train-by-train upgrade paths (never a downgrade; up-to-date versions are reported as such).
  - **Compliance Scoring**: Derives PCI-DSS, CIS Benchmark, and HIPAA scores from the structured check results.
  - **Change Tickets & Exemptions**: Link configuration runs to change tickets, and log approved security exemptions (matched by stable finding keys, so dynamic finding texts stay exempt).
- 🗺️ **Interactive Network Topology** (dedicated page): A D3-powered, CDN-free collapsible tree with a **mirrored layout** — WAN uplinks and IPsec/SSL-VPN tunnels fan out to the *left* of a central Internet node, while the FortiGate, its FortiSwitch stack, VLANs, ports, and client devices grow to the *right*. Pan/zoom, search, filters, a right-click context menu, and:
  - **Device faceplates**: Clicking the firewall or a switch slides in an auto-generated schematic front panel with per-port coloring (WAN / FortiLink / VLAN parent / IP configured), a **VLAN color legend**, and per-port details.
  - **Maximize view**: A one-click ⛶ button (and `Esc`) hides all page chrome so the canvas fills the viewport.
  - **Public share links**: Generate revocable, optionally expiring token URLs that expose a single firewall's topology read-only without login (firmware version and VPN remote gateways are redacted).
  - **Live device & state overlay** (optional `graylog_device_data` extension) — derived purely from **config backups + Graylog logs**, with *no REST API and no SSH connection to the firewall*. For firewalls with managed FortiSwitches it adds, refreshed hourly (or on demand):
    - **Client devices** under their switch/VLAN with MAC, IP, and an OS/vendor **fingerprint**; devices sharing a MAC/IP are highlighted;
    - **Device → switch-port pinning** derived from FortiSwitch MAC-table events (add / move / delete) and NAC device events, with per-switch sighting analysis so a client is pinned to its true access port — never the uplink ports its frames transit;
    - **Automatic switch-tree detection**: switch↔switch wiring from the config's auto-ISL trunk bindings plus STP events — FortiSwitch names inter-switch trunks after the peer's serial, and a trunk's STP *root* role marks it as the uplink, orienting the tree (including access→access chains and dual-homed uplinks to an MC-LAG core pair, whose LAG legs come from trunk-membership events);
    - **Wireless clients** linked to their AP and SSID, with signal strength;
    - **Port link up/down** and **FortiSwitch STP / loop / root-guard** state — blocked ports blink orange on faceplates and mark their switch and interlinks;
    - **VPN tunnel up/down** and **HA member/role** status;
    - **MC-LAG ICL** peer detection between core switches.
  - **"Live" refresh button**: temporarily polls Graylog every ~minute (auto-stops after 10 min) with an automatically narrowed search window, for near-real-time device data while you watch.
- 🌐 **Bilingual UI (EN/DE)**: English by default, one-click toggle to German — including localized audit findings and upgrade paths.
- ✉️ **SMTP Alerts**: Failure notifications with STARTTLS enforced (plaintext delivery is refused).
- 🔌 **Modular Extension System**: A clean loader mounts self-contained extensions (such as the FGT ADM VPN configuration module) with their own routes, storage, and background workers.
- 🖥️ **Terminal-style Web UI**: A full-width, keyboard-accessible interface with a self-hosted monospace typeface — no external fonts or scripts.

---

## 🗺️ Network Topology

The topology page renders a live map of each site **entirely from the two data sources FortiSafe already has — the config backup and Graylog logs.** It never opens an SSH session or calls the FortiGate REST API. The structure (interfaces, VLANs, FortiSwitches, ports, VPN definitions, HA, FortiAPs) is parsed from the latest backup; the runtime overlay (device→port pinning, link/STP state, tunnel and HA up/down, wireless associations) comes from the `graylog_device_data` extension.

```mermaid
graph LR
    Peers([Remote VPN peers]):::ext

    %% Internet-facing branches render to the LEFT of the Internet node
    WAN["🌎 WAN uplinks<br/>wan1 · wan2"]:::cfg
    VPN["🔒 IPsec / SSL-VPN tunnels<br/><i>up ▲ / down ▼</i>"]:::live
    NET(["🌐 Internet"]):::ext

    Peers --- VPN
    WAN --> NET
    VPN --> NET
    NET --> FGT

    FGT["🛡️ FortiGate<br/><i>HA-cluster aware</i>"]:::cfg
    HA["⇄ HA members<br/>primary · secondary"]:::live
    APG["📶 FortiAPs"]:::cfg
    WCL["Wireless clients<br/>SSID · AP · signal"]:::live
    VLAN["VLANs<br/><i>color-coded</i>"]:::cfg
    CORE["FortiSwitch — core"]:::cfg
    CORE2["FortiSwitch — core peer"]:::cfg
    ACC["FortiSwitch — access"]:::cfg
    PORT["Ports<br/><i>link ▲/▼ · STP / guard</i>"]:::live
    DEV["Client devices<br/>MAC · IP · VLAN · fingerprint"]:::live

    FGT --> HA
    FGT --> APG
    APG --> WCL
    FGT --> VLAN
    FGT --> CORE
    CORE -. "MC-LAG ICL" .- CORE2
    CORE --> ACC
    ACC --> PORT
    PORT --> DEV

    classDef cfg fill:#0b3d5c,stroke:#22d3ee,color:#e6f6ff;
    classDef live fill:#4a3410,stroke:#f0b429,color:#fff6e0;
    classDef ext fill:#2b2b2b,stroke:#888,color:#eeeeee;
```

> **Legend** — 🟦 **blue** nodes are parsed from the **config backup**; 🟧 **amber** nodes are the **live Graylog overlay** (device pinning, link/STP state, VPN & HA up/down, wireless associations). Enable the overlay with `EXT_GRAYLOG_DEVICE_DATA=true` plus `GRAYLOG_URL` / `GRAYLOG_TOKEN`.

Each Graylog signal has its own tunable query template (`%s` is expanded to the firewall's Graylog `source`, resolved from the FGT ADM VPN Config module so HA clusters match **both** member hostnames). See the [extension configuration](#extension-graylog-device-data-topology-overlay) below.

---

## 📋 Prerequisites

1. **FortiGate SSH & SCP Access** — enable SCP backups on the target FortiGate:
   ```txt
   config system global
       set admin-scp enable
   end
   ```
2. **SCP User Account & Profile** — create a dedicated profile and administrator with read access to the system configuration:
   ```txt
   config system accprofile
       edit "scp-profile"
           set comments "Access profile for FortiSafe backups"
           set secfabgrp read
           set ftviewgrp read
           set authgrp read
           set sysgrp custom
           set netgrp read
           set loggrp read
           set fwgrp read
           set vpngrp read
           set utmgrp read
           set wifi read
           set cli-diagnose enable
           set cli-get enable
           set cli-show enable
           set cli-exec enable
           set cli-config enable
           config sysgrp-permission
               set admin read-write
               set upd read
               set cfg read
               set mnt read
           end
       next
   end

   config system admin
       edit "scpuser"
           set accprofile "scp-profile"
           set password <YOUR_SECURE_PASSWORD>
       next
   end
   ```
3. **PostgreSQL** — a reachable PostgreSQL database for the main store. The bundled Compose files include one; point `PG_*` at your own if you already run Postgres.

---

## 🚀 Installation & Deployment

FortiSafe is distributed as a container image on the GitHub Container Registry (GHCR). It listens on port **8521** and persists to `./backups` and `./data` by default.

### Option 1 — Run the pre-built image from GHCR (recommended)

Pull the latest published image:
```bash
docker pull ghcr.io/arumes31/fortigate-scp-backup:latest
```

The quickest start is the bundled Compose file, which brings up FortiSafe together with a PostgreSQL database:
```bash
docker compose -f docker-compose.ghcr.yml up -d
```

Or run the container directly against an existing PostgreSQL instance:
```bash
docker run -d \
  --name fortisafe \
  -p 8521:8521 \
  -e TZ=Europe/Vienna \
  -e PG_HOST=db.internal -e PG_PORT=5432 \
  -e PG_USER=fortisafe -e PG_PASSWORD=change-me \
  -e PG_DATABASE=firewall_backups \
  -e SESSION_KEY=please-change-me-to-a-long-random-string \
  -v "$(pwd)/backups:/app/backups" \
  -v "$(pwd)/data:/app/data" \
  --restart unless-stopped \
  ghcr.io/arumes31/fortigate-scp-backup:latest
```

Or drop this minimal `compose.yml` next to your project and run `docker compose up -d`:
```yaml
services:
  fortisafe:
    image: ghcr.io/arumes31/fortigate-scp-backup:latest
    container_name: fortisafe
    ports:
      - "8521:8521"
    environment:
      TZ: Europe/Vienna
      PG_HOST: db
      PG_USER: fortisafe
      PG_PASSWORD: change-me
      PG_DATABASE: firewall_backups
      SESSION_KEY: please-change-me-to-a-long-random-string
      # Optional: 32-byte hex/base64 key to enable AES-256-GCM encryption at rest
      # ENCRYPTION_KEY: ""
    volumes:
      - ./backups:/app/backups
      - ./data:/app/data
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    container_name: fortisafe-db
    environment:
      POSTGRES_USER: fortisafe
      POSTGRES_PASSWORD: change-me
      POSTGRES_DB: firewall_backups
    volumes:
      - ./pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fortisafe -d firewall_backups"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped
```

> [!WARNING]
> The `db` service is pinned to `postgres:16-alpine`. PostgreSQL only opens a data directory created by the **same major version** — this applies to downgrades too: a `./pgdata` initialized by a newer major (e.g. `postgres:latest`, i.e. 17/18, used by earlier revisions of the bundled compose files) will not start under 16. Before switching images, check `cat ./pgdata/PG_VERSION`; if it differs from the image's major version, follow the dump/restore procedure documented in [`docker-compose.yml`](docker-compose.yml) (`pg_dumpall` with the matching old version, then restore into a freshly initialized data directory).

**Available tags:** `latest`, a date tag (`DDMMYYYY`), the commit SHA, and release tags (`vX.Y.Z`). See [`docker-compose.ghcr.yml`](docker-compose.ghcr.yml) for a fully annotated example covering every setting.

### Option 2 — Build and run locally

[`docker-compose.yml`](docker-compose.yml) compiles the static binary inside a multi-stage Docker build and starts it alongside PostgreSQL:
```bash
docker compose up -d
```

> [!NOTE]
> By default the application maps the local `./backups` and `./data` directories for persistent storage.

### First login

Open <http://localhost:8521> and sign in with the seeded administrator account:

| Username | Password   |
| :------- | :--------- |
| `admin`  | `changeme` |

You are required to change the password on first login. Enable `TOTP_ENABLED` and/or `RADIUS_ENABLED` to add multi-factor authentication.

---

## ⚙️ Configuration Reference

FortiSafe is configured entirely via environment variables.

### General Configuration
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `TZ` | `Europe/Vienna` | Timezone location used by the scheduler. |
| `PORT` | `8521` | HTTP port the application web server listens on. |
| `LOG_LEVEL` | `info` | Logging verbosity: `debug` \| `info` \| `warn` \| `error`. |
| `BACKUP_DIR` | `backups` | Storage directory for configuration backups. |
| `DATA_DIR` | `/app/data` | Storage directory for SQLite extension data. |

### PostgreSQL Configuration (Main Database Store)
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PG_HOST` | `localhost` | PostgreSQL host. |
| `PG_PORT` | `5432` | PostgreSQL port. |
| `PG_USER` | `your_user` | PostgreSQL user. |
| `PG_PASSWORD` | `your_password` | PostgreSQL password. |
| `PG_DATABASE` | `firewall_backups` | PostgreSQL database name. |
| `PGSSLMODE` | `prefer` | SSL connection mode. |
| `PG_MAX_CONNS` | `50` | Maximum connections allowed in the database pool. |
| `PG_CONNECT_RETRIES` | `10` | Database connection retry attempts on startup. |
| `PG_CONNECT_BACKOFF_SECONDS` | `3` | Time to wait between connection retry attempts. |

### Authentication & Web Security
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `TOTP_ENABLED` | `false` | Enable TOTP 2FA for the local admin account. |
| `TOTP_SECRET` | *(Auto-generated)* | 16-character Base32 TOTP secret. |
| `RADIUS_ENABLED` | `false` | Enable RADIUS (PAP) authentication. |
| `RADIUS_SERVER` | `localhost` | RADIUS server address. |
| `RADIUS_PORT` | `1812` | RADIUS service port. |
| `RADIUS_SECRET` | `secret` | RADIUS shared secret key. |
| `LOGIN_MAX_ATTEMPTS` | `5` | Maximum login failures allowed before lockout. |
| `LOGIN_LOCKOUT_MINUTES` | `15` | Minutes a user is locked out after the limit is exceeded. |
| `SESSION_KEY` | *(Auto-generated)* | Session signing key (forces re-login on restart if empty). |
| `COOKIE_SECURE` | `false` | Set the `Secure` flag on session cookies (requires HTTPS). |
| `ENABLE_HSTS` | `false` | Emit `Strict-Transport-Security` headers (requires HTTPS). |
| `TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` for client IP (enable only behind a trusted proxy). |

### Backup Engine & SCP Defaults
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ENCRYPTION_KEY` | *(Unset)* | 32-byte (hex/base64) key to enable AES-256-GCM encryption at rest. |
| `DEFAULT_SCP_USER` | `test` | Default SSH username when none is specified. |
| `DEFAULT_SCP_PASSWORD` | *(Unset)* | Default SSH password when none is specified. |
| `FORTIGATE_CONFIG_PATH` | `sys_config` | Remote file path to download (typically `sys_config`). |
| `SCP_TIMEOUT` | `60` | SSH connection and transfer timeout in seconds. |
| `MAX_CONCURRENT_BACKUPS` | `10` | Semaphore cap limiting simultaneous SSH sessions. |
| `CSV_MAX_BYTES` | `5242880` | Maximum allowed size (in bytes) for CSV bulk uploads. |

### SMTP Mail Notification Settings
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `MAIL_SERVER` | `smtp.example.com` | SMTP host for backup failure notifications. |
| `MAIL_PORT` | `587` | SMTP port (STARTTLS is enforced). |
| `MAIL_USER` | `user@example.com` | SMTP authentication user. |
| `MAIL_PASSWORD` | `password` | SMTP authentication password. |
| `MAIL_RECIPIENT` | *(Same as user)* | Destination email address for error logs. |

### Extension: FGT ADM VPN Configuration
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `EXT_ADM_VPN_CONF` | `false` | Enable the FGT ADM VPN Config module. |
| `GRAYLOG_URL` | *(Unset)* | API endpoint for the Graylog cluster (shared by both Graylog-backed extensions). |
| `GRAYLOG_TOKEN` | *(Unset)* | Graylog authentication token. |
| `GRAYLOG_SEARCH_TIMEFRAME` | `86400` | Device status log scan timeframe in seconds. |
| `HOOKWISE_URL` | *(Unset)* | Webhook endpoint for HookWise up/down transition logs. |
| `HOOKWISE_TOKEN` | *(Unset)* | Bearer authentication token for HookWise webhook. |
| `ACTIVITY_LOG_RETENTION_DAYS` | `0` | Auto-prune activity logs older than N days (0 = keep forever). |

### Extension: Graylog Device Data (Topology Overlay)

Powers the live device & state overlay on the [topology page](#-network-topology). Requires `GRAYLOG_URL` / `GRAYLOG_TOKEN` (above). Each signal is a separate query template; `%s` is expanded to the firewall's Graylog `source` (resolved from the FGT ADM VPN Config module, so HA clusters match both member hostnames).

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `EXT_GRAYLOG_DEVICE_DATA` | `false` | Enable the Graylog switch-device inventory extension (topology device data). |
| `GRAYLOG_DEVICE_INTERVAL` | `3600` | Background refresh interval in seconds for all signals below. |
| `GRAYLOG_DEVICE_RANGE` | `86400` | Seconds of log history scanned per background fetch. (The topology "Live" button overrides this with a narrower window, clamped to 60–3600 s.) |
| `GRAYLOG_DEVICE_QUERY` | `source:"%s" AND (mac:* OR srcmac:* OR macaddr:*)` | Client-device logs (MAC/IP/VLAN + OS fingerprint). |
| `GRAYLOG_MAC_QUERY` | *(FortiSwitch MAC-table add/move/delete + NAC device add/delete logids)* | Device-to-switch-port pinning from FortiSwitch MAC-table events (requires `set mac-event-logging enable` under `config switch-controller global`) and NAC device events. |
| `GRAYLOG_STP_QUERY` | *(FortiSwitch spanning-tree / port-status / link / BPDU / loop- & root-guard filter)* | Port link up/down and STP / guard state (blocked ports blink on faceplates). |
| `GRAYLOG_WIFI_QUERY` | `source:"%s" AND subtype:"wireless" AND stamac:* AND (ssid:* OR ap:*)` | Wireless client ↔ AP ↔ SSID associations with signal strength. |
| `GRAYLOG_VPN_QUERY` | `source:"%s" AND subtype:"vpn" AND tunnelid:*` | IPsec / SSL-VPN tunnel up/down status. |
| `GRAYLOG_HA_QUERY` | `source:"%s" AND subtype:"ha"` | HA member / role events. |

### Extension: FortiGate Policy Generator (ConfGen)
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `EXT_FGT_CONF_GEN` | `false` | Enable the FortiGate Policy Generator extension. |

### Extension: FortiGate Policy Split Advisor (PolSplit)
Requires `GRAYLOG_URL` / `GRAYLOG_TOKEN` (above) — the analysis runs as server-side Graylog aggregations over the firewall's traffic logs.

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `EXT_FGT_POLSPLIT` | `false` | Enable the Policy Split Advisor extension. |
| `GRAYLOG_POLSPLIT_QUERY` | `source:"%s" AND policyid:%s AND _exists_:srcip AND _exists_:dstip` | Traffic-log query template; `source:"%s"` is expanded to the firewall's Graylog source (HA-aware) and `policyid:%s` to the analyzed policy ID. |
| `POLSPLIT_WAN_INTERFACES` | *(Unset)* | Extra interface names to treat as internet-facing (comma-separated), merged with auto-detection (`set role wan`, SD-WAN members, `virtual-wan-link`). Policies whose destination interfaces are all internet-facing keep `dstaddr "all"` instead of enumerating rotating internet IPs. |
| `POLSPLIT_ANALYZE_TIMEOUT` | `55` | Seconds; hard cap on one analyze request so it fails with a clean error instead of a raw reverse-proxy 504. Windows longer than 12h are loaded in parallel 1-hour chunks; raise this (and the proxy read timeout, e.g. nginx `proxy_read_timeout`) for very busy policies, or `0` to disable the cap. |

---

## 🔌 Modules & Extensions

### FGT ADM VPN Config

An optional module (`EXT_ADM_VPN_CONF=true`) for managing customer-specific VPN configurations and device status.

* **Independent storage** — keeps entries in its own SQLite database (`fgt-adm-vpn-conf-db.db`) under the data directory, without bloating PostgreSQL.
* **Config generation** — produces ready-to-apply FortiGate configuration bundles (ZIP) per customer/site, including IPsec phase1/phase2, loopback interface, firewall services/policies, static routes, RADIUS users/groups, and admin profiles.
* **Guided teardown** — deleting an entry opens a modal listing the exact FortiGate CLI needed to remove everything that entry created, gated behind a confirmation checkbox so the device is cleaned up before the entry is deleted.
* **Public status DSV endpoint** — `/fgt-adm-vpn-conf/graylog_dsv` serves raw, unauthenticated status data (`Firewallname;Remote_IP;Status`) for external metrics collectors.
* **Graylog integration** — checks the Graylog API to assert status. A firewall is `online` when logs are found within `GRAYLOG_SEARCH_TIMEFRAME` (default 24 h).
* **HookWise alerting** — sends HTTP webhooks on transition states (`online` ↔ `offline`).

### FortiGate Policy Generator (ConfGen)

An optional module (`EXT_FGT_CONF_GEN=true`) for managing templates and generating firewall policies.

* **Database Configuration Integration** — allows selecting any firewall to load and parse its latest successful backup automatically (decrypting it on-the-fly).
* **Multi-User Isolation** — saves templates per-user by default, with an optional checkbox to save/edit globally.
* **Link Shortener** — generates unique shortened URLs (`/fgt-confgen/s/<shortCode>`) to share templates.

### FortiGate Policy Split Advisor (PolSplit)

An optional module (`EXT_FGT_POLSPLIT=true`) that helps restrict overly-open firewall policies by splitting them into smaller, tightly-scoped ones based on the traffic they actually carry.

* **Log-driven analysis** — pick a firewall and a policy ID, choose a window (30 m – 30 d or a custom range), and the module aggregates the policy's Graylog traffic logs server-side into source/destination/service tuples — complete even for month-long windows on busy policies.
* **Split strategies** — recommendations per service, per destination, and a hybrid strategy that clusters services flowing between strongly overlapping host sets into shared policies; the lowest-footprint strategy is flagged as recommended.
* **Path-based policy naming** — split policies are named after their interface path plus service, e.g. `VL1>VL51 (RDP)`; multiple interfaces sharing a prefix collapse to `XX` (`VL1>VLXX (RDP)`).
* **Object & group reuse, gap list** — existing address/service objects *and* address/service groups from the latest config backup are referenced on exact match (including exact port-range objects); everything missing is listed explicitly ("objects to create") and generated under a configurable name prefix. Adjacent single ports consolidate into range objects (`8080-8082`).
* **Subnet rollup** — optionally collapses many observed hosts in the same subnet (threshold and mask configurable) into one subnet object.
* **Baseline comparison** — optionally compares the analysis window against a preceding baseline window, flagging **new** flows and listing **stale** baseline-only flows that the recommendations would not cover.
* **Internet-aware destinations** — WAN-bound policies (auto-detected from interface roles/SD-WAN membership, operator-extensible) keep `dstaddr "all"` for public destinations instead of enumerating rotating internet IPs; private destinations stay explicit. Vendor-recognized destinations additionally get Internet-Service (ISDB) object suggestions.
* **Traffic-pattern intelligence** — port scans are excluded, RPC endpoint-mapper spreads collapse to one dynamic range, passive-FTP data channels fold into FTP, pairs using ≥100 real ports collapse to a range with a review warning; local-in flows (to the firewall's own addresses) are excluded; well-known ports get readable names; DNS-style tcp+udp pairs merge into dual-protocol objects; recognized bundles (Active Directory, infrastructure services) are tagged.
* **UTM awareness** — destinations whose sessions were blocked by UTM inspection under the analyzed policy are listed for review before being re-allowed.
* **FQDN suggestions** — optional best-effort PTR resolution of observed destinations, offered as candidate FQDN objects (never applied automatically).
* **Ready-to-paste CLI** — emits the full FortiGate configuration in dependency order (addresses → groups → services → policies), clones the original policy's interfaces/NAT/UTM profiles, allocates free policy IDs, wraps multi-VDOM output in the correct `config vdom` context, moves the splits above the original and finally disables (not deletes) it. An optional change-ticket ID is embedded in every generated policy's comments, and an optional explicit **fallthrough deny+log policy** can be placed directly above the disabled original so missed traffic logs loudly instead of dying silently.


---

## 🛠️ Development & Building from Source

Requires **Go 1.26+**. Because the application embeds its static assets and timezone data, CGO is disabled — you can build a native binary without a C toolchain:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o fortisafe ./cmd/fortisafe
./fortisafe
```

### Local Docker Build
```bash
docker build -t fortisafe:local .
```

### Tests & Code Quality
The same checks run in GitHub Actions:
```bash
# Build, vet, and test (with the race detector)
go build ./...
go vet ./...
go test -race ./...

# Formatting and linting
gofmt -l cmd internal extensions
golangci-lint run
```

---

## 🤝 Contributing

1. Fork this repository.
2. Create a feature branch: `git checkout -b feature/my-new-feature`.
3. Commit your changes with descriptive messages: `git commit -m 'feat: add support for X'`.
4. Push to your branch: `git push origin feature/my-new-feature`.
5. Open a Pull Request targeting `main`.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

The bundled JetBrains Mono font is licensed separately under the SIL Open Font License 1.1; see [`internal/web/static/fonts/OFL.txt`](internal/web/static/fonts/OFL.txt).
