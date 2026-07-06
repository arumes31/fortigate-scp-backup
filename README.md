# FortiSafe

Web application for backing up FortiGate firewall configurations over SCP.

Rewritten in **Go**: it ships as a single, fully static binary (`fortisafe`) with
all HTML templates and static assets embedded via Go `embed` and the timezone
database embedded via `time/tzdata`. It runs as **one process** — the HTTP
server, the backup scheduler and every extension background worker are
goroutines. There is no gunicorn, no Python runtime, and no worker/thread tuning
to get right. Existing deployments can swap in place: the same environment
variables are honored and it is drop-in compatible with your existing
PostgreSQL (main store) and SQLite (extension) data.

## Features
- **Firewall Management**: Add, delete, and manage multiple FortiGate firewalls with customizable SSH credentials and backup intervals.
- **Automated Backups**: Schedule periodic backups with retention policies. On startup the scheduler is rebuilt from the `firewalls` table (job startup is staggered), so there is no separate job store to maintain.
- **Backup History**: View and download previous backup configurations.
- **Error Logging**: Monitor failed backup attempts with detailed logs.
- **Email Notifications**: Receive alerts for backup failures via SMTP (configurable via environment variables).
- **Authentication**: Local admin login with optional TOTP, plus optional RADIUS authentication (no external RADIUS dictionary file required).
- **Reverse Proxy Support**: Compatible with reverse proxies using X-Forwarded headers.
- **Session Management**: Automatic logout after 1 hour or on IP address change.

## Screenshots

![login](https://github.com/user-attachments/assets/5929f9ae-e4e2-4b25-911d-c5e102bc5f06)
<img width="1515" height="801" alt="image" src="https://github.com/user-attachments/assets/3ef6e5f3-c48a-49dd-a15e-434151df3e06" />
<img width="1561" height="690" alt="image" src="https://github.com/user-attachments/assets/02600e20-8cce-42f8-af32-cd65466662af" />

## Prerequisites
- Docker (or the Go toolchain if building from source — see [Build from source](#build-from-source)).
- A reachable PostgreSQL database (a companion service is included in `docker-compose.yml`).
- Access to a FortiGate firewall with SSH and SCP enabled.
```
config system global
    set admin-scp enable
end
```
- scp profile
```
config system accprofile
    edit "scp-profile"
        set comments "https://community.fortinet.com/t5/FortiGate/Technical-Tip-Backing-Up-the-FortiGate-configuration-file-via/ta-p/367088"
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
```
- scp user
```
config system admin
    edit "scpuser"
        set accprofile "scp-profile"
        set password xxxxxxxXCHANGEMExxxxx
    next
end
```

## Installation
### Using Docker Compose
Use the provided [`docker-compose.yml`](docker-compose.yml). It defines two
services: the `fortisafe-app` container and a `fortisafe-db` PostgreSQL
companion (the app waits for the DB healthcheck before starting).

```yaml
services:
  fortisafe-app:
    container_name: "fortisafe-app"
    # Pre-built image from GitHub Container Registry...
    image: "ghcr.io/arumes31/fortigate-scp-backup:latest"
    # ...or build locally instead (comment out `image:` above):
    # build: .
    environment:
      - "DEFAULT_SCP_USER=fortisafe"
      - "DEFAULT_SCP_PASSWORD=XXXXXX"
      - "TOTP_ENABLED=true"
      - "TOTP_SECRET=XXXXXX"
      - "MAIL_SERVER=smtp.test.com"
      - "MAIL_PORT=25"
      - "MAIL_USER=fortisafe@test.com"
      - "MAIL_PASSWORD=XXXXXX"
      - "MAIL_RECIPIENT=user1@test.com"
      - "TZ=Europe/Vienna"
      - "RADIUS_ENABLED=true"
      - "RADIUS_PORT=1812"
      - "RADIUS_SECRET=fortisafe-XXXXXX"
      - "RADIUS_SERVER=192.168.0.100"
      - "PG_HOST=fortisafe-db"
      - "PG_PORT=5432"
      - "PG_USER=postgre"
      - "PG_PASSWORD=XXXXXXTDB"
      - "PG_DATABASE=firewall_backups"
      - "EXT_ADM_VPN_CONF=true"
    ports:
      - "8521:8521/tcp"
    volumes:
      - "/mnt/.../backups:/app/backups"
      - "/mnt/.../data_fgt-adm-vpn-conf:/app/data"
    restart: unless-stopped
    depends_on:
      fortisafe-db:
        condition: service_healthy
        restart: true

  fortisafe-db:
    container_name: "fortisafe-db"
    image: postgres:latest
    environment:
      - "POSTGRES_USER=postgre"
      - "POSTGRES_PASSWORD=XXXXXXTDB"
      - "POSTGRES_DB=firewall_backups"
    restart: unless-stopped
    volumes:
      - "/mnt/.../data:/var/lib/postgresql/data"
    healthcheck:
          test: ["CMD-SHELL", "pg_isready -U postgre -d firewall_backups"]
          interval: 5s
          timeout: 5s
          retries: 5
```

Then run:
```
docker compose up -d
```

Two volumes are used by the app:
- `/app/backups` — the backup files (`BACKUP_DIR`, default relative `backups`).
- `/app/data` — the extension SQLite database `fgt-adm-vpn-conf-db.db` (`DATA_DIR`, default `/app/data`).

The container runs as root so bind-mounted host volumes stay writable; the
binary creates both directories at startup if they do not already exist.

## Build from source
The app is a standard Go module (`github.com/arumes31/fortigate-scp-backup`)
with the entrypoint under `cmd/fortisafe`. It uses the pure-Go SQLite
driver (`modernc.org/sqlite`), so **CGO is not required**.

Build a native binary:
```
CGO_ENABLED=0 go build -ldflags="-s -w" -o fortisafe ./cmd/fortisafe
./fortisafe
```

Build the container image:
```
docker build -t fortisafe:local .
```

The image is multi-stage: `golang:1.26` compiles a fully static binary, and the
final image is `gcr.io/distroless/static-debian12` (just the binary + CA
certificates). The listening port is **8521**.

## Modules
### FGT ADM VPN Config
This module provides a way to manage and generate VPN configurations for FortiGate firewalls.
- **Enabled via**: `EXT_ADM_VPN_CONF=true` environment variable.
- **Storage**: Uses a self-contained SQLite database at `${DATA_DIR}/fgt-adm-vpn-conf-db.db` (pure-Go driver, no cgo).
- **CID**: Each VPN config requires a `CID` (customer/contract identifier) field.
- **Public Graylog Endpoint**: `/fgt-adm-vpn-conf/graylog_dsv` — Serves DSV data (`Firewallname;Remote_IP;Status`) without authentication for Graylog integration. Supports cluster hostnames (multiple entries per VPN config if `cluster_hostnames` is set).
- **Graylog Status Monitoring**: A background worker (goroutine) periodically checks Graylog for recent logs from each device (a device is `online` if any log exists for its hostname within `GRAYLOG_SEARCH_TIMEFRAME`).
- **HookWise Up/Down Events**: When a device transitions between `online` and `offline`, an UP/DOWN event is sent to [HookWise](https://github.com/arumes31/hookwise). Configured via `HOOKWISE_URL` and `HOOKWISE_TOKEN`; if unset, event sending is skipped.

## Usage
1. Access the app at `http://localhost:8521` (or your reverse proxy URL).
2. Log in with the default credentials:
   - Username: `admin`
   - Password: `changeme`
   - **Note**: You must change the password on first login.
3. Add a new firewall by clicking "Add New Firewall", filling in the details, and submitting.
4. Schedule backups or trigger manual backups via the "Backup Now" button.
5. View backup history or error logs from the respective links.
6. Change your password via the "Change Password" button in the top-right corner.

## Configuration
APP:
Environment variables can be set to customize the app:
- `TZ`: Timezone (default: `Europe/Vienna`).
- `TOTP_ENABLED`: Enable TOTP authentication for the admin user (default: `false`).
- `TOTP_SECRET`: TOTP secret key (Base32, 16 characters). If unset, a random secret is generated at startup and not displayed.
- `RADIUS_ENABLED`: Enable RADIUS authentication (default: `false`).
- `RADIUS_SERVER`: RADIUS server address (default: `localhost`).
- `RADIUS_PORT`: RADIUS server port (default: `1812`).
- `RADIUS_SECRET`: RADIUS shared secret (default: `secret`).
- `DEFAULT_SCP_USER`: Default SCP username (default: `test`).
- `DEFAULT_SCP_PASSWORD`: Default SCP password.
- `FORTIGATE_CONFIG_PATH`: Path to the configuration file on the FortiGate (default: `sys_config`).
- `SCP_TIMEOUT`: SCP/SSH timeout in seconds (default: `60`).
- `MAIL_SERVER`: SMTP server address (default: `smtp.example.com`).
- `MAIL_PORT`: SMTP port (default: `587`).
- `MAIL_USER`: SMTP username (default: `user@example.com`).
- `MAIL_PASSWORD`: SMTP password.
- `MAIL_RECIPIENT`: Email recipient for failure notifications (default: value of `MAIL_USER`).
- `GRAYLOG_URL`: Graylog API URL for status checks (e.g., `https://graylog.example.com`).
- `GRAYLOG_TOKEN`: Graylog API token for authentication.
- `GRAYLOG_SEARCH_TIMEFRAME`: Time in seconds to check for recent logs (default: `86400`). A device is considered `online` if any log exists for its hostname within this timeframe.
- `HOOKWISE_URL`: Full HookWise webhook URL (e.g., `https://hookwise.example.com/webhook/<endpoint_id>`). Up/down events are sent here on device status transitions. Leave unset to disable.
- `HOOKWISE_TOKEN`: HookWise bearer token for authentication.
- `EXT_ADM_VPN_CONF`: Enable the FGT ADM VPN Config module (default: `false`).
- `PORT`: HTTP listen port (default: `8521`).
- `BACKUP_DIR`: Directory for backup files (default: `backups`, i.e. `/app/backups` in the container).
- `DATA_DIR`: Directory for the extension SQLite database (default: `/app/data`).
- `PG_HOST`: PostgreSQL host (e.g., `fortisafe-db`).
- `PG_PORT`: PostgreSQL port (default: `5432`).
- `PG_USER`: PostgreSQL user (e.g., `postgre`).
- `PG_PASSWORD`: PostgreSQL password.
- `PG_DATABASE`: PostgreSQL database name (e.g., `firewall_backups`).

DB:
- `POSTGRES_USER`: postgre
- `POSTGRES_PASSWORD`: XXXXXXTDB
- `POSTGRES_DB`: firewall_backups

## Generate TOTP SECRET

The `TOTP_SECRET` is a standard 16-character Base32 key. Any Base32 generator
works; for example, in PowerShell:
```
# Define the Base32 alphabet (A-Z, 2-7)
$base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

# Function to generate a random Base32 key
function Generate-Base32Key {
    $keyLength = 16  # Standard 16-character Base32 secret
    $randomKey = -join (1..$keyLength | ForEach-Object {
        $base32Alphabet[(Get-Random -Minimum 0 -Maximum $base32Alphabet.Length)]
    })
    return $randomKey
}

# Generate and output the key
$key = Generate-Base32Key
Write-Output $key
```

## Bulk Upload

CSV Content:
```fqdn,username,password,interval_minutes,retention_count,ssh_port
fqdn,username,password,interval_minutes,retention_count,ssh_port
firewall1.example.com,username,password,180,300,9422
firewall2.example.com,username,password,60,600,22
```
`username` and `password`: Optional, default to `DEFAULT_SCP_USER` and `DEFAULT_SCP_PASSWORD` if empty.

## Troubleshooting
- **Backup Fails**: Check the container logs for detailed errors (e.g., SSH/SCP issues). Ensure the FortiGate allows SCP and the config path (`FORTIGATE_CONFIG_PATH`) is correct.
- **Timeout Issues**: Increase `SCP_TIMEOUT` (seconds) if network latency is high.
- **Email Not Sent**: Verify SMTP credentials and server accessibility.
- **Database**: Ensure PostgreSQL is reachable (`PG_HOST`/`PG_PORT`/credentials); the app initializes/migrates the schema on startup.

## Contributing
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m "Add feature-name"`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
