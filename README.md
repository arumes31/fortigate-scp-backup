Web application for backing up FortiGate firewall configurations using SCP.

## Features
- **Firewall Management**: Add, delete, and manage multiple FortiGate firewalls with customizable SSH credentials and backup intervals.
- **Automated Backups**: Schedule periodic backups with retention policies using APScheduler.
- **Backup History**: View and download previous backup configurations.
- **Error Logging**: Monitor failed backup attempts with detailed logs.
- **Email Notifications**: Receive alerts for backup failures via SMTP (configurable via environment variables).
- **Reverse Proxy Support**: Compatible with reverse proxies using X-Forwarded headers.
- **Session Management**: Automatic logout after 1 hour or on IP address change.

## Screenshots

![login](https://github.com/user-attachments/assets/5929f9ae-e4e2-4b25-911d-c5e102bc5f06)
<img width="1515" height="801" alt="image" src="https://github.com/user-attachments/assets/3ef6e5f3-c48a-49dd-a15e-434151df3e06" />
<img width="1561" height="690" alt="image" src="https://github.com/user-attachments/assets/02600e20-8cce-42f8-af32-cd65466662af" />


## Prerequisites
- Docker
- Access to a FortiGate firewall with SSH and SCP enabled
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
Alternatively, use the following `docker-compose.yml` configuration to run the app:

```yaml
services:
  fortisafe-app:
    container_name: "fortisafe-app"
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
    image: "registry.reitetschlaeger.com/fortisafe:latest"
    ports:
      - "8521:8521/tcp"
    volumes:
      - "/mnt/.../backups:/app/backups"
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
- `TZ`: Timezone (default: `Europe\Vienna`).
- `TOTP_ENABLED`: Enable TOTP authentication for the admin user (default: `false`).
- `TOTP_SECRET`: TOTP secret key for the admin user (`false` 16 characters - default: `random-not-displayed`)
- `RADIUS_ENABLED`: Enable RADIUS authentication (default: `false`).
- `RADIUS_SERVER`: RADIUS server address (default: `localhost`).
- `RADIUS_PORT`: RADIUS server port (default: `1812`).
- `RADIUS_SECRET`: RADIUS shared secret (default: `secret`).
- `DEFAULT_SCP_USER`: Default SCP username (default: `test`).
- `DEFAULT_SCP_PASSWORD`: Default SCP password.
- `FORTIGATE_CONFIG_PATH`: Path to the configuration file on the FortiGate (default: `sys_config`).
- `MAIL_SERVER`: SMTP server address (default: `smtp.example.com`).
- `MAIL_PORT`: SMTP port (default: `587`).
- `MAIL_USER`: SMTP username (default: `user@example.com`).
- `MAIL_PASSWORD`: SMTP password.
- `MAIL_RECIPIENT`: Email recipient for failure notifications (default: value of `MAIL_USER`).
- `PG_HOST`: fortisafe-db
- `PG_PORT`: 5432
- `PG_USER`: postgre
- `PG_PASSWORD`: XXXXXXTDB
- `PG_DATABASE`: firewall_backups

DB: 
- `POSTGRES_USER`: postgre
- `POSTGRES_PASSWORD`: XXXXXXTDB
- `POSTGRES_DB`: firewall_backups

## Generate TOTP SECRET

Powershell:
```
# Define the Base32 alphabet (A-Z, 2-7)
$base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

# Function to generate a random Base32 key
function Generate-Base32Key {
    $keyLength = 16  # Standard length for pyotp.random_base32()
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
- **Backup Fails**: Check logs for detailed errors (e.g., SSH/SCP issues). Ensure the FortiGate allows SCP and the config path is correct.
- **Timeout Issues**: Increase the keep-alive interval by modifying `app.py` if network latency is high.
- **Email Not Sent**: Verify SMTP credentials and server accessibility.

## Contributing
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m "Add feature-name"`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
