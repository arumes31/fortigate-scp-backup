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

<img width="648" height="720" alt="image" src="https://github.com/user-attachments/assets/f6b34dc6-16ab-4c79-88cb-24231941976b" />
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
1. Clone the repository:
   ```bash
   git clone https://github.com/arumes31/fortigate-scp-backup.git
   cd fortigate-scp-backup
   ```
2. Create necessary directories and set permissions:
   ```bash
   mkdir -p data backups
   chmod -R u+rwX data backups
   ```
3. Build the Docker image:
   ```bash
   docker build -t fortigate-scp-backup .
   ```
4. Run the container with environment variables:
   ```bash
   docker run -d -p 8521:8521 \
       -v $(pwd)/data:/app/data \
       -v $(pwd)/data/backups:/app/backups \
       -e DEFAULT_SCP_USER=scpuser \
       -e DEFAULT_SCP_PASSWORD=scppassword \
       -e FORTIGATE_CONFIG_PATH=sys_config \
       -e MAIL_SERVER=smtp.yourserver.com \
       -e MAIL_PORT=587 \
       -e MAIL_USER=your@email.com \
       -e MAIL_PASSWORD=your_password \
       -e MAIL_RECIPIENT=recipient@example.com \
       --name fortisafe fortigate-scp-backup
   ```
   - Replace `your_default_password`, `smtp.yourserver.com`, `your@email.com`, `your_password`, and `recipient@example.com` with your actual values.
   
### Using Docker Compose
Alternatively, use the following `docker-compose.yml` configuration to run the app:

```yaml
services:
  fortisafe:
    container_name: "fortisafe"
    environment:
      - "DEFAULT_SCP_USER=scpuser"
      - "DEFAULT_SCP_PASSWORD=xxxx"  # Replace with your SCP password
      - "MAIL_SERVER=mail.xxx.com"
      - "MAIL_PORT=25"
      - "MAIL_USER=fortisafe@xxx.com"  # Replace with your mail user
      - "MAIL_PASSWORD=xxxx"  # Replace with your mail password
      - "MAIL_RECIPIENT=xxx@xxx.com"  # Replace with your recipient email
      - "TZ=Europe/Vienna"
    image: "registry.reitetschlaeger.com/fortisafe:latest"
    ports:
      - "8521:8521/tcp"
    volumes:
      - "/container/fortisafe/backups:/app/backups"
      - "/container/fortisafe/data:/app/data"
    restart: unless-stopped
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
