Web application for backing up FortiGate firewall configurations using SCP.

## Features
- **Firewall Management**: Add, delete, and manage multiple FortiGate firewalls with customizable SSH credentials and backup intervals.
- **Automated Backups**: Schedule periodic backups with retention policies using APScheduler.
- **Backup History**: View and download previous backup configurations.
- **Error Logging**: Monitor failed backup attempts with detailed logs.
- **Email Notifications**: Receive alerts for backup failures via SMTP (configurable via environment variables).
- **Reverse Proxy Support**: Compatible with reverse proxies using X-Forwarded headers.
- **Session Management**: Automatic logout after 1 hour or on IP address change.

## Prerequisites
- Docker
- Access to a FortiGate firewall with SSH and SCP enabled

config system global
    set admin-scp enable

end

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/fortigate-scp-backup.git
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
       -e DEFAULT_SCP_USER=test \
       -e DEFAULT_SCP_PASSWORD=your_default_password \
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
- `DEFAULT_SCP_USER`: Default SCP username (default: `test`).
- `DEFAULT_SCP_PASSWORD`: Default SCP password.
- `FORTIGATE_CONFIG_PATH`: Path to the configuration file on the FortiGate (default: `sys_config`).
- `MAIL_SERVER`: SMTP server address (default: `smtp.example.com`).
- `MAIL_PORT`: SMTP port (default: `587`).
- `MAIL_USER`: SMTP username (default: `user@example.com`).
- `MAIL_PASSWORD`: SMTP password.
- `MAIL_RECIPIENT`: Email recipient for failure notifications (default: value of `MAIL_USER`).

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