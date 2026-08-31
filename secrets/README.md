# Runtime secrets

Create these files locally before starting either Compose stack. They are
ignored by Git and excluded from container build contexts.

- `postgres_password`: a strong PostgreSQL password.
- `session_key`: at least 32 random bytes.
- `encryption_key`: exactly 32 random bytes encoded as base64 or hex. Keep an
  offline recovery copy; losing it makes existing credentials and backups
  unrecoverable.
- `bootstrap_admin_password`: at least 16 bytes. It is used only when the
  database does not yet contain the `admin` account.
- `totp_secret`: a stable Base32 TOTP secret when TOTP is enabled; it may be an
  empty file while TOTP is disabled.
- `radius_secret`: at least 16 bytes when RADIUS is enabled; it may be an empty
  file while RADIUS is disabled.

SSH host keys are persisted automatically in `data/ssh_known_hosts`. A first
connection learns an unknown key; a changed key is rejected until its detected
fingerprint is explicitly accepted in the firewall UI.

On Linux, the non-root application container needs write permission to the
bind-mounted `backups/` and `data/` directories (UID/GID `65532`). Restrict all
secret files to the deployment account, for example mode `0600`.
