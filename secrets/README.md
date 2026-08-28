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
- `known_hosts`: OpenSSH known-host entries for every FortiGate endpoint. Obtain
  and verify each fingerprint through an independent trusted channel; do not
  blindly accept a key discovered over the same network path.

On Linux, the non-root application container needs write permission to the
bind-mounted `backups/` and `data/` directories (UID/GID `65532`). Restrict all
secret files to the deployment account, for example mode `0600`.
