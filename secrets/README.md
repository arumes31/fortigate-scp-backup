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

The optional `fgt_conftail` extension does not require another secret file when
`FGT_CONFTAIL_HOOKWISE_TOKEN` is set directly. To use the file fallback instead,
create `fgt_conftail_hookwise_token`, then uncomment its service secret mount,
top-level secret declaration, and `FGT_CONFTAIL_HOOKWISE_TOKEN_FILE` entry in
the selected Compose file. A non-empty direct token takes precedence when both
forms are configured.

SSH host keys are persisted automatically in `data/ssh_known_hosts`. A first
connection learns an unknown key; a changed key is rejected until its detected
fingerprint is explicitly accepted in the firewall UI.

On Linux, Compose file-backed secrets are bind mounts: local Compose does not
remap their owner or mode. Make the mandatory files root-owned, group-readable
by the application's GID `65532`, and unreadable to everyone else:

```bash
sudo chown 0:65532 \
  ./secrets/postgres_password \
  ./secrets/session_key \
  ./secrets/encryption_key \
  ./secrets/bootstrap_admin_password \
  ./secrets/totp_secret \
  ./secrets/radius_secret
sudo chmod 0440 \
  ./secrets/postgres_password \
  ./secrets/session_key \
  ./secrets/encryption_key \
  ./secrets/bootstrap_admin_password \
  ./secrets/totp_secret \
  ./secrets/radius_secret
stat -c '%u:%g %a %n' ./secrets/{postgres_password,session_key,encryption_key,bootstrap_admin_password,totp_secret,radius_secret}
```

The files should report owner/group/mode `0:65532 440`; the application runs as
`65532:65532`. The official PostgreSQL image reads its one root-owned mounted
password during its root entrypoint setup before dropping privileges. Apply the
same owner and `0440` mode to `fgt_conftail_hookwise_token` when using that
optional `_FILE` fallback. The deployment account will need `sudo` to replace
these files after ownership is hardened.
