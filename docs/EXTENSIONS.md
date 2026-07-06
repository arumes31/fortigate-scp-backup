# Writing an extension

Extensions are self-contained feature modules that are mounted only when
enabled. They live under `extensions/<name>/` and implement a small interface;
the main app never imports their internals beyond the constructor.

## The contract

```go
// internal/extension/extension.go
type Extension interface {
    Name() string                       // short id for logs
    Prefix() string                     // URL mount point, e.g. "/fgt-adm-vpn-conf"
    Enabled() bool                      // usually gated by an env var
    Mount(r chi.Router, d Deps) error   // register routes + start workers
}

type Deps struct {
    DB            *pgxpool.Pool                   // shared Postgres pool (rarely needed)
    LogActivity   func(user, action, details string) // shared activity_logs
    LoginRequired func(http.Handler) http.Handler    // same session guard as the main app
    CurrentUser   func(*http.Request) string         // logged-in username for a request
    Logger        *slog.Logger
    TZ            *time.Location
    DataDir       string                             // where to keep private storage
}
```

## Lifecycle

1. `cmd/fortisafe` constructs the extension (`New(cfg, logger)`) and registers
   it with the `extension.Registry`.
2. `registry.MountEnabled` calls `Mount` for every extension whose `Enabled()`
   returns true, passing shared `Deps` and a fresh sub-router that is mounted at
   `Prefix()`.
3. Inside `Mount` you typically:
   - open any private storage under `d.DataDir`;
   - create/migrate your schema;
   - register routes, wrapping authenticated ones with `d.LoginRequired` (leave
     public endpoints ungated — e.g. the VPN module's `/graylog_dsv`);
   - start background workers as goroutines.

## Conventions

- Own your storage. The VPN extension uses a private SQLite database rather than
  the shared Postgres store.
- Reuse the design system: link `/static/app.css` and use the same CSS classes
  (`.app`, `.topbar`, `.card`, `table.data`, `.pill`, `.modal`, …) so the module
  matches the rest of the UI.
- Attribute activity via `d.LogActivity(d.CurrentUser(r), action, details)`.
- Read your own configuration from the environment inside the extension (keep it
  namespaced) rather than adding fields to the global config where possible.

## Reference implementation

`extensions/fgt_adm_vpn_conf` is the canonical example: private SQLite DB with
idempotent migrations, a config-bundle (ZIP) generator, CSV import/export, a
public Graylog DSV endpoint, and a background Graylog status worker that emits
HookWise up/down events on state transitions.
