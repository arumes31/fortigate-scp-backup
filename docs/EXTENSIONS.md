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

## graylog_device_data

`extensions/graylog_device_data` (mounted at `/graylog-devices`, enabled via
`EXT_GRAYLOG_DEVICE_DATA=true`) feeds the topology page with the client
devices seen behind managed FortiSwitches:

- A background worker runs every `GRAYLOG_DEVICE_INTERVAL` seconds (default
  3600). For every firewall whose latest audited configuration manages
  FortiSwitches (read from the core insights cache), it queries Graylog
  (`GRAYLOG_URL`/`GRAYLOG_TOKEN`) with the `GRAYLOG_DEVICE_QUERY` template
  (default `source:"%s" AND mac:*`, `%s` = the firewall's short hostname)
  over the last `GRAYLOG_DEVICE_RANGE` seconds, staggering firewalls across
  the interval.
- Messages are normalized into devices (MAC, IP, VLAN, switch port, switch
  serial, hostname, last seen); several FortiGate field aliases are accepted
  (`mac`/`srcmac`, `ip`/`assignedip`/`srcip`, `vlan`/`vlanid`,
  `portname`/`port`/`srcintf`, `switchid`/`sn`, …).
- The inventory lives in a private SQLite DB (`graylog-device-data.db`).
- API: `GET /graylog-devices/data/{fwID}` returns the stored inventory with
  `shared_mac` / `shared_ip` flags (one MAC seen with several IPs, one IP
  behind several MACs); `POST /graylog-devices/refresh/{fwID}` fetches from
  Graylog immediately ("fetch device data now" in the topology view).
- The topology page renders devices under their switch's VLAN group with the
  device's VLAN badge, and highlights shared MAC/IP devices with a red dashed
  border. When the extension is disabled the topology simply omits devices.
