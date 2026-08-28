// Package config loads all runtime configuration from environment variables,
// preserving the runtime variable names of the original Python application
// while requiring stable secrets and encrypted storage for secure deployments.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds every tunable value the application reads from the environment.
type Config struct {
	// PostgreSQL (shared main store)
	PGHost     string
	PGPort     string
	PGUser     string
	PGPassword string
	PGDatabase string
	PGSSLMode  string
	// Pool / connection tuning.
	PGMaxConns       int
	PGConnectRetries int
	PGConnectBackoff time.Duration

	// Authentication
	TOTPEnabled   bool
	TOTPSecret    string
	RadiusEnabled bool
	RadiusServer  string
	RadiusPort    int
	RadiusSecret  string
	// Brute-force protection.
	LoginMaxAttempts       int
	LoginLockoutMinutes    int
	BootstrapAdminPassword string

	// Sessions / cookies
	SessionKey   []byte // derived from SESSION_KEY; nil => random per start
	CookieSecure bool
	EnableHSTS   bool
	// TrustProxyHeaders lets the client-IP lookup honour X-Forwarded-For. Enable
	// it only when the app sits behind a trusted reverse proxy that sets the
	// header; otherwise a direct client can spoof it (e.g. to defeat the login
	// rate limiter).
	TrustProxyHeaders bool

	// Encryption at rest (firewall credentials + backup files).
	EncryptionKey []byte
	// SSHKnownHostsFile is an OpenSSH known_hosts file whose fingerprints are
	// verified for every FortiGate SSH/SCP connection.
	SSHKnownHostsFile string

	// SCP / backup defaults
	DefaultSCPUser       string
	DefaultSCPPassword   string
	FortigateConfigPath  string
	SCPTimeout           int // seconds
	MaxConcurrentBackups int
	CSVMaxBytes          int64

	// Mail
	MailServer    string
	MailPort      int
	MailUser      string
	MailPassword  string
	MailRecipient string

	// Extension: fgt_adm_vpn_conf
	ExtAdmVpnConf          bool
	ExtFgtConfGen          bool
	GraylogURL             string
	GraylogToken           string
	GraylogSearchTimeframe string
	HookwiseURL            string
	HookwiseToken          string

	// Extension: graylog_device_data (switch client inventory for the topology)
	ExtGraylogDeviceData  bool
	GraylogDeviceQuery    string // Graylog query template, %s = source host
	GraylogStpQuery       string // Graylog query template for FortiSwitch STP/link events, %s = source host
	GraylogTopoQuery      string // trunk-named FortiSwitch STP events for switch-interlink (topology) detection, %s = source host
	GraylogLinkQuery      string // FortiSwitch port link up/down events for the latest-per-port aggregation, %s = source host
	GraylogMacQuery       string // FortiSwitch MAC add/move/delete + NAC device add/delete events (device→switch-port), %s = source host
	GraylogWifiQuery      string // wireless client↔AP↔SSID association events, %s = source host
	GraylogVpnQuery       string // IPsec/SSL VPN tunnel up/down events, %s = source host
	GraylogHaQuery        string // HA member/role events, %s = source host
	GraylogDeviceRange    string // seconds of log history to scan per fetch
	GraylogTopoRange      string // seconds of history for the sparse switch-interlink query (wider than the device window)
	GraylogLinkRange      string // seconds of history for the latest-per-port link-state aggregation (wide, like the topo window)
	GraylogDeviceInterval int    // background refresh interval in seconds

	// Extension: fgt_polsplit (policy split advisor — analyze a policy's real
	// traffic from Graylog and recommend tighter replacement policies)
	ExtFgtPolSplit         bool
	GraylogPolsplitQuery   string // Graylog query template, %s = source host, policyid:%s = policy ID
	PolsplitWANInterfaces  string // extra interface names to treat as internet-facing (comma-separated), merged with auto-detection
	PolsplitAnalyzeTimeout int    // seconds; hard cap on one analyze request so it fails cleanly before a reverse-proxy 504 (0 = no cap)

	// Extension: fgt_confconv (configuration conversions — chained structural
	// migration recipes: interfaces->FortiLink, WAN interfaces->SD-WAN,
	// interface-based->zone-based policies, SD-WAN static routes->SD-WAN rules)
	ExtFgtConfConv bool

	// Live SSH diagnostics: query the FortiGate CLI directly for authoritative
	// per-switch-port link state, STP role/state and interlink trunks (data the
	// logs only reveal partially). Reuses each firewall's stored SSH credentials.
	FgtDiagSSHEnabled       bool // FGT_DIAG_SSH_ENABLED: turn the SSH diagnostics collector on
	FgtDiagSSHBackgroundSec int  // background sweep cadence per device (seconds)
	FgtDiagSSHViewSec       int  // min spacing when the topology page triggers a query (seconds)
	FgtDiagSSHFloorSec      int  // hard rate floor between query starts (seconds); one query per device runs at a time regardless
	FgtDiagSSHTimeoutSec    int  // overall SSH session timeout per device (seconds)

	// CVE auto-update: the audit engine's CVE findings are matched against a
	// live dataset (NVD CPE search + CISA KEV) instead of a hand-maintained
	// table, refreshed on this interval plus a manual "Refresh now" button on
	// the audit page. Defaults to false like every other outbound-integration
	// flag in this config (Graylog, SSH diagnostics, extensions) — an operator
	// opts in explicitly rather than this tool silently starting to call out to
	// NVD/CISA. The manual refresh button always works regardless of this
	// flag, since that's an explicit operator action, not a background one.
	// NVDAPIKey is optional (raises NVD's keyless 5 req/30s limit to 50 req/30s).
	CVEAutoUpdate   bool
	CVERefreshHours int
	NVDAPIKey       string

	// Housekeeping
	ActivityLogRetentionDays int

	// General
	TZ        *time.Location
	BackupDir string
	DataDir   string
	Port      string
	LogLevel  string
}

// Load reads the environment and returns a populated Config. It never fails;
// missing values fall back to the same defaults the Python app used.
func Load(logger *slog.Logger) *Config {
	tzName := getenv("TZ", "Europe/Vienna")
	tz, err := time.LoadLocation(tzName)
	if err != nil {
		logger.Warn("failed to load timezone, falling back to UTC", "tz", tzName, "err", err)
		tz = time.UTC
	}

	totpSecret := secretEnv("TOTP_SECRET", logger)

	c := &Config{
		PGHost:           getenv("PG_HOST", "localhost"),
		PGPort:           getenv("PG_PORT", "5432"),
		PGUser:           getenv("PG_USER", "your_user"),
		PGPassword:       secretEnv("PG_PASSWORD", logger),
		PGDatabase:       getenv("PG_DATABASE", "firewall_backups"),
		PGSSLMode:        getenv("PGSSLMODE", "prefer"),
		PGMaxConns:       intenv("PG_MAX_CONNS", 50),
		PGConnectRetries: intenv("PG_CONNECT_RETRIES", 10),
		PGConnectBackoff: time.Duration(intenv("PG_CONNECT_BACKOFF_SECONDS", 3)) * time.Second,

		TOTPEnabled:            boolenv("TOTP_ENABLED", false),
		TOTPSecret:             totpSecret,
		RadiusEnabled:          boolenv("RADIUS_ENABLED", false),
		RadiusServer:           getenv("RADIUS_SERVER", "localhost"),
		RadiusPort:             intenv("RADIUS_PORT", 1812),
		RadiusSecret:           secretEnv("RADIUS_SECRET", logger),
		LoginMaxAttempts:       intenv("LOGIN_MAX_ATTEMPTS", 5),
		LoginLockoutMinutes:    intenv("LOGIN_LOCKOUT_MINUTES", 15),
		BootstrapAdminPassword: secretEnv("BOOTSTRAP_ADMIN_PASSWORD", logger),

		SessionKey:        deriveOrNil(secretEnv("SESSION_KEY", logger)),
		CookieSecure:      boolenv("COOKIE_SECURE", false),
		EnableHSTS:        boolenv("ENABLE_HSTS", false),
		TrustProxyHeaders: boolenv("TRUST_PROXY_HEADERS", false),

		EncryptionKey:     decodeKey(secretEnv("ENCRYPTION_KEY", logger), logger),
		SSHKnownHostsFile: os.Getenv("SSH_KNOWN_HOSTS_FILE"),

		DefaultSCPUser:       getenv("DEFAULT_SCP_USER", "fortisafe"),
		DefaultSCPPassword:   secretEnv("DEFAULT_SCP_PASSWORD", logger),
		FortigateConfigPath:  getenv("FORTIGATE_CONFIG_PATH", "sys_config"),
		SCPTimeout:           intenv("SCP_TIMEOUT", 60),
		MaxConcurrentBackups: intenv("MAX_CONCURRENT_BACKUPS", 10),
		CSVMaxBytes:          int64(intenv("CSV_MAX_BYTES", 5<<20)),

		MailServer:    getenv("MAIL_SERVER", "smtp.example.com"),
		MailPort:      intenv("MAIL_PORT", 587),
		MailUser:      getenv("MAIL_USER", "user@example.com"),
		MailPassword:  secretEnv("MAIL_PASSWORD", logger),
		MailRecipient: getenv("MAIL_RECIPIENT", getenv("MAIL_USER", "user@example.com")),

		ExtAdmVpnConf:          boolenv("EXT_ADM_VPN_CONF", false),
		ExtFgtConfGen:          boolenv("EXT_FGT_CONF_GEN", false),
		GraylogURL:             os.Getenv("GRAYLOG_URL"),
		GraylogToken:           secretEnv("GRAYLOG_TOKEN", logger),
		GraylogSearchTimeframe: getenv("GRAYLOG_SEARCH_TIMEFRAME", "86400"),
		HookwiseURL:            os.Getenv("HOOKWISE_URL"),
		HookwiseToken:          secretEnv("HOOKWISE_TOKEN", logger),

		ExtGraylogDeviceData: boolenv("EXT_GRAYLOG_DEVICE_DATA", false),
		GraylogDeviceQuery:   getenv("GRAYLOG_DEVICE_QUERY", `source:"%s" AND (mac:* OR srcmac:* OR macaddr:*)`),
		GraylogStpQuery:      getenv("GRAYLOG_STP_QUERY", `source:"%s" AND subtype:"switch-controller" AND (logdesc:"FortiSwitch spanning Tree" OR logdesc:"FortiSwitch port status" OR logdesc:"FortiSwitch link" OR logdesc:"FortiSwitch switch" OR msg:bpdu OR msg:"loop guard" OR msg:"loop-guard" OR msg:"root guard" OR msg:"root-guard" OR msg:"status up" OR msg:"status down")`),
		// Interlinks change rarely, so the short device window catches them only
		// for whichever switch recently churned. This focused query keeps just the
		// trunk-named STP events (the ones that resolve a peer) so a much wider
		// window stays cheap and captures every switch's stable uplinks.
		GraylogTopoQuery: getenv("GRAYLOG_TOPO_QUERY", `source:"%s" AND subtype:"switch-controller" AND logdesc:"FortiSwitch spanning Tree" AND NOT switchphysicalport:/port[0-9]+/`),
		// A handful of flapping ports can emit tens of thousands of link events a
		// day, so a capped message fetch only ever returns those few ports and the
		// stable up/down state of every other port is crowded out. This query feeds
		// a server-side aggregation (latest status per switch+port) instead, so one
		// row per port is returned regardless of event volume.
		GraylogLinkQuery:      getenv("GRAYLOG_LINK_QUERY", `source:"%s" AND subtype:"switch-controller" AND (status:"up" OR status:"down") AND _exists_:switchphysicalport`),
		GraylogMacQuery:       getenv("GRAYLOG_MAC_QUERY", `source:"%s" AND (logid:0115032615 OR logid:0115032617 OR logid:0115032616 OR logid:0115022861 OR logid:0115022862)`),
		GraylogWifiQuery:      getenv("GRAYLOG_WIFI_QUERY", `source:"%s" AND subtype:"wireless" AND stamac:* AND (ssid:* OR ap:*)`),
		GraylogVpnQuery:       getenv("GRAYLOG_VPN_QUERY", `source:"%s" AND subtype:"vpn" AND tunnelid:*`),
		GraylogHaQuery:        getenv("GRAYLOG_HA_QUERY", `source:"%s" AND subtype:"ha"`),
		GraylogDeviceRange:    getenv("GRAYLOG_DEVICE_RANGE", "86400"),
		GraylogTopoRange:      getenv("GRAYLOG_TOPO_RANGE", "2592000"),
		GraylogLinkRange:      getenv("GRAYLOG_LINK_RANGE", "2592000"),
		GraylogDeviceInterval: intenv("GRAYLOG_DEVICE_INTERVAL", 3600),

		ExtFgtPolSplit:         boolenv("EXT_FGT_POLSPLIT", false),
		GraylogPolsplitQuery:   getenv("GRAYLOG_POLSPLIT_QUERY", `source:"%s" AND policyid:%s AND _exists_:srcip AND _exists_:dstip`),
		PolsplitWANInterfaces:  getenv("POLSPLIT_WAN_INTERFACES", ""),
		PolsplitAnalyzeTimeout: intenv("POLSPLIT_ANALYZE_TIMEOUT", 55),

		ExtFgtConfConv: boolenv("EXT_FGT_CONFCONV", false),

		FgtDiagSSHEnabled:       boolenv("FGT_DIAG_SSH_ENABLED", false),
		FgtDiagSSHBackgroundSec: intenv("FGT_DIAG_SSH_BACKGROUND_SECONDS", 3600), // hourly background sweep
		FgtDiagSSHViewSec:       intenv("FGT_DIAG_SSH_VIEW_SECONDS", 1200),       // ≥20 min between page-triggered queries
		FgtDiagSSHFloorSec:      intenv("FGT_DIAG_SSH_FLOOR_SECONDS", 2),         // min 2 s between query starts (and only one at a time per device)
		FgtDiagSSHTimeoutSec:    intenv("FGT_DIAG_SSH_TIMEOUT_SECONDS", 180),

		CVEAutoUpdate:   boolenv("CVE_AUTOUPDATE", false),
		CVERefreshHours: intenv("CVE_REFRESH_HOURS", 24),
		NVDAPIKey:       secretEnv("NVD_API_KEY", logger),

		ActivityLogRetentionDays: intenv("ACTIVITY_LOG_RETENTION_DAYS", 0),

		TZ:        tz,
		BackupDir: getenv("BACKUP_DIR", "backups"),
		DataDir:   getenv("DATA_DIR", "/app/data"),
		Port:      getenv("PORT", "8521"),
		LogLevel:  getenv("LOG_LEVEL", "info"),
	}
	if c.MaxConcurrentBackups < 1 {
		c.MaxConcurrentBackups = 1
	}
	if c.PGMaxConns < 1 {
		c.PGMaxConns = 1
	}
	return c
}

// ValidateRuntime rejects insecure or unstable production configuration before
// any network listener or database migration is started.
func (c *Config) ValidateRuntime() error {
	var errs []error
	if c.PGPassword == "" {
		errs = append(errs, errors.New("PG_PASSWORD or PG_PASSWORD_FILE is required"))
	}
	if len(c.SessionKey) < 32 {
		errs = append(errs, errors.New("SESSION_KEY or SESSION_KEY_FILE must contain at least 32 bytes"))
	}
	if len(c.EncryptionKey) != 32 {
		errs = append(errs, errors.New("ENCRYPTION_KEY or ENCRYPTION_KEY_FILE must decode to exactly 32 bytes"))
	}
	if c.SSHKnownHostsFile == "" {
		errs = append(errs, errors.New("SSH_KNOWN_HOSTS_FILE is required"))
	}
	if c.TOTPEnabled && c.TOTPSecret == "" {
		errs = append(errs, errors.New("TOTP_SECRET or TOTP_SECRET_FILE is required when TOTP is enabled"))
	}
	if c.RadiusEnabled && len(c.RadiusSecret) < 16 {
		errs = append(errs, errors.New("RADIUS_SECRET or RADIUS_SECRET_FILE must contain at least 16 bytes when RADIUS is enabled"))
	}
	if !validRemotePath(c.FortigateConfigPath) {
		errs = append(errs, errors.New("FORTIGATE_CONFIG_PATH contains unsafe characters or a parent-directory segment"))
	}
	if c.SCPTimeout < 5 || c.SCPTimeout > 3600 {
		errs = append(errs, errors.New("SCP_TIMEOUT must be between 5 and 3600 seconds"))
	}
	return errors.Join(errs...)
}

func validRemotePath(value string) bool {
	if value == "" || len(value) > 255 || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("_./-", r):
		default:
			return false
		}
	}
	return true
}

// secretEnv reads KEY directly, or KEY_FILE when direct configuration is
// absent. File values support Docker/Kubernetes secrets and have only trailing
// line endings removed; other whitespace remains part of the secret.
func secretEnv(key string, logger *slog.Logger) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	path := os.Getenv(key + "_FILE")
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Error("failed to read secret file", "variable", key+"_FILE", "err", err)
		return ""
	}
	return strings.TrimRight(string(data), "\r\n")
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func boolenv(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch v {
	case "true", "True", "TRUE", "1", "yes", "YES":
		return true
	default:
		return false
	}
}

func intenv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// randomBase32 mirrors pyotp.random_base32(): a random Base32 key of the given
// length. Used when TOTP_SECRET is not supplied.
func randomBase32(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		// Fail closed: never fall back to a predictable constant secret, which
		// would silently weaken TOTP for anyone who did not set TOTP_SECRET.
		panic("config: crypto/rand unavailable for TOTP secret: " + err.Error())
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = base32Alphabet[int(b)%len(base32Alphabet)]
	}
	return string(out)
}

// deriveOrNil returns the raw bytes of a session secret, or nil when unset so
// the session manager falls back to a per-process random key.
func deriveOrNil(v string) []byte {
	if v == "" {
		return nil
	}
	return []byte(v)
}

// decodeKey parses ENCRYPTION_KEY as base64 or hex and requires exactly 32 bytes
// (AES-256). Anything else disables encryption (returns nil) with a warning.
func decodeKey(v string, logger *slog.Logger) []byte {
	if v == "" {
		return nil
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == 32 {
		return b
	}
	if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
		return b
	}
	logger.Warn("ENCRYPTION_KEY is not a valid 32-byte base64/hex key")
	return nil
}
