// Package config loads all runtime configuration from environment variables,
// preserving the exact variable names, defaults and semantics of the original
// Python application so an existing deployment can be swapped in place, plus a
// set of newer optional settings (session/crypto keys, pool tuning, limits).
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
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
	LoginMaxAttempts    int
	LoginLockoutMinutes int

	// Sessions / cookies
	SessionKey   []byte // derived from SESSION_KEY; nil => random per start
	CookieSecure bool
	EnableHSTS   bool
	// TrustProxyHeaders lets the client-IP lookup honour X-Forwarded-For. Enable
	// it only when the app sits behind a trusted reverse proxy that sets the
	// header; otherwise a direct client can spoof it (e.g. to defeat the login
	// rate limiter).
	TrustProxyHeaders bool

	// Encryption at rest (firewall credentials + backup files). Nil => disabled,
	// preserving drop-in behaviour with existing plaintext data.
	EncryptionKey []byte

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
	GraylogURL             string
	GraylogToken           string
	GraylogSearchTimeframe string
	HookwiseURL            string
	HookwiseToken          string

	// Extension: graylog_device_data (switch client inventory for the topology)
	ExtGraylogDeviceData  bool
	GraylogDeviceQuery    string // Graylog query template, %s = source host
	GraylogStpQuery       string // Graylog query template for FortiSwitch STP/link events, %s = source host
	GraylogMacQuery       string // FortiSwitch MAC add/move/delete events (device→switch-port), %s = source host
	GraylogWifiQuery      string // wireless client↔AP↔SSID association events, %s = source host
	GraylogVpnQuery       string // IPsec/SSL VPN tunnel up/down events, %s = source host
	GraylogHaQuery        string // HA member/role events, %s = source host
	GraylogDeviceRange    string // seconds of log history to scan per fetch
	GraylogDeviceInterval int    // background refresh interval in seconds

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

	totpSecret := os.Getenv("TOTP_SECRET")
	if totpSecret == "" {
		totpSecret = randomBase32(16)
	}

	c := &Config{
		PGHost:           getenv("PG_HOST", "localhost"),
		PGPort:           getenv("PG_PORT", "5432"),
		PGUser:           getenv("PG_USER", "your_user"),
		PGPassword:       getenv("PG_PASSWORD", "your_password"),
		PGDatabase:       getenv("PG_DATABASE", "firewall_backups"),
		PGSSLMode:        getenv("PGSSLMODE", "prefer"),
		PGMaxConns:       intenv("PG_MAX_CONNS", 50),
		PGConnectRetries: intenv("PG_CONNECT_RETRIES", 10),
		PGConnectBackoff: time.Duration(intenv("PG_CONNECT_BACKOFF_SECONDS", 3)) * time.Second,

		TOTPEnabled:         boolenv("TOTP_ENABLED", false),
		TOTPSecret:          totpSecret,
		RadiusEnabled:       boolenv("RADIUS_ENABLED", false),
		RadiusServer:        getenv("RADIUS_SERVER", "localhost"),
		RadiusPort:          intenv("RADIUS_PORT", 1812),
		RadiusSecret:        getenv("RADIUS_SECRET", "secret"),
		LoginMaxAttempts:    intenv("LOGIN_MAX_ATTEMPTS", 5),
		LoginLockoutMinutes: intenv("LOGIN_LOCKOUT_MINUTES", 15),

		SessionKey:        deriveOrNil(os.Getenv("SESSION_KEY")),
		CookieSecure:      boolenv("COOKIE_SECURE", false),
		EnableHSTS:        boolenv("ENABLE_HSTS", false),
		TrustProxyHeaders: boolenv("TRUST_PROXY_HEADERS", false),

		EncryptionKey: decodeKey(os.Getenv("ENCRYPTION_KEY"), logger),

		DefaultSCPUser:       getenv("DEFAULT_SCP_USER", "test"),
		DefaultSCPPassword:   getenv("DEFAULT_SCP_PASSWORD", ""),
		FortigateConfigPath:  getenv("FORTIGATE_CONFIG_PATH", "sys_config"),
		SCPTimeout:           intenv("SCP_TIMEOUT", 60),
		MaxConcurrentBackups: intenv("MAX_CONCURRENT_BACKUPS", 10),
		CSVMaxBytes:          int64(intenv("CSV_MAX_BYTES", 5<<20)),

		MailServer:    getenv("MAIL_SERVER", "smtp.example.com"),
		MailPort:      intenv("MAIL_PORT", 587),
		MailUser:      getenv("MAIL_USER", "user@example.com"),
		MailPassword:  getenv("MAIL_PASSWORD", "password"),
		MailRecipient: getenv("MAIL_RECIPIENT", getenv("MAIL_USER", "user@example.com")),

		ExtAdmVpnConf:          boolenv("EXT_ADM_VPN_CONF", false),
		GraylogURL:             os.Getenv("GRAYLOG_URL"),
		GraylogToken:           os.Getenv("GRAYLOG_TOKEN"),
		GraylogSearchTimeframe: getenv("GRAYLOG_SEARCH_TIMEFRAME", "86400"),
		HookwiseURL:            os.Getenv("HOOKWISE_URL"),
		HookwiseToken:          os.Getenv("HOOKWISE_TOKEN"),

		ExtGraylogDeviceData:  boolenv("EXT_GRAYLOG_DEVICE_DATA", false),
		GraylogDeviceQuery:    getenv("GRAYLOG_DEVICE_QUERY", `source:"%s" AND (mac:* OR srcmac:* OR macaddr:*)`),
		GraylogStpQuery:       getenv("GRAYLOG_STP_QUERY", `source:"%s" AND subtype:"switch-controller" AND (logdesc:"FortiSwitch spanning Tree" OR logdesc:"FortiSwitch port status" OR logdesc:"FortiSwitch link" OR msg:bpdu OR msg:"loop guard" OR msg:"loop-guard" OR msg:"root guard" OR msg:"root-guard" OR msg:"status up" OR msg:"status down")`),
		GraylogMacQuery:       getenv("GRAYLOG_MAC_QUERY", `source:"%s" AND (logid:0115032615 OR logid:0115032617 OR logid:0115032616)`),
		GraylogWifiQuery:      getenv("GRAYLOG_WIFI_QUERY", `source:"%s" AND subtype:"wireless" AND stamac:* AND (ssid:* OR ap:*)`),
		GraylogVpnQuery:       getenv("GRAYLOG_VPN_QUERY", `source:"%s" AND subtype:"vpn" AND tunnelid:*`),
		GraylogHaQuery:        getenv("GRAYLOG_HA_QUERY", `source:"%s" AND subtype:"ha"`),
		GraylogDeviceRange:    getenv("GRAYLOG_DEVICE_RANGE", "86400"),
		GraylogDeviceInterval: intenv("GRAYLOG_DEVICE_INTERVAL", 3600),

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
	logger.Warn("ENCRYPTION_KEY is not a valid 32-byte base64/hex key; encryption at rest disabled")
	return nil
}
