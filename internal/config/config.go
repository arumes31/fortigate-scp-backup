// Package config loads all runtime configuration from environment variables,
// preserving the exact variable names, defaults and semantics of the original
// Python application so an existing deployment can be swapped in place.
package config

import (
	"crypto/rand"
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

	// Authentication
	TOTPEnabled   bool
	TOTPSecret    string
	RadiusEnabled bool
	RadiusServer  string
	RadiusPort    int
	RadiusSecret  string

	// SCP / backup defaults
	DefaultSCPUser      string
	DefaultSCPPassword  string
	FortigateConfigPath string
	SCPTimeout          int // seconds

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

	// General
	TZ        *time.Location
	BackupDir string
	DataDir   string
	Port      string
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
		PGHost:     getenv("PG_HOST", "localhost"),
		PGPort:     getenv("PG_PORT", "5432"),
		PGUser:     getenv("PG_USER", "your_user"),
		PGPassword: getenv("PG_PASSWORD", "your_password"),
		PGDatabase: getenv("PG_DATABASE", "firewall_backups"),

		TOTPEnabled:   boolenv("TOTP_ENABLED", false),
		TOTPSecret:    totpSecret,
		RadiusEnabled: boolenv("RADIUS_ENABLED", false),
		RadiusServer:  getenv("RADIUS_SERVER", "localhost"),
		RadiusPort:    intenv("RADIUS_PORT", 1812),
		RadiusSecret:  getenv("RADIUS_SECRET", "secret"),

		DefaultSCPUser:      getenv("DEFAULT_SCP_USER", "test"),
		DefaultSCPPassword:  getenv("DEFAULT_SCP_PASSWORD", ""),
		FortigateConfigPath: getenv("FORTIGATE_CONFIG_PATH", "sys_config"),
		SCPTimeout:          intenv("SCP_TIMEOUT", 60),

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

		TZ:        tz,
		BackupDir: getenv("BACKUP_DIR", "backups"),
		DataDir:   getenv("DATA_DIR", "/app/data"),
		Port:      getenv("PORT", "8521"),
	}
	return c
}

// PostgresDSN builds the connection string for the shared store.
func (c *Config) PostgresDSN() string {
	return "postgres://" + c.PGUser + ":" + c.PGPassword + "@" + c.PGHost + ":" + c.PGPort + "/" + c.PGDatabase
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
		// Extremely unlikely; fall back to a fixed but valid secret.
		return "AAAAAAAAAAAAAAAA"[:length]
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = base32Alphabet[int(b)%len(base32Alphabet)]
	}
	return string(out)
}
