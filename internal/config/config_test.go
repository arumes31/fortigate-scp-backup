package config

import (
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestLoadDefaults verifies security-sensitive and operational defaults.
func TestLoadDefaults(t *testing.T) {
	// Clear every env var the assertions below depend on so an ambient value in
	// CI or a developer shell cannot influence the default-path behavior.
	for _, k := range []string{
		"PG_HOST", "PORT", "SCP_TIMEOUT", "ENCRYPTION_KEY", "MAX_CONCURRENT_BACKUPS", "COOKIE_SECURE",
	} {
		t.Setenv(k, "")
	}
	c := Load(discard())
	if c.Port != "8521" {
		t.Errorf("default port = %q", c.Port)
	}
	if c.SCPTimeout != 60 {
		t.Errorf("default scp timeout = %d", c.SCPTimeout)
	}
	if c.MaxConcurrentBackups < 1 {
		t.Error("concurrency must be >= 1")
	}
	if c.EncryptionKey != nil {
		t.Error("encryption disabled by default")
	}
	if !c.CookieSecure {
		t.Error("session cookies must be secure by default")
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("PORT", "9000")
	t.Setenv("TOTP_ENABLED", "true")
	t.Setenv("MAX_CONCURRENT_BACKUPS", "3")
	c := Load(discard())
	if c.Port != "9000" {
		t.Errorf("port = %q", c.Port)
	}
	if !c.TOTPEnabled {
		t.Error("TOTP should be enabled")
	}
	if c.MaxConcurrentBackups != 3 {
		t.Errorf("concurrency = %d", c.MaxConcurrentBackups)
	}
}

func TestEncryptionKeyDecode(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	c := Load(discard())
	if len(c.EncryptionKey) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(c.EncryptionKey))
	}
}

func TestEncryptionKeyRejectsWrongLength(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte("tooshort")))
	c := Load(discard())
	if c.EncryptionKey != nil {
		t.Fatal("invalid key length must disable encryption")
	}
}

func TestRandomBase32Length(t *testing.T) {
	if got := randomBase32(16); len(got) != 16 {
		t.Fatalf("len = %d", len(got))
	}
}

func TestSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session_key")
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESSION_KEY", "")
	t.Setenv("SESSION_KEY_FILE", path)
	if got := string(Load(discard()).SessionKey); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("session key from file = %q", got)
	}
}

func TestSSHKnownHostsDefaultsToDataDir(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DATA_DIR", dataDir)
	t.Setenv("SSH_KNOWN_HOSTS_FILE", "")
	got := Load(discard()).SSHKnownHostsFile
	want := filepath.Join(dataDir, "ssh_known_hosts")
	if got != want {
		t.Fatalf("SSHKnownHostsFile = %q, want %q", got, want)
	}
}

func TestLoadFgtConfTailDefaultsAndTokenPrecedence(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "hookwise_token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXT_FGT_CONFTAIL", "true")
	t.Setenv("FGT_CONFTAIL_HOOKWISE_URL", "https://hookwise.example/w/config-tail")
	t.Setenv("FGT_CONFTAIL_HOOKWISE_TOKEN", "direct-token")
	t.Setenv("FGT_CONFTAIL_HOOKWISE_TOKEN_FILE", tokenFile)
	t.Setenv("FGT_CONFTAIL_POLL_SECONDS", "")
	t.Setenv("FGT_CONFTAIL_IDLE_SECONDS", "")
	t.Setenv("FGT_CONFTAIL_OVERLAP_SECONDS", "")
	t.Setenv("FGT_CONFTAIL_RETENTION_DAYS", "")
	t.Setenv("FGT_CONFTAIL_TICKET_MAX_BYTES", "")
	t.Setenv("FGT_CONFTAIL_GRAYLOG_QUERY", "")

	c := Load(discard())
	if !c.ExtFgtConfTail {
		t.Fatal("fgt_conftail should be enabled")
	}
	if c.FgtConfTailHookwiseToken != "direct-token" {
		t.Fatalf("direct token did not win: %q", c.FgtConfTailHookwiseToken)
	}
	if c.FgtConfTailPollSeconds != 900 || c.FgtConfTailIdleSeconds != 1800 || c.FgtConfTailOverlapSeconds != 3600 {
		t.Fatalf("unexpected timing defaults: poll=%d idle=%d overlap=%d",
			c.FgtConfTailPollSeconds, c.FgtConfTailIdleSeconds, c.FgtConfTailOverlapSeconds)
	}
	if c.FgtConfTailRetentionDays != 365 {
		t.Fatalf("retention default = %d, want 365", c.FgtConfTailRetentionDays)
	}
	if c.FgtConfTailTicketMaxBytes != 60000 {
		t.Fatalf("ticket description limit = %d, want 60000", c.FgtConfTailTicketMaxBytes)
	}
	if !strings.Contains(c.FgtConfTailGraylogQuery, "0100044544") || strings.Contains(c.FgtConfTailGraylogQuery, "0100044548") {
		t.Fatalf("unexpected default query: %q", c.FgtConfTailGraylogQuery)
	}

	t.Setenv("FGT_CONFTAIL_HOOKWISE_TOKEN", "")
	if got := Load(discard()).FgtConfTailHookwiseToken; got != "file-token" {
		t.Fatalf("token file fallback = %q, want file-token", got)
	}
}

func TestValidateRuntimeFgtConfTail(t *testing.T) {
	valid := func() *Config {
		return &Config{
			PGPassword: "database-password",
			SessionKey: make([]byte, 32), EncryptionKey: make([]byte, 32),
			SSHKnownHostsFile: "known_hosts", FortigateConfigPath: "sys_config", SCPTimeout: 60,
			ExtFgtConfTail: true, GraylogURL: "https://graylog.example", GraylogToken: "graylog-token",
			FgtConfTailHookwiseURL: "https://hookwise.example/w/config-tail", FgtConfTailHookwiseToken: "hookwise-token",
			FgtConfTailPollSeconds: 900, FgtConfTailIdleSeconds: 1800,
			FgtConfTailOverlapSeconds: 3600, FgtConfTailRetentionDays: 365,
			FgtConfTailTicketMaxBytes: 60000,
			FgtConfTailGraylogQuery:   "type:event AND logid:0100044544",
		}
	}

	if err := valid().ValidateRuntime(); err != nil {
		t.Fatalf("valid fgt_conftail config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing graylog url", mutate: func(c *Config) { c.GraylogURL = "" }, want: "GRAYLOG_URL"},
		{name: "missing graylog token", mutate: func(c *Config) { c.GraylogToken = "" }, want: "GRAYLOG_TOKEN"},
		{name: "missing hookwise url", mutate: func(c *Config) { c.FgtConfTailHookwiseURL = "" }, want: "FGT_CONFTAIL_HOOKWISE_URL"},
		{name: "missing hookwise token", mutate: func(c *Config) { c.FgtConfTailHookwiseToken = "" }, want: "FGT_CONFTAIL_HOOKWISE_TOKEN"},
		{name: "poll too short", mutate: func(c *Config) { c.FgtConfTailPollSeconds = 0 }, want: "FGT_CONFTAIL_POLL_SECONDS"},
		{name: "idle too short", mutate: func(c *Config) { c.FgtConfTailIdleSeconds = 59 }, want: "FGT_CONFTAIL_IDLE_SECONDS"},
		{name: "overlap too short", mutate: func(c *Config) { c.FgtConfTailOverlapSeconds = 59 }, want: "FGT_CONFTAIL_OVERLAP_SECONDS"},
		{name: "negative retention", mutate: func(c *Config) { c.FgtConfTailRetentionDays = -1 }, want: "FGT_CONFTAIL_RETENTION_DAYS"},
		{name: "ticket limit too small", mutate: func(c *Config) { c.FgtConfTailTicketMaxBytes = 100 }, want: "FGT_CONFTAIL_TICKET_MAX_BYTES"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(c)
			err := c.ValidateRuntime()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateRuntime() error = %v, want mention of %s", err, tt.want)
			}
		})
	}
}

func TestValidateRuntime(t *testing.T) {
	c := &Config{
		PGPassword: "database-password",
		SessionKey: make([]byte, 32), EncryptionKey: make([]byte, 32),
		SSHKnownHostsFile: "known_hosts", FortigateConfigPath: "sys_config", SCPTimeout: 60,
	}
	if err := c.ValidateRuntime(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	c.FortigateConfigPath = "sys_config; reboot"
	if err := c.ValidateRuntime(); err == nil {
		t.Fatal("unsafe remote path accepted")
	}
}
