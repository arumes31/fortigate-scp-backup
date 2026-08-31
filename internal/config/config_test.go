package config

import (
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestLoadDefaults(t *testing.T) {
	// Clear every env var the assertions below depend on so an ambient value in
	// CI or a developer shell cannot influence the default-path behavior.
	for _, k := range []string{
		"PG_HOST", "PORT", "SCP_TIMEOUT", "ENCRYPTION_KEY", "MAX_CONCURRENT_BACKUPS",
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
