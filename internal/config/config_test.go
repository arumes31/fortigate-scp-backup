package config

import (
	"encoding/base64"
	"log/slog"
	"testing"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PG_HOST", "")
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
