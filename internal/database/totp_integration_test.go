//go:build integration

package database

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

// TestTOTPSecretEncryptedAtRest covers TOTP_SECRET rotation, encryption of the
// stored secret and the plaintext migration. Same env gating as TestStoreIntegration.
func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	host := os.Getenv("TEST_PG_HOST")
	if host == "" {
		t.Skip("set TEST_PG_HOST to run the store integration test")
	}
	cfg := config.Load(slog.New(slog.DiscardHandler))
	cfg.PGHost = host
	for env, field := range map[string]*string{"TEST_PG_PORT": &cfg.PGPort, "TEST_PG_USER": &cfg.PGUser, "TEST_PG_PASSWORD": &cfg.PGPassword, "TEST_PG_DATABASE": &cfg.PGDatabase} {
		if v := os.Getenv(env); v != "" {
			*field = v
		}
	}
	cfg.PGConnectRetries = 1
	ctx := context.Background()
	cipher, err := crypto.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(ctx, cfg, cipher, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer store.Close()
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `UPDATE users SET totp_secret = NULL WHERE username = 'admin'`)
	})

	for _, secret := range []string{"JBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLU"} {
		if err := store.InitSchema(ctx, true, secret, "integration-test-admin-password"); err != nil {
			t.Fatalf("init schema: %v", err)
		}
		var stored string
		if err := store.pool.QueryRow(ctx, `SELECT totp_secret FROM users WHERE username = 'admin'`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !crypto.IsEncryptedString(stored) {
			t.Fatal("admin TOTP secret stored in plaintext")
		}
		admin, err := store.GetUserForLogin(ctx, "admin")
		if err != nil || admin == nil || admin.TOTPSecret != secret {
			t.Fatalf("admin TOTP secret is not the rotated value (err %v)", err)
		}
	}

	if _, err := store.pool.Exec(ctx, `UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP' WHERE username = 'admin'`); err != nil {
		t.Fatal(err)
	}
	if n, err := store.MigrateTOTPEncryption(ctx); err != nil || n != 1 {
		t.Fatalf("first migration = %d, %v; want 1", n, err)
	}
	if n, err := store.MigrateTOTPEncryption(ctx); err != nil || n != 0 {
		t.Fatalf("second migration = %d, %v; want idempotent 0", n, err)
	}
	cipher.RequireEncrypted()
	if admin, err := store.GetUserForLogin(ctx, "admin"); err != nil || admin == nil || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("migrated admin TOTP secret = %v", err)
	}
}
