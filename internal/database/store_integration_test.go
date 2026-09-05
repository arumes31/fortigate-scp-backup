//go:build integration

package database

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// TestStoreIntegration exercises schema init, migrations and CRUD against a real
// PostgreSQL. It is skipped unless TEST_PG_HOST is set, e.g.:
//
//	TEST_PG_HOST=localhost TEST_PG_PORT=15432 TEST_PG_USER=postgre \
//	TEST_PG_PASSWORD=testpass TEST_PG_DATABASE=firewall_backups go test ./internal/database
//
// A testcontainers-based variant can be wired here later; this env-gated form
// keeps the default `go test` run free of external dependencies.
func TestStoreIntegration(t *testing.T) {
	host := os.Getenv("TEST_PG_HOST")
	if host == "" {
		t.Skip("set TEST_PG_HOST to run the store integration test")
	}
	cfg := config.Load(slog.New(slog.DiscardHandler))
	cfg.PGHost = host
	if v := os.Getenv("TEST_PG_PORT"); v != "" {
		cfg.PGPort = v
	}
	if v := os.Getenv("TEST_PG_USER"); v != "" {
		cfg.PGUser = v
	}
	if v := os.Getenv("TEST_PG_PASSWORD"); v != "" {
		cfg.PGPassword = v
	}
	if v := os.Getenv("TEST_PG_DATABASE"); v != "" {
		cfg.PGDatabase = v
	}
	cfg.PGConnectRetries = 1

	ctx := context.Background()
	cipher, _ := crypto.New(nil)
	store, err := NewStore(ctx, cfg, cipher, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer store.Close()

	if err := store.InitSchema(ctx, false, "", "integration-test-admin-password"); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	admin, err := store.GetUserForLogin(ctx, "admin")
	if err != nil || admin == nil || admin.Role != models.RoleAdmin || admin.IsRadiusUser {
		t.Fatalf("migrated admin = %+v, err %v; want admin role", admin, err)
	}
	radiusUsername := "integration-radius-user"
	_, _ = store.pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, radiusUsername)
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM users WHERE username = $1`, radiusUsername)
	})
	if err := store.UpsertRadiusUser(ctx, radiusUsername); err != nil {
		t.Fatalf("upsert radius user: %v", err)
	}
	radiusUser, err := store.GetUserForLogin(ctx, radiusUsername)
	if err != nil || radiusUser == nil || radiusUser.Role != models.RoleOperator {
		t.Fatalf("radius user = %+v, err %v; want operator role", radiusUser, err)
	}

	timeStep := time.Now().UnixNano()
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM totp_replay WHERE user_id = $1 AND time_step = $2`, admin.ID, timeStep)
	})
	results := make(chan bool, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			consumed, consumeErr := store.ConsumeTOTP(context.Background(), admin.ID, timeStep)
			if consumeErr != nil {
				t.Errorf("consume TOTP: %v", consumeErr)
			}
			results <- consumed
		}()
	}
	wait.Wait()
	close(results)
	accepted := 0
	for consumed := range results {
		if consumed {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted concurrent TOTP attempts = %d, want 1", accepted)
	}

	id, err := store.AddFirewall(ctx, models.Firewall{
		FQDN: "it-test.example.com", Username: "u", Password: "p",
		IntervalMin: 60, RetentionCount: 3, Status: "New", SSHPort: 22,
	})
	if err != nil {
		t.Fatalf("add firewall: %v", err)
	}
	t.Cleanup(func() { _, _ = store.DeleteFirewall(context.Background(), id) })

	fw, err := store.GetFirewall(ctx, id)
	if err != nil {
		t.Fatalf("get firewall: %v", err)
	}
	if fw.FQDN != "it-test.example.com" || fw.Password != "p" {
		t.Fatalf("unexpected firewall: %+v", fw)
	}

	if err := store.InsertBackup(ctx, id, store.Now(), "x.conf", 123, "abc"); err != nil {
		t.Fatalf("insert backup: %v", err)
	}
	last, ok, err := store.LastBackupTime(ctx, id)
	if err != nil || !ok {
		t.Fatalf("last backup: ok=%v err=%v", ok, err)
	}
	if time.Since(last) > time.Hour {
		t.Fatalf("last backup time looks wrong: %v", last)
	}

	if _, err := store.DashboardStats(ctx); err != nil {
		t.Fatalf("dashboard stats: %v", err)
	}
}
