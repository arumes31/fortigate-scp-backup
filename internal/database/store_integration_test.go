//go:build integration

package database

import (
	"context"
	"errors"
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
	committed, err := store.GetBackupByFilename(ctx, id, "x.conf")
	if err != nil || committed.ID <= 0 || committed.FwID != id || committed.Filename != "x.conf" || committed.SizeBytes != 123 || committed.Checksum != "abc" {
		t.Fatalf("exact committed backup lookup = %+v, %v", committed, err)
	}
	if _, err := store.GetBackupByFilename(ctx, -1, "x.conf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-firewall backup lookup = %v", err)
	}
	if _, err := store.GetBackupByFilename(ctx, id, "missing.conf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing backup lookup = %v", err)
	}
	last, ok, err := store.LastBackupTime(ctx, id)
	if err != nil || !ok {
		t.Fatalf("last backup: ok=%v err=%v", ok, err)
	}
	if time.Since(last) > time.Hour {
		t.Fatalf("last backup time looks wrong: %v", last)
	}
	// A legacy NULL-timestamp row must sort last and not break scans.
	if _, err := store.pool.Exec(ctx, `INSERT INTO backups (fw_id, timestamp, filename) VALUES ($1, NULL, 'legacy.conf')`, id); err != nil {
		t.Fatalf("insert legacy backup: %v", err)
	}
	if list, err := store.ListBackups(ctx, id); err != nil || len(list) != 2 || list[0].Filename != "x.conf" {
		t.Fatalf("list backups with NULL timestamp = %+v, %v", list, err)
	}
	if names, err := store.ListBackupFilenames(ctx, id); err != nil || len(names) != 2 || names[0] != "x.conf" {
		t.Fatalf("list backup filenames with NULL timestamp = %v, %v", names, err)
	}
	if rows, err := store.ListBackupIDFilenames(ctx, id, 1); err != nil || len(rows) != 1 || rows[0].Filename != "x.conf" {
		t.Fatalf("list backup id/filenames with NULL timestamp = %+v, %v", rows, err)
	}
	if last2, ok, err := store.LastBackupTime(ctx, id); err != nil || !ok || !last2.Equal(last) {
		t.Fatalf("last backup with NULL timestamp row: %v ok=%v err=%v", last2, ok, err)
	}
	latest, err := store.LatestBackups(ctx)
	if err != nil {
		t.Fatalf("latest backups: %v", err)
	}
	var latestForFw []models.Backup
	for _, b := range latest {
		if b.FwID == id {
			latestForFw = append(latestForFw, b)
		}
	}
	if len(latestForFw) != 1 || latestForFw[0].Filename != "x.conf" {
		t.Fatalf("latest backups for firewall = %+v", latestForFw)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM backups WHERE filename = 'legacy.conf'`); err != nil {
		t.Fatalf("delete legacy backup: %v", err)
	}

	if _, err := store.DashboardStats(ctx); err != nil {
		t.Fatalf("dashboard stats: %v", err)
	}
}
