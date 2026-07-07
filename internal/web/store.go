package web

import (
	"context"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// Store is the subset of the database layer the web handlers depend on. Using an
// interface (rather than the concrete *database.Store) decouples the handlers
// and allows them to be unit-tested with a fake (#42).
type Store interface {
	Ping(ctx context.Context) error
	LogActivity(username, action, details string)
	GetUserForLogin(ctx context.Context, username string) (*models.User, error)
	UpsertRadiusUser(ctx context.Context, username string) error
	AuthenticateLocal(ctx context.Context, username, password string) (*models.User, bool, error)
	GetFirstLogin(ctx context.Context, username string) (int, bool, error)
	ChangePassword(ctx context.Context, username, oldPassword, newPassword string) (bool, error)
	ListFirewalls(ctx context.Context) ([]models.Firewall, error)
	AddFirewall(ctx context.Context, fw models.Firewall) (int, error)
	DeleteFirewall(ctx context.Context, id int) (string, error)
	ListBackups(ctx context.Context, fwID int) ([]models.Backup, error)
	ListErrors(ctx context.Context) ([]models.Firewall, error)
	ListActivityLogs(ctx context.Context, limit, offset int) ([]models.ActivityLog, error)
	CountActivityLogs(ctx context.Context) (int, error)
	DashboardStats(ctx context.Context) (models.DashboardStats, error)
	ListFirewallRefs(ctx context.Context) ([]models.FirewallRef, error)
}
