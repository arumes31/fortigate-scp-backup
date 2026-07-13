package backup

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestLiveBackupTransfer pulls the config from a real FortiGate over SCP using
// the production transfer path. Skipped unless
// FGT_BACKUP_LIVE="host|port|user|pass|remotePath" is set. No credentials are
// committed; they come from the environment at runtime.
func TestLiveBackupTransfer(t *testing.T) {
	spec := os.Getenv("FGT_BACKUP_LIVE")
	if spec == "" {
		t.Skip("set FGT_BACKUP_LIVE=host|port|user|pass|remotePath to run")
	}
	p := strings.SplitN(spec, "|", 5)
	if len(p) != 5 {
		t.Fatalf("FGT_BACKUP_LIVE must be host|port|user|pass|remotePath")
	}
	port, _ := strconv.Atoi(p[1])
	s := &Service{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	local := filepath.Join(t.TempDir(), "sys_config")

	if err := s.transfer(p[0], p[2], p[3], port, p[4], local, 60); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	fi, err := os.Stat(local)
	if err != nil {
		t.Fatalf("stat pulled config: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("pulled config is empty")
	}
	head, _ := os.ReadFile(local)
	t.Logf("pulled %d bytes; head: %q", fi.Size(), string(head[:min(120, len(head))]))
}
