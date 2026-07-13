package graylogdevicedata

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

// TestLiveGraylogFetch queries a real Graylog for a firewall's device logs via
// the production fetch path. Skipped unless FGT_GRAYLOG_LIVE="url|token|source"
// is set. Credentials come from the environment at runtime, never committed.
func TestLiveGraylogFetch(t *testing.T) {
	spec := os.Getenv("FGT_GRAYLOG_LIVE")
	if spec == "" {
		t.Skip("set FGT_GRAYLOG_LIVE=url|token|source to run")
	}
	p := strings.SplitN(spec, "|", 3)
	if len(p) != 3 {
		t.Fatalf("FGT_GRAYLOG_LIVE must be url|token|source")
	}
	_ = os.Setenv("GRAYLOG_URL", p[0])
	_ = os.Setenv("GRAYLOG_TOKEN", p[1])
	cfg := config.Load(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	e := &Extension{cfg: cfg, logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	devices, err := e.fetchDevices(p[2], "3600")
	if err != nil {
		t.Fatalf("fetchDevices: %v", err)
	}
	t.Logf("graylog returned %d devices for source %q", len(devices), p[2])
	for i, d := range devices {
		if i >= 5 {
			break
		}
		t.Logf("  device: mac=%s ip=%s vlan=%s port=%s switch=%s", d.Mac, d.IP, d.Vlan, d.Port, d.SwitchID)
	}
}
