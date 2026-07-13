package graylogdevicedata

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLiveDiag exercises the real production path (dial → shell → parse) against
// an actual FortiGate. Skipped unless FGT_DIAG_LIVE="host|port|user|pass" is set.
// Never committed with credentials; creds come from the environment at runtime.
func TestLiveDiag(t *testing.T) {
	spec := os.Getenv("FGT_DIAG_LIVE")
	if spec == "" {
		t.Skip("set FGT_DIAG_LIVE=host|port|user|pass to run")
	}
	p := strings.SplitN(spec, "|", 4)
	if len(p) != 4 {
		t.Fatalf("FGT_DIAG_LIVE must be host|port|user|pass")
	}
	port, _ := strconv.Atoi(p[1])
	client, err := dialSSHDiag(p[0], p[2], p[3], port, 90*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	err = runSSHShell(client, 90*time.Second, func(run func(string) string) {
		inv := parseSwitchInventory(run("diagnose switch-controller switch-info status"))
		t.Logf("inventory: %d managed switches", len(inv))
		for _, sw := range inv {
			ps := run("diagnose switch-controller switch-info port-stats " + sw.Name)
			stp := run("diagnose switch-controller switch-info stp " + sw.Name)
			ports, edges := buildDiagPorts(sw, ps, stp)
			up, blocked := 0, 0
			for _, pp := range ports {
				if pp.Link == "up" {
					up++
				}
				if pp.State == "discarding" || pp.Role == "alternate" || pp.Role == "backup" {
					blocked++
				}
			}
			t.Logf("%-14s %-18s ports=%2d up=%2d blocked=%d interlinks=%d",
				sw.Name, sw.Serial, len(ports), up, blocked, len(edges))
			for _, ed := range edges {
				t.Logf("      interlink trunk=%-18s role=%s", ed.Trunk, ed.Role)
			}
		}
	})
	if err != nil {
		t.Fatalf("shell: %v", err)
	}
}
