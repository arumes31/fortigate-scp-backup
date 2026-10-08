//go:build integration

package web

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// TestLiveLicenseChildDevices runs the real collection commands against a live
// FortiGate and the real parsers over their output. Skipped unless the
// LIVE_FGT_* environment variables point at a lab device — CI never runs it.
//
//	LIVE_FGT_HOST=10.0.0.1 LIVE_FGT_PORT=22 LIVE_FGT_USER=u LIVE_FGT_PW=p \
//	  go test ./internal/web/ -run TestLiveLicenseChildDevices -v
func TestLiveLicenseChildDevices(t *testing.T) {
	host := os.Getenv("LIVE_FGT_HOST")
	if host == "" {
		t.Skip("LIVE_FGT_HOST not set; skipping live-device test")
	}
	port, err := strconv.Atoi(os.Getenv("LIVE_FGT_PORT"))
	if err != nil {
		port = 22
	}
	fw := models.Firewall{
		FQDN:     host,
		SSHPort:  port,
		Username: os.Getenv("LIVE_FGT_USER"),
		Password: os.Getenv("LIVE_FGT_PW"),
	}
	hostKeyCallback, err := knownhosts.New(os.Getenv("SSH_KNOWN_HOSTS_FILE"))
	if err != nil {
		t.Fatalf("load SSH_KNOWN_HOSTS_FILE: %v", err)
	}
	out, err := sshRunCommands(fw, hostKeyCallback, []string{
		"diagnose switch-controller switch-info status",
		"get switch-controller managed-switch",
		"show wireless-controller wtp",
	})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	switches := mergeSwitchDevices(
		parseManagedSwitchList(out["get switch-controller managed-switch"]),
		parseSwitchInfoStatus(out["diagnose switch-controller switch-info status"]))
	aps := parseWTPConfig(out["show wireless-controller wtp"])
	for _, d := range append(switches, aps...) {
		t.Logf("%-6s %-24s serial=%-18s model=%-18s fw=%s b%s status=%s",
			d.Kind, d.Name, d.Serial, d.Model, d.Version, d.Build, d.Status)
	}
	if len(switches) == 0 && len(aps) == 0 {
		t.Error("live device returned no managed switches or APs — check parsers against current FortiOS output")
	}
	for _, d := range switches {
		if d.Status == "online" && (d.Serial == "" || d.Model == "") {
			t.Errorf("connected switch missing serial/model: %+v", d)
		}
	}
	for _, d := range aps {
		if d.Serial == "" {
			t.Errorf("AP without serial: %+v", d)
		}
	}
}
