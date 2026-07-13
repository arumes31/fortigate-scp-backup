package graylogdevicedata

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
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
		b := "diagnose switch-controller switch-info "
		for _, sw := range inv {
			ps := run(b + "port-stats " + sw.Name)
			stp := run(b + "stp " + sw.Name)
			props := run(b + "port-properties " + sw.Name)
			dot1x := run(b + "802.1X " + sw.Name)
			poe := run(b + "poe summary " + sw.Name)
			modules := run(b + "modules summary " + sw.Name)
			lldp := run(b + "lldp neighbors-detail " + sw.Name)
			ports, edges := buildDiagPorts(sw, ps, stp, props, poe, modules, dot1x, lldp)
			up, health, poeCnt := 0, 0, 0
			for _, pp := range ports {
				if pp.Link == "up" {
					up++
				}
				if pp.Health != "" {
					health++
				}
				if pp.Poe != "" {
					poeCnt++
				}
			}
			t.Logf("%-14s ports=%2d up=%2d health-issues=%d poe=%d interlinks=%d",
				sw.Name, len(ports), up, health, poeCnt, len(edges))
			for _, ed := range edges {
				t.Logf("      interlink trunk=%-18s role=%-11s state=%s", ed.Trunk, ed.Role, ed.State)
			}
		}
	})
	if err != nil {
		t.Fatalf("shell: %v", err)
	}
}

// TestLiveDiagStore runs the full production collectDiag against a real FortiGate
// into a temp SQLite DB, then confirms the enriched columns persisted and are
// readable via listStp. Skipped unless FGT_DIAG_LIVE is set.
func TestLiveDiagStore(t *testing.T) {
	spec := os.Getenv("FGT_DIAG_LIVE")
	if spec == "" {
		t.Skip("set FGT_DIAG_LIVE=host|port|user|pass to run")
	}
	p := strings.SplitN(spec, "|", 4)
	if len(p) != 4 {
		t.Fatalf("FGT_DIAG_LIVE must be host|port|user|pass")
	}
	port, _ := strconv.Atoi(p[1])

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "d.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	for _, q := range []string{createTableSQL, createStpTableSQL, createSwitchEdgesSQL, createMacSightingsSQL, createMacEnrichSQL, createWifiSQL, createHaStatusSQL, createSwitchHealthSQL, createLiveRoutesSQL, createSdwanHealthSQL, createIfaceStatsSQL, createDiagStatusSQL} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{FgtDiagSSHEnabled: true, FgtDiagSSHTimeoutSec: 180}
	e := &Extension{db: db, logger: slog.New(slog.NewTextHandler(os.Stderr, nil)), cfg: cfg,
		firewallCreds: func(_ context.Context, _ int) (string, string, string, int, error) {
			return p[0], p[2], p[3], port, nil
		}}

	if err := e.collectDiag(1, true); err != nil {
		t.Fatalf("collectDiag: %v", err)
	}
	stp, err := e.listStp(1)
	if err != nil {
		t.Fatalf("listStp: %v", err)
	}
	var withSpeed, withMedia, withPoe, withHealth, withDot1x, withNbr, up int
	for _, s := range stp {
		if s.Link == "up" {
			up++
		}
		if s.Speed != "" {
			withSpeed++
		}
		if s.Media != "" {
			withMedia++
		}
		if s.Poe != "" {
			withPoe++
		}
		if s.Health != "" {
			withHealth++
		}
		if s.Dot1x != "" {
			withDot1x++
		}
		if s.Neighbor != "" {
			withNbr++
		}
	}
	edges, _ := e.listSwitchEdges(1)
	blocked, iclWithPorts := 0, 0
	iclNote := ""
	for _, g := range edges {
		if g.State == "discarding" {
			blocked++
		}
		if strings.Contains(g.Trunk, "_ICL") && len(g.Ports) > 0 {
			iclWithPorts++
			iclNote = g.Note
		}
	}
	sh, _ := e.listSwitchHealth(1)
	fans := 0
	for _, h := range sh {
		if h.Fan != "" {
			fans++
		}
	}
	lr, _ := e.listLiveRoutes(1)
	tunRoutes := 0
	for _, r := range lr {
		if r.Routes > 0 {
			tunRoutes++
		}
	}
	tcn, poeBudget := 0, 0
	for _, h := range sh {
		if h.Tcn > 0 {
			tcn++
		}
		if h.PoeTotal > 0 {
			poeBudget++
		}
	}
	sd, _ := e.listSdwanHealth(1)
	worstLoss := 0.0
	for _, s := range sd {
		if s.Loss > worstLoss {
			worstLoss = s.Loss
		}
	}
	tp, _ := e.listIfaceThroughput(1)
	ds := e.diagStatus(1)
	t.Logf("P1 ICL w/ports=%d note=%q | health sw=%d fans=%d tcn=%d poeBudget=%d | routes=%d | sdwan members=%d worstLoss=%.1f%% | throughput ifaces=%d | status: %d sw %dms static=%v",
		iclWithPorts, iclNote, len(sh), fans, tcn, poeBudget, tunRoutes, len(sd), worstLoss, len(tp), ds.Switches, ds.DurationMs, ds.Static)
	// mac_enrich holds the ARP IP + 802.1X identity (device rows come from Graylog,
	// absent here, so query the enrichment table directly).
	var enrIP, enrUser int
	_ = e.db.QueryRow("SELECT count(*) FROM mac_enrich WHERE ip != ''").Scan(&enrIP)
	_ = e.db.QueryRow("SELECT count(*) FROM mac_enrich WHERE dot1x_user != ''").Scan(&enrUser)
	t.Logf("ports=%d (%d up) media=%d speed=%d poe=%d health=%d dot1x=%d nbr=%d | edges=%d(%d blk) | mac_enrich: ip=%d user=%d | health=%q",
		len(stp), up, withMedia, withSpeed, withPoe, withHealth, withDot1x, withNbr, len(edges), blocked, enrIP, enrUser, e.fwHealth(1))
	if withDot1x == 0 || withNbr == 0 {
		t.Errorf("expected 802.1X state (%d) and LLDP neighbors (%d) to persist", withDot1x, withNbr)
	}
}
