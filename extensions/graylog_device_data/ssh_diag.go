package graylogdevicedata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// errDiagBusy is returned when an on-demand port query cannot start because the
// firewall's single SSH slot is already in use (a background sweep or another
// on-demand query is running).
var errDiagBusy = errors.New("a diagnostics query is already running for this firewall")

// reDiagName validates a switch or port name before it is interpolated into an
// SSH CLI command. Restricting to this alphabet (no whitespace, no shell/CLI
// metacharacters, no newlines) makes command injection through the switch/port
// arguments impossible.
var reDiagName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidDiagName reports whether s is a safe switch/port identifier for the
// on-demand port diagnostics endpoint.
func ValidDiagName(s string) bool { return reDiagName.MatchString(s) }

// This file runs the live FortiGate CLI diagnostics collector. It reuses each
// firewall's stored SSH credentials to pull authoritative per-switch-port link
// state, STP role/state and interlink trunks — the data the Graylog logs only
// reveal partially (a capped, event-driven stream). The store layer (stp_ports,
// switch_edges) and the topology frontend are shared with the log path, so the
// faceplate needs no changes; SSH just supplies a fresher, complete overlay.

// diagFloor is the hard lower bound on spacing between query starts per device.
// One query runs at a time per firewall regardless (the serial executor), so in
// practice consecutive collections are spaced by the collection's own duration;
// this floor only bounds the gap for very fast commands.
func (e *Extension) diagFloor() time.Duration {
	if e.cfg.FgtDiagSSHFloorSec > 0 {
		return time.Duration(e.cfg.FgtDiagSSHFloorSec) * time.Second
	}
	return 2 * time.Second
}

// diagStaticInterval is how often the slow-changing data (media/optics/PoE
// capability/switch structure) is re-collected — much less often than the live
// data, so a big fabric is not re-walked for static facts every poll.
func (e *Extension) diagStaticInterval() time.Duration {
	return 12 * time.Hour
}

// runDiagIfAllowed requests one collection for a firewall. It enforces "at most
// one query per firewall at a time": if a query is already running, this request
// is queued (coalesced into a single pending slot that keeps the shortest
// requested interval) and drained when the running one finishes, so requests are
// serialized per firewall rather than dropped or run concurrently. The cadence
// gate (max(minInterval, floor) since the last run) still applies. Safe to call
// concurrently and from a page-view goroutine.
func (e *Extension) runDiagIfAllowed(fwID int, minInterval time.Duration) {
	if !e.cfg.FgtDiagSSHEnabled || e.firewallCreds == nil {
		return
	}
	if floor := e.diagFloor(); minInterval < floor {
		minInterval = floor
	}
	e.diagMu.Lock()
	st := e.diagState[fwID]
	if st == nil {
		st = &diagRunState{}
		e.diagState[fwID] = st
	}
	if st.busy {
		// Serialize: queue behind the in-flight run (single coalesced slot,
		// keeping the most urgent — shortest — interval).
		if !st.pending || minInterval < st.pendMin {
			st.pendMin = minInterval
		}
		st.pending = true
		e.diagMu.Unlock()
		return
	}
	if !st.last.IsZero() && time.Since(st.last) < minInterval {
		e.diagMu.Unlock()
		return // too soon and nothing running to queue behind
	}
	st.busy = true
	st.last = time.Now() // stamp at start so failures still count against the cadence
	e.diagMu.Unlock()
	e.runDiagSerial(fwID, st)
}

// runDiagSerial runs the collection, then drains a coalesced pending request if
// the cadence now permits — never concurrent with itself for a given firewall.
func (e *Extension) runDiagSerial(fwID int, st *diagRunState) {
	for {
		e.diagMu.Lock()
		withStatic := time.Since(st.lastStatic) >= e.diagStaticInterval()
		if withStatic {
			st.lastStatic = time.Now()
		}
		e.diagMu.Unlock()

		if err := e.collectDiagSafe(fwID, withStatic); err != nil {
			e.logger.Warn("fgt ssh diagnostics failed", "fw_id", fwID, "err", err)
			e.diagMu.Lock()
			st.lastStatic = time.Time{} // a failed run must not skip the next static refresh
			e.diagMu.Unlock()
		}

		e.diagMu.Lock()
		if st.pending && time.Since(st.last) >= st.pendMin {
			st.pending = false
			st.last = time.Now()
			e.diagMu.Unlock()
			continue // drain the queued request
		}
		st.pending = false
		st.busy = false
		e.diagMu.Unlock()
		return
	}
}

// diagWorker is the background sweep: it queries every switch-managing firewall
// on the configured cadence (default hourly). Page views drive the more frequent
// (but still rate-limited) refresh; this guarantees a floor of freshness even
// when nobody is looking at the topology.
func (e *Extension) diagWorker() {
	time.Sleep(30 * time.Second) // let the app boot and the first Graylog sweep run
	bg := time.Duration(e.cfg.FgtDiagSSHBackgroundSec) * time.Second
	if bg < time.Minute {
		bg = time.Hour
	}
	e.logger.Info("fgt ssh diagnostics worker started",
		"background", bg.String(), "view_min", time.Duration(e.cfg.FgtDiagSSHViewSec)*time.Second,
		"floor", e.diagFloor().String())
	tick := time.NewTicker(bg)
	defer tick.Stop()
	for {
		if fws, err := e.switchFirewalls(); err == nil {
			for _, fw := range fws {
				e.runDiagIfAllowed(fw.ID, bg)
				time.Sleep(2 * time.Second) // gentle stagger across devices
			}
		}
		<-tick.C
	}
}

// poeCapableSwitches returns the switch names known to have PoE ports (from the
// last static sweep's stored media), so live sweeps can gate `poe summary`
// without re-running the static `port-properties` capability query.
func (e *Extension) poeCapableSwitches(fwID int) map[string]bool {
	m := map[string]bool{}
	rows, err := e.db.Query("SELECT DISTINCT switch_name FROM stp_ports WHERE fw_id = ? AND poe != ''", fwID)
	if err != nil {
		return m
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			m[s] = true
		}
	}
	return m
}

// collectDiagSafe runs collectDiag with panic recovery. The collection runs in
// detached background goroutines (page-view refresh + the hourly worker), so a
// panic in the SSH runner or any CLI parser would otherwise crash the whole
// process. It also guarantees the caller's cleanup runs: an unrecovered panic
// would unwind past runDiagSerial and leave st.busy stuck true, permanently
// wedging this firewall's collector. A recovered panic is surfaced as an error
// so the caller resets the static-tier timer and retries next sweep.
func (e *Extension) collectDiagSafe(fwID int, withStatic bool) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			e.logger.Error("fgt ssh diagnostics panicked", "fw_id", fwID, "panic", rec)
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return e.collectDiag(fwID, withStatic)
}

// collectDiag opens one SSH session to the firewall, enumerates its managed
// switches and pulls per-port link state + STP/interlink data for each, storing
// the result. withStatic includes the slow-changing tier (media/optics/LLDP/
// congestion); live-only sweeps skip it and rely on the stored values, so a large
// fabric is not re-walked for static facts every poll. Credentials come from the
// host (decrypted) via FirewallCreds.
func (e *Extension) collectDiag(fwID int, withStatic bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	host, user, pass, port, err := e.firewallCreds(ctx, fwID)
	cancel()
	if err != nil {
		return fmt.Errorf("resolve credentials: %w", err)
	}
	if user == "" || pass == "" {
		return errors.New("no SSH credentials on file for this firewall")
	}
	if port <= 0 {
		port = 22
	}
	overall := time.Duration(e.cfg.FgtDiagSSHTimeoutSec) * time.Second
	if overall <= 0 {
		overall = 90 * time.Second
	}
	client, err := dialSSHDiag(host, user, pass, port, overall)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	start := time.Now()
	now := start.Format("2006-01-02 15:04:05")
	switches, macs := 0, 0
	base := "diagnose switch-controller switch-info "
	// Live sweeps gate `poe summary` on the switches known PoE-capable from the
	// last static sweep (port-properties, which reveals capability, is static-tier).
	var poeCap map[string]bool
	if !withStatic {
		poeCap = e.poeCapableSwitches(fwID)
	}
	// Persistence failures are logged AND accumulated (not just logged): a
	// swallowed static-tier store error would let runDiagSerial advance
	// lastStatic and skip the retry for a full static interval. Returning the
	// joined error forces the next sweep to re-collect the static tier.
	var storeErr error
	runErr := runSSHShell(client, overall, func(run func(string) string) {
		inv := parseSwitchInventory(run(base + "status"))
		for _, sw := range inv {
			portStats := run(base + "port-stats " + sw.Name)
			stp := run(base + "stp " + sw.Name)
			dot1x := run(base + "802.1X " + sw.Name)
			// Static tier: connector/media, optics and LLDP neighbors change rarely,
			// so they run only on static sweeps; the non-empty store-merge keeps
			// their values on live sweeps. Empty strings here → parsers return
			// nothing → stored values are preserved.
			portProps, modules, lldp := "", "", ""
			hasPoe, hasSFP := false, false
			if withStatic {
				portProps = run(base + "port-properties " + sw.Name)
				lldp = run(base + "lldp neighbors-detail " + sw.Name)
				for _, pp := range parsePortProperties(portProps) {
					hasPoe = hasPoe || pp.PoeCapable
					hasSFP = hasSFP || pp.HasSFP
				}
				if hasSFP {
					modules = run(base + "modules summary " + sw.Name)
				}
			} else {
				hasPoe = poeCap[sw.Name]
			}
			poe := ""
			if hasPoe {
				poe = run(base + "poe summary " + sw.Name)
			}
			ports, edges := buildDiagPorts(sw, portStats, stp, portProps, poe, modules, dot1x, lldp)
			// MC-LAG ICL detail (member ports + peer serial + split-brain/keepalive
			// health) for the switches that own an ICL trunk — the authoritative
			// core↔core cabling the STP view alone cannot resolve to ports.
			ownsICL := false
			for _, ed := range edges {
				if strings.Contains(ed.Trunk, "_ICL") {
					ownsICL = true
					break
				}
			}
			if ownsICL {
				if icl := parseMclagIcl(run(base + "mclag icl " + sw.Name)); icl != nil {
					note := ""
					if icl.SplitBrain != "" && !strings.EqualFold(icl.SplitBrain, "Disabled") {
						note = "⚠ split-brain: " + icl.SplitBrain
					}
					if icl.KeepaliveDrop > 0 {
						if note != "" {
							note += " · "
						}
						note += "keepalive drops: " + strconv.Itoa(icl.KeepaliveDrop)
					}
					edges = append(edges, SwitchEdge{SwitchSN: sw.Serial, SwitchName: sw.Name, Trunk: icl.Trunk, Ports: icl.Ports, Note: note})
				}
			}
			// Error-rate trending: flag ports actively accumulating errors since the
			// last poll (a failing cable/SFP), folded into the port health string.
			if deltas := e.storePortCounters(fwID, sw.Name, portStats, now); len(deltas) > 0 {
				for i := range ports {
					if d := deltas[ports[i].Port]; d > 0 {
						if ports[i].Health != "" {
							ports[i].Health += " "
						}
						ports[i].Health += "err-rate:+" + strconv.Itoa(d)
					}
				}
			}
			if serr := e.storeDiagStp(fwID, ports, now); serr != nil {
				e.logger.Warn("fgt diag: stp store failed", "fw_id", fwID, "switch", sw.Name, "err", serr)
				storeErr = errors.Join(storeErr, serr)
			}
			if serr := e.storeSwitchEdges(fwID, edges, now); serr != nil {
				e.logger.Warn("fgt diag: edge store failed", "fw_id", fwID, "switch", sw.Name, "err", serr)
				storeErr = errors.Join(storeErr, serr)
			}
			// 802.1X authenticated sessions → per-MAC RADIUS identity + dynamic VLAN.
			if serr := e.storeMacEnrichDot1x(fwID, parseDot1xSessions(dot1x), now); serr != nil {
				e.logger.Warn("fgt diag: dot1x identity store failed", "fw_id", fwID, "switch", sw.Name, "err", serr)
				storeErr = errors.Join(storeErr, serr)
			}
			// Switch health: fan (live) + STP topology-change churn (from the stp
			// output already pulled) + PoE budget (from poe summary already pulled)
			// + QoS congestion (static-tier — cumulative, low-churn).
			fan := parseFan(run(base + "fan " + sw.Name))
			cong := 0
			if withStatic {
				cong = parseQosCongestion(run(base + "qos-stats " + sw.Name))
			}
			poeUsed, poeTotal := parsePoeBudget(poe)
			sh := SwitchHealth{SwitchName: sw.Name, Fan: fan, Congestion: cong, Tcn: parseStpTcn(stp), PoeUsed: poeUsed, PoeTotal: poeTotal}
			if sh.Fan != "" || sh.Congestion > 0 || sh.Tcn > 0 || sh.PoeTotal > 0 {
				if serr := e.storeSwitchHealth(fwID, []SwitchHealth{sh}, now); serr != nil {
					e.logger.Warn("fgt diag: switch-health store failed", "fw_id", fwID, "switch", sw.Name, "err", serr)
					storeErr = errors.Join(storeErr, serr)
				}
			}
			switches++
		}
		// One fabric-wide MAC table (no-arg = all switches) → authoritative
		// device→access-port sightings, keyed the same way the Graylog MAC path is.
		if macPorts := parseMacTable(run(base + "mac-table")); len(macPorts) > 0 {
			if serr := e.storeMacSightings(fwID, macPorts, now); serr != nil {
				e.logger.Warn("fgt diag: mac-sighting store failed", "fw_id", fwID, "err", serr)
				storeErr = errors.Join(storeErr, serr)
			}
			macs = len(macPorts)
		}
		// ARP → MAC↔IP for device IP enrichment (the switch mac-table has no IP).
		if serr := e.storeMacEnrichArp(fwID, parseArp(run("get system arp")), now); serr != nil {
			e.logger.Warn("fgt diag: arp store failed", "fw_id", fwID, "err", serr)
			storeErr = errors.Join(storeErr, serr)
		}
		// Firewall node health: live CPU/mem/sessions/uptime + authoritative HA roles.
		health := parseFwHealth(run("get system performance status"), run("diagnose sys ha status"))
		if serr := e.storeFwHealth(fwID, health.summary(), now); serr != nil {
			e.logger.Warn("fgt diag: health store failed", "fw_id", fwID, "err", serr)
			storeErr = errors.Join(storeErr, serr)
		}
		// Live routing egress summary: which interface/tunnel carries how many
		// installed routes (and the live default) — reality vs the config's routes.
		if serr := e.storeLiveRoutes(fwID, parseRoutes(run("get router info routing-table all")), now); serr != nil {
			e.logger.Warn("fgt diag: live-routes store failed", "fw_id", fwID, "err", serr)
			storeErr = errors.Join(storeErr, serr)
		}
		// SD-WAN member SLA: live per-WAN loss/latency/jitter/state.
		if serr := e.storeSdwanHealth(fwID, parseSdwanHealth(run("diagnose sys sdwan health-check")), now); serr != nil {
			e.logger.Warn("fgt diag: sdwan store failed", "fw_id", fwID, "err", serr)
			storeErr = errors.Join(storeErr, serr)
		}
		// Interface throughput: byte-counter delta → live Mbps per FGT interface.
		if serr := e.storeIfaceThroughput(fwID, parseNetlinkIfaces(run("diagnose netlink interface list")), now); serr != nil {
			e.logger.Warn("fgt diag: iface-throughput store failed", "fw_id", fwID, "err", serr)
			storeErr = errors.Join(storeErr, serr)
		}
		// FortiAP → switch-port pin (static tier): each managed AP's own LLDP report
		// names the switch + port it is wired to. AP location rarely changes, so it
		// rides the static sweep; the non-empty merge keeps it across live sweeps.
		if withStatic {
			if serr := e.storeApLocation(fwID, parseWtpStatus(run("get wireless-controller wtp-status")), now); serr != nil {
				e.logger.Warn("fgt diag: ap-location store failed", "fw_id", fwID, "err", serr)
				storeErr = errors.Join(storeErr, serr)
			}
		}
		// Port-security (MAC-limit) violations across the whole fabric — one command.
		if serr := e.storeMacViolations(fwID, parseMacLimitViolations(run(base+"mac-limit-violations all")), now); serr != nil {
			e.logger.Warn("fgt diag: mac-violations store failed", "fw_id", fwID, "err", serr)
			storeErr = errors.Join(storeErr, serr)
		}
	})
	if serr := e.storeDiagStatus(fwID, CollectionStatus{
		LastRun: now, Switches: switches, DurationMs: int(time.Since(start).Milliseconds()), Static: withStatic,
	}, now); serr != nil {
		e.logger.Warn("fgt diag: status store failed", "fw_id", fwID, "err", serr)
		storeErr = errors.Join(storeErr, serr)
	}
	e.logger.Info("fgt ssh diagnostics collected", "fw_id", fwID, "host", host,
		"switches", switches, "mac_sightings", macs, "static", withStatic, "ms", time.Since(start).Milliseconds())
	return errors.Join(runErr, storeErr)
}

// dialSSHDiag connects to the FortiGate CLI. FortiOS advertises the password
// method (plus keyboard-interactive on some builds); offer both. Host keys are
// ignored, matching the backup transport, since the device fingerprint is not
// pinned in this tool.
func dialSSHDiag(host, user, pass string, port int, timeout time.Duration) (*ssh.Client, error) {
	ki := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		ans := make([]string, len(questions))
		for i := range ans {
			ans[i] = pass
		}
		return ans, nil
	})
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass), ki},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	return ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
}

// runSSHShell opens an interactive shell and hands fn a prompt-synchronized
// `run` closure. FortiOS is an interactive, paginated CLI, so we request a very
// tall PTY (pagination triggers on terminal height — a tall window keeps normal
// diagnostic output flowing without a "--More--" prompt, which a read-only admin
// cannot disable via `config system console`). Each run sends a command and
// reads until the shell prompt returns or a per-command deadline fires.
func runSSHShell(client *ssh.Client, overall time.Duration, fn func(run func(string) string)) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm", 10000, 511, modes); err != nil {
		return err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	sess.Stderr = io.Discard
	if err := sess.Shell(); err != nil {
		return err
	}

	chunks := make(chan []byte, 64)
	go func() {
		b := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(b)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, b[:n])
				chunks <- cp
			}
			if rerr != nil {
				close(chunks)
				return
			}
		}
	}()

	deadline := time.Now().Add(overall)
	// A hard failure — the session stream closing, a stdin write failing, or the
	// overall deadline elapsing — makes every subsequent run() return empty
	// output, which the parsers silently accept as "nothing observed". Latch the
	// first such failure so the caller treats the whole collection as failed
	// rather than persisting a half-empty snapshot as success. A per-command
	// timeout that is NOT the overall deadline stays soft (partial output, no
	// latch): one slow command must not abort an otherwise-healthy sweep.
	var shellErr error
	readUntilPrompt := func() string {
		var buf bytes.Buffer
		cmdDeadline := time.Now().Add(20 * time.Second)
		if cmdDeadline.After(deadline) {
			cmdDeadline = deadline
		}
		timer := time.NewTimer(time.Until(cmdDeadline))
		defer timer.Stop()
		for {
			select {
			case c, ok := <-chunks:
				if !ok {
					shellErr = errors.New("ssh session stream closed mid-command")
					return buf.String()
				}
				buf.Write(c)
				if isFortiPrompt(buf.String()) {
					return buf.String()
				}
			case <-timer.C:
				if !time.Now().Before(deadline) {
					shellErr = errors.New("ssh overall deadline exceeded")
				}
				return buf.String()
			}
		}
	}
	run := func(cmd string) string {
		if shellErr != nil {
			return "" // session already broken: stop issuing commands
		}
		if time.Now().After(deadline) {
			shellErr = errors.New("ssh overall deadline exceeded")
			return ""
		}
		if _, werr := io.WriteString(stdin, cmd+"\n"); werr != nil {
			shellErr = fmt.Errorf("ssh stdin write: %w", werr)
			return ""
		}
		return readUntilPrompt()
	}

	readUntilPrompt() // consume the login banner / first prompt
	fn(run)
	_, _ = io.WriteString(stdin, "exit\n")
	return shellErr
}

// isFortiPrompt reports whether the buffer currently ends at a FortiOS CLI
// prompt ("hostname(...) $ " or "... # "), the signal a command has finished.
func isFortiPrompt(s string) bool {
	s = strings.TrimRight(s, " \r\n")
	return strings.HasSuffix(s, "$") || strings.HasSuffix(s, "#")
}

// portDiagCommands are the per-port switch-info subcommands run on demand. All
// accept an explicit "<switch> <port>" argument (verified live), so each returns
// small, port-scoped output rather than a whole-switch dump.
var portDiagCommands = []struct{ title, sub string }{
	{"Port status & counters", "port-stats"},
	{"Physical properties", "port-properties"},
	{"802.1X sessions", "802.1X"},
	{"802.1X dynamic ACL", "802.1X-dacl"},
	{"ACL counters", "acl-counters"},
	{"Port-security (MAC-limit) violations", "mac-limit-violations interface"},
	{"QoS / congestion", "qos-stats"},
}

// collectPortDiag runs the live per-port diagnostics for one switch port on
// demand (the faceplate "Run diagnostics" button). It reuses the same SSH
// transport and the per-firewall single-flight guard as the background sweep, so
// only one SSH session ever runs per device; if one is already in flight it
// returns errDiagBusy. sw and port MUST already be validated (reDiagName) —
// they are interpolated straight into the CLI command.
func (e *Extension) collectPortDiag(fwID int, sw, port string) (*PortDiag, error) {
	if e.firewallCreds == nil {
		return nil, errors.New("ssh diagnostics not configured")
	}
	// Single-flight per firewall: never run concurrently with a sweep or another
	// on-demand query. Unlike a sweep this does not queue — the caller surfaces
	// "busy, try again" to the user.
	e.diagMu.Lock()
	st := e.diagState[fwID]
	if st == nil {
		st = &diagRunState{}
		e.diagState[fwID] = st
	}
	if st.busy {
		e.diagMu.Unlock()
		return nil, errDiagBusy
	}
	// Cooldown for repeated on-demand queries, kept on its own clock (lastPortDiag)
	// rather than st.last: stamping st.last here would push back the next background
	// sweep. errDiagBusy maps to HTTP 429, the right signal for both "already
	// running" and "too soon since the last on-demand query".
	if !st.lastPortDiag.IsZero() && time.Since(st.lastPortDiag) < e.diagFloor() {
		e.diagMu.Unlock()
		return nil, errDiagBusy
	}
	st.busy = true
	st.lastPortDiag = time.Now()
	e.diagMu.Unlock()
	defer func() {
		e.diagMu.Lock()
		st.busy = false
		e.diagMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	host, user, pass, prt, err := e.firewallCreds(ctx, fwID)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("resolve credentials: %w", err)
	}
	if user == "" || pass == "" {
		return nil, errors.New("no SSH credentials on file for this firewall")
	}
	if prt <= 0 {
		prt = 22
	}
	overall := time.Duration(e.cfg.FgtDiagSSHTimeoutSec) * time.Second
	if overall <= 0 {
		overall = 90 * time.Second
	}
	client, err := dialSSHDiag(host, user, pass, prt, overall)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	pd := &PortDiag{Switch: sw, Port: port, Ran: time.Now().Format("2006-01-02 15:04:05")}
	base := "diagnose switch-controller switch-info "
	runErr := runSSHShell(client, overall, func(run func(string) string) {
		for _, c := range portDiagCommands {
			out := cleanDiagOutput(run(base + c.sub + " " + sw + " " + port))
			pd.Sections = append(pd.Sections, PortDiagSection{
				Title: c.title, Command: c.sub + " " + sw + " " + port,
				// OK reflects only whether the switch rejected the command; a
				// legitimately empty response (e.g. no 802.1X session / no
				// violations on this port) is a successful, healthy result.
				Output: out, OK: !diagCmdFailed(out),
			})
		}
	})
	if runErr != nil {
		return nil, runErr
	}
	return pd, nil
}

// cleanDiagOutput strips the echoed command line and the trailing CLI prompt
// from a single command's raw shell output, leaving just the port data.
func cleanDiagOutput(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimRight(ln, " \r")
		if isFortiPrompt(t) {
			continue // drop the returned prompt line(s)
		}
		out = append(out, t)
	}
	// Drop leading blank lines and the echoed command.
	for len(out) > 0 {
		f := strings.TrimSpace(out[0])
		if f == "" || strings.HasPrefix(f, "diagnose ") || strings.HasPrefix(f, "get ") {
			out = out[1:]
			continue
		}
		break
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// diagCmdFailed reports whether a command's output is a FortiOS CLI rejection
// (unsupported subcommand / parse error) rather than real data.
func diagCmdFailed(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "parse error") ||
		strings.Contains(l, "unknown action") ||
		strings.Contains(l, "command fail")
}
