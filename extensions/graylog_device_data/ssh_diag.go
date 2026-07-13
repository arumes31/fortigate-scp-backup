package graylogdevicedata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file runs the live FortiGate CLI diagnostics collector. It reuses each
// firewall's stored SSH credentials to pull authoritative per-switch-port link
// state, STP role/state and interlink trunks — the data the Graylog logs only
// reveal partially (a capped, event-driven stream). The store layer (stp_ports,
// switch_edges) and the topology frontend are shared with the log path, so the
// faceplate needs no changes; SSH just supplies a fresher, complete overlay.

// diagFloor is the hard lower bound on query spacing per device, regardless of
// the requested cadence — a safety valve so nothing can hammer a firewall.
func (e *Extension) diagFloor() time.Duration {
	if e.cfg.FgtDiagSSHFloorSec > 0 {
		return time.Duration(e.cfg.FgtDiagSSHFloorSec) * time.Second
	}
	return 10 * time.Second
}

// diagAllow reserves the per-device slot: it returns true (and marks the device
// busy + stamps the attempt time) only when no query is in flight AND at least
// max(minInterval, floor) has elapsed since the last attempt. The caller must
// pair a true return with diagDone.
func (e *Extension) diagAllow(fwID int, minInterval time.Duration) bool {
	if floor := e.diagFloor(); minInterval < floor {
		minInterval = floor
	}
	e.diagMu.Lock()
	defer e.diagMu.Unlock()
	if e.diagBusy[fwID] {
		return false
	}
	if t, ok := e.diagLast[fwID]; ok && time.Since(t) < minInterval {
		return false
	}
	e.diagBusy[fwID] = true
	e.diagLast[fwID] = time.Now() // stamp at start so failures still count against the cadence
	return true
}

func (e *Extension) diagDone(fwID int) {
	e.diagMu.Lock()
	delete(e.diagBusy, fwID)
	e.diagMu.Unlock()
}

// runDiagIfAllowed runs one diagnostics pass for a device if the rate gate
// permits it (minInterval = the caller's cadence, clamped up to the hard floor).
// It is safe to call concurrently and from a page-view goroutine: a denied slot
// simply returns.
func (e *Extension) runDiagIfAllowed(fwID int, minInterval time.Duration) {
	if !e.cfg.FgtDiagSSHEnabled || e.firewallCreds == nil {
		return
	}
	if !e.diagAllow(fwID, minInterval) {
		return
	}
	defer e.diagDone(fwID)
	if err := e.collectDiag(fwID); err != nil {
		e.logger.Warn("fgt ssh diagnostics failed", "fw_id", fwID, "err", err)
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

// collectDiag opens one SSH session to the firewall, enumerates its managed
// switches and pulls per-port link state + STP/interlink data for each, storing
// the result. Credentials come from the host (decrypted) via FirewallCreds.
func (e *Extension) collectDiag(fwID int) error {
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

	now := time.Now().Format("2006-01-02 15:04:05")
	switches := 0
	runErr := runSSHShell(client, overall, func(run func(string) string) {
		inv := parseSwitchInventory(run("diagnose switch-controller switch-info status"))
		for _, sw := range inv {
			portStats := run("diagnose switch-controller switch-info port-stats " + sw.Name)
			stp := run("diagnose switch-controller switch-info stp " + sw.Name)
			ports, edges := buildDiagPorts(sw, portStats, stp)
			if serr := e.storeDiagStp(fwID, ports, now); serr != nil {
				e.logger.Warn("fgt diag: stp store failed", "fw_id", fwID, "switch", sw.Name, "err", serr)
			}
			if serr := e.storeSwitchEdges(fwID, edges, now); serr != nil {
				e.logger.Warn("fgt diag: edge store failed", "fw_id", fwID, "switch", sw.Name, "err", serr)
			}
			switches++
		}
	})
	e.logger.Info("fgt ssh diagnostics collected", "fw_id", fwID, "host", host, "switches", switches)
	return runErr
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
					return buf.String()
				}
				buf.Write(c)
				if isFortiPrompt(buf.String()) {
					return buf.String()
				}
			case <-timer.C:
				return buf.String()
			}
		}
	}
	run := func(cmd string) string {
		if time.Now().After(deadline) {
			return ""
		}
		if _, werr := io.WriteString(stdin, cmd+"\n"); werr != nil {
			return ""
		}
		return readUntilPrompt()
	}

	readUntilPrompt() // consume the login banner / first prompt
	fn(run)
	_, _ = io.WriteString(stdin, "exit\n")
	return nil
}

// isFortiPrompt reports whether the buffer currently ends at a FortiOS CLI
// prompt ("hostname(...) $ " or "... # "), the signal a command has finished.
func isFortiPrompt(s string) bool {
	s = strings.TrimRight(s, " \r\n")
	return strings.HasSuffix(s, "$") || strings.HasSuffix(s, "#")
}
