// Package sshhostkey implements persistent trust-on-first-use verification for
// every FortiGate SSH connection made by the application.
package sshhostkey

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrNoPendingKey means no rejected replacement key is awaiting approval for
// the requested host.
var ErrNoPendingKey = errors.New("no pending SSH host key")

// PendingKey is the safe, displayable part of a rejected replacement key.
type PendingKey struct {
	Host        string
	Algorithm   string
	Fingerprint string
}

type pendingKey struct {
	PendingKey
	address       string
	remoteAddress string
	key           ssh.PublicKey
}

// Manager owns one OpenSSH known_hosts file and serializes verification with
// updates so concurrent first connections cannot enroll different keys.
type Manager struct {
	mu       sync.Mutex
	path     string
	callback ssh.HostKeyCallback
	pending  map[string]pendingKey
}

// New opens or creates an application-managed OpenSSH known_hosts file.
func New(path string) (*Manager, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("ssh known_hosts path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ssh known_hosts directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("create ssh known_hosts: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create ssh known_hosts: %w", err)
	}

	m := &Manager{path: path, pending: make(map[string]pendingKey)}
	if err := m.reloadLocked(); err != nil {
		return nil, err
	}
	return m, nil
}

// Callback returns the shared callback used by SCP and live SSH clients.
func (m *Manager) Callback() ssh.HostKeyCallback { return m.check }

// Pending returns a rejected replacement key for a configured host, if any.
func (m *Manager) Pending(host string, port int) (PendingKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, ok := m.pending[normalizedAddress(host, port)]
	return pending.PendingKey, ok
}

// Accept replaces the stored key with the exact replacement most recently
// rejected for host and port.
func (m *Manager) Accept(host string, port int) (PendingKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized := normalizedAddress(host, port)
	pending, ok := m.pending[normalized]
	if !ok {
		return PendingKey{}, ErrNoPendingKey
	}
	remote := stringAddr(pending.remoteAddress)
	err := m.callback(pending.address, remote, pending.key)
	if err == nil {
		delete(m.pending, normalized)
		return pending.PendingKey, nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return PendingKey{}, fmt.Errorf("verify pending ssh host key: %w", err)
	}
	if len(keyErr.Want) == 0 {
		if err := m.appendLocked(pending.address, pending.key); err != nil {
			return PendingKey{}, err
		}
	} else if err := m.replaceLocked(keyErr.Want, pending.address, pending.key); err != nil {
		return PendingKey{}, err
	}
	if err := m.reloadLocked(); err != nil {
		return PendingKey{}, err
	}
	if err := m.callback(pending.address, remote, pending.key); err != nil {
		return PendingKey{}, fmt.Errorf("verify accepted ssh host key: %w", err)
	}
	delete(m.pending, normalized)
	return pending.PendingKey, nil
}

func (m *Manager) check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if remote == nil {
		return errors.New("ssh host key callback received no remote address")
	}

	err := m.callback(hostname, remote, key)
	if err == nil {
		delete(m.pending, knownhosts.Normalize(hostname))
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return err
	}
	normalized := knownhosts.Normalize(hostname)
	if len(keyErr.Want) == 0 {
		if err := m.appendLocked(hostname, key); err != nil {
			return fmt.Errorf("learn ssh host key for %s: %w", normalized, err)
		}
		if err := m.reloadLocked(); err != nil {
			return err
		}
		if err := m.callback(hostname, remote, key); err != nil {
			return fmt.Errorf("verify learned ssh host key for %s: %w", normalized, err)
		}
		delete(m.pending, normalized)
		return nil
	}

	fingerprint := ssh.FingerprintSHA256(key)
	m.pending[normalized] = pendingKey{
		PendingKey:    PendingKey{Host: normalized, Algorithm: key.Type(), Fingerprint: fingerprint},
		address:       hostname,
		remoteAddress: remote.String(),
		key:           key,
	}
	return fmt.Errorf("ssh host key changed for %s; detected %s; accept the new key in the firewall list: %w",
		normalized, fingerprint, err)
}

func (m *Manager) appendLocked(address string, key ssh.PublicKey) error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read ssh known_hosts: %w", err)
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, knownhosts.Line([]string{address}, key)...)
	data = append(data, '\n')
	if err := writeFileAtomic(m.path, data); err != nil {
		return fmt.Errorf("write ssh known_hosts: %w", err)
	}
	return nil
}

func (m *Manager) replaceLocked(want []knownhosts.KnownKey, address string, key ssh.PublicKey) error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read ssh known_hosts: %w", err)
	}
	wantedLines := make(map[int]struct{}, len(want))
	for _, known := range want {
		if filepath.Clean(known.Filename) == filepath.Clean(m.path) {
			wantedLines[known.Line] = struct{}{}
		}
	}
	if len(wantedLines) == 0 {
		return errors.New("pending ssh host key has no replaceable known_hosts entry")
	}

	lines := bytes.Split(data, []byte{'\n'})
	replacement := []byte(knownhosts.Line([]string{address}, key))
	out := make([][]byte, 0, len(lines))
	replaced := false
	for i, line := range lines {
		if _, ok := wantedLines[i+1]; !ok {
			out = append(out, line)
			continue
		}
		if !replaced {
			out = append(out, replacement)
			replaced = true
		}
	}
	if !replaced {
		return errors.New("pending ssh host key entry changed before acceptance")
	}
	if err := writeFileAtomic(m.path, bytes.Join(out, []byte{'\n'})); err != nil {
		return fmt.Errorf("replace ssh host key: %w", err)
	}
	return nil
}

func (m *Manager) reloadLocked() error {
	callback, err := knownhosts.New(m.path)
	if err != nil {
		return fmt.Errorf("load ssh known_hosts: %w", err)
	}
	m.callback = callback
	return nil
}

func normalizedAddress(host string, port int) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))
}

type stringAddr string

func (stringAddr) Network() string  { return "tcp" }
func (a stringAddr) String() string { return string(a) }

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ssh-known-hosts-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
