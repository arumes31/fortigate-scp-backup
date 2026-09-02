package sshhostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type testAddr string

func (testAddr) Network() string  { return "tcp" }
func (a testAddr) String() string { return string(a) }

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestManagerLearnsUnknownHostAndPersistsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh", "known_hosts")
	manager, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	key := testPublicKey(t)
	address := "fw.example.com:22"
	if err := manager.Callback()(address, testAddr("192.0.2.1:22"), key); err != nil {
		t.Fatalf("first connection rejected: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), knownhosts.Line([]string{address}, key)) {
		t.Fatalf("learned key missing from known_hosts: %q", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("known_hosts mode = %o, want 600", got)
		}
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Callback()(address, testAddr("192.0.2.2:22"), key); err != nil {
		t.Fatalf("persisted key rejected: %v", err)
	}
}

func TestManagerRejectsChangedKeyUntilExplicitlyAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	manager, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	oldKey := testPublicKey(t)
	newKey := testPublicKey(t)
	address := "fw.example.com:2222"
	remote := testAddr("192.0.2.1:2222")
	if err := manager.Callback()(address, remote, oldKey); err != nil {
		t.Fatal(err)
	}

	err = manager.Callback()(address, remote, newKey)
	if err == nil {
		t.Fatal("changed key was accepted before approval")
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		t.Fatalf("changed key error = %v, want wrapped knownhosts mismatch", err)
	}
	pending, ok := manager.Pending("fw.example.com", 2222)
	if !ok {
		t.Fatal("changed key was not exposed as pending")
	}
	if pending.Fingerprint != ssh.FingerprintSHA256(newKey) || pending.Algorithm != newKey.Type() {
		t.Fatalf("pending key = %+v", pending)
	}

	accepted, err := manager.Accept("fw.example.com", 2222)
	if err != nil {
		t.Fatalf("accept changed key: %v", err)
	}
	if accepted.Fingerprint != pending.Fingerprint {
		t.Fatalf("accepted fingerprint = %q, want %q", accepted.Fingerprint, pending.Fingerprint)
	}
	if err := manager.Callback()(address, remote, newKey); err != nil {
		t.Fatalf("approved key rejected: %v", err)
	}
	if err := manager.Callback()(address, remote, oldKey); err == nil {
		t.Fatal("old key remained trusted after replacement")
	}
}

func TestManagerAcceptRequiresDetectedReplacement(t *testing.T) {
	manager, err := New(filepath.Join(t.TempDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Accept("fw.example.com", 22); !errors.Is(err, ErrNoPendingKey) {
		t.Fatalf("Accept without mismatch = %v, want ErrNoPendingKey", err)
	}
}

var _ net.Addr = testAddr("")
