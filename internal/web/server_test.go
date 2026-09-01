package web

import (
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/arumes31/fortigate-scp-backup/internal/sshhostkey"
	"golang.org/x/crypto/ssh"
)

func TestServerHostKeyCallbackConcurrentSetters(t *testing.T) {
	manager, err := sshhostkey.New(filepath.Join(t.TempDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	callback := func(string, net.Addr, ssh.PublicKey) error { return nil }
	server := &Server{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 1_000 {
			server.SetHostKeyCallback(callback)
		}
	})
	wg.Go(func() {
		<-start
		for range 1_000 {
			server.SetHostKeyManager(manager)
		}
	})
	wg.Go(func() {
		<-start
		for range 1_000 {
			_ = server.hostKeyCallbackForSSH()
		}
	})
	close(start)
	wg.Wait()
}
