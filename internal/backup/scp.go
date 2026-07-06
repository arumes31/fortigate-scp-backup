package backup

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	scp "github.com/bramvdbogaerde/go-scp"
	"golang.org/x/crypto/ssh"
)

// transfer establishes an SSH connection to the firewall, performs a best-effort
// remote existence check and pulls the configuration file to localPath via SCP.
//
// It mirrors the connection/transfer portion of the Python backup_firewall: any
// error returned here corresponds to Python's (socket.timeout, SSHException,
// SCPException) branch and is therefore treated as retryable by the caller.
func (s *Service) transfer(fqdn, username, password string, sshPort int, remotePath, localPath string, timeout int) error {
	clientConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}

	addr := net.JoinHostPort(fqdn, strconv.Itoa(sshPort))
	conn, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh connect: %w", err)
	}
	defer conn.Close()

	// Keep-alive goroutine, matching paramiko transport.set_keepalive(60).
	// Best-effort: failures are ignored. Stopped via done before conn closes.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_, _, _ = conn.SendRequest("keepalive@openssh.com", true, nil)
			}
		}
	}()

	s.logger.Debug("SSH connection established with keep-alive", "fqdn", fqdn)

	// Best-effort remote file check (non-fatal), mirroring `ls REMOTE_CONFIG_PATH`.
	s.remoteCheck(conn, remotePath, fqdn)

	client, err := scp.NewClientBySSH(conn)
	if err != nil {
		return fmt.Errorf("scp client: %w", err)
	}
	defer client.Close()

	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	s.logger.Debug("Attempting SCP transfer", "remote", remotePath, "local", localPath)
	copyErr := client.CopyFromRemote(ctx, file, remotePath)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("scp transfer: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close local file: %w", closeErr)
	}

	s.logger.Debug("SCP transfer completed", "fqdn", fqdn)
	return nil
}

// remoteCheck runs `ls <remotePath>` over a throwaway session and logs the
// outcome. It never fails the backup: any error is logged and ignored so the
// SCP transfer is still attempted, exactly like the Python implementation.
func (s *Service) remoteCheck(conn *ssh.Client, remotePath, fqdn string) {
	session, err := conn.NewSession()
	if err != nil {
		s.logger.Warn("Failed to open session for remote file check, proceeding with SCP transfer",
			"fqdn", fqdn, "path", remotePath, "err", err)
		return
	}
	defer session.Close()

	out, err := session.CombinedOutput("ls " + remotePath)
	if err != nil {
		s.logger.Warn("Remote file check failed, proceeding with SCP transfer",
			"fqdn", fqdn, "path", remotePath, "err", err, "output", strings.TrimSpace(string(out)))
		return
	}
	s.logger.Debug("Remote file exists", "fqdn", fqdn, "path", remotePath)
}
