// Package mailer sends failure-notification emails over SMTP with STARTTLS,
// mirroring the original send_email helper (best-effort, errors are logged).
package mailer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

// Mailer holds SMTP settings.
type Mailer struct {
	cfg    *config.Config
	logger *slog.Logger
}

// New returns a Mailer bound to the given config.
func New(cfg *config.Config, logger *slog.Logger) *Mailer {
	return &Mailer{cfg: cfg, logger: logger}
}

// Send delivers a plaintext message. It never returns an error: like the
// Python version it logs failures and moves on.
func (m *Mailer) Send(subject, body, to string) {
	c := m.cfg
	if c.MailServer == "" || c.MailUser == "" || c.MailPassword == "" {
		m.logger.Error("email configuration missing: MAIL_SERVER, MAIL_USER, or MAIL_PASSWORD not set")
		return
	}
	if err := m.send(subject, body, to); err != nil {
		m.logger.Error("failed to send email notification", "to", to, "err", err)
		return
	}
	m.logger.Info("email notification sent", "to", to, "subject", subject)
}

// sanitizeHeader removes CR and LF so a value cannot inject additional SMTP
// headers or terminate the header block early (header injection).
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

func smtpAuthentication(advertised, username, password, host string) (smtp.Auth, error) {
	mechanisms := strings.Fields(advertised)
	if supportsSMTPAuth(mechanisms, "PLAIN") {
		return smtp.PlainAuth("", username, password, host), nil
	}
	if supportsSMTPAuth(mechanisms, "LOGIN") {
		return &loginAuth{username: username, password: password, host: host}, nil
	}
	return nil, errors.New("smtp: server does not advertise a supported AUTH mechanism (PLAIN or LOGIN)")
}

func supportsSMTPAuth(mechanisms []string, wanted string) bool {
	for _, mechanism := range mechanisms {
		if strings.EqualFold(mechanism, wanted) {
			return true
		}
	}
	return false
}

type loginAuth struct {
	username string
	password string
	host     string
	step     int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("smtp: LOGIN authentication requires TLS")
	}
	if !strings.EqualFold(server.Name, a.host) {
		return "", nil, errors.New("smtp: wrong host name for LOGIN authentication")
	}
	if !supportsSMTPAuth(server.Auth, "LOGIN") {
		return "", nil, errors.New("smtp: server does not support LOGIN authentication")
	}
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch a.step {
	case 0:
		a.step++
		return []byte(a.username), nil
	case 1:
		a.step++
		return []byte(a.password), nil
	default:
		return nil, errors.New("smtp: unexpected LOGIN authentication challenge")
	}
}

func (m *Mailer) send(subject, body, to string) error {
	c := m.cfg
	addr := net.JoinHostPort(c.MailServer, strconv.Itoa(c.MailPort))

	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	client, err := smtp.NewClient(conn, c.MailServer)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Fail closed: never fall back to plaintext transport or unauthenticated
	// delivery, which would expose the message and the SMTP credentials.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: c.MailServer}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else {
		return fmt.Errorf("smtp: server does not advertise STARTTLS; refusing to send over plaintext")
	}

	if ok, mechanisms := client.Extension("AUTH"); ok {
		auth, err := smtpAuthentication(mechanisms, c.MailUser, c.MailPassword, c.MailServer)
		if err != nil {
			return err
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	} else {
		return fmt.Errorf("smtp: server does not advertise AUTH; refusing to send unauthenticated")
	}

	if err := client.Mail(c.MailUser); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	// Strip CR/LF from header values so attacker-influenced data (e.g. a
	// firewall FQDN embedded in the subject) cannot inject additional SMTP
	// headers or prematurely terminate the header block.
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		sanitizeHeader(c.MailUser), sanitizeHeader(to), sanitizeHeader(subject), body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return client.Quit()
}
