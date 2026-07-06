// Package mailer sends failure-notification emails over SMTP with STARTTLS,
// mirroring the original send_email helper (best-effort, errors are logged).
package mailer

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
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
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	// Fail closed: never fall back to plaintext transport or unauthenticated
	// delivery, which would expose the message and the SMTP credentials.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: c.MailServer}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else {
		return fmt.Errorf("smtp: server does not advertise STARTTLS; refusing to send over plaintext")
	}

	if ok, _ := client.Extension("AUTH"); ok {
		auth := smtp.PlainAuth("", c.MailUser, c.MailPassword, c.MailServer)
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
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		c.MailUser, to, subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return client.Quit()
}
