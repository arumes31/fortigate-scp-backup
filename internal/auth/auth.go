// Package auth implements the credential checks used at login: RADIUS
// (PAP) authentication and TOTP verification. Local password comparison stays
// in the store/handlers because passwords are kept as plaintext for database
// compatibility.
package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/pquerna/otp/totp"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

// Authenticator performs RADIUS and TOTP checks.
type Authenticator struct {
	cfg    *config.Config
	logger *slog.Logger
}

// New returns an Authenticator bound to the given config.
func New(cfg *config.Config, logger *slog.Logger) *Authenticator {
	return &Authenticator{cfg: cfg, logger: logger}
}

// VerifyRadius returns true when the RADIUS server accepts the credentials.
// When RADIUS is disabled it always returns false (matching the Python guard).
func (a *Authenticator) VerifyRadius(username, password string) bool {
	if !a.cfg.RadiusEnabled {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	packet := radius.New(radius.CodeAccessRequest, []byte(a.cfg.RadiusSecret))
	if err := rfc2865.UserName_SetString(packet, username); err != nil {
		a.logger.Error("radius: set username", "err", err)
		return false
	}
	if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
		a.logger.Error("radius: set password", "err", err)
		return false
	}

	addr := a.cfg.RadiusServer + ":" + itoa(a.cfg.RadiusPort)
	response, err := radius.Exchange(ctx, packet, addr)
	if err != nil {
		a.logger.Error("radius: exchange failed", "user", username, "server", addr, "err", err)
		return false
	}
	if response.Code == radius.CodeAccessAccept {
		return true
	}
	a.logger.Debug("radius: rejected", "user", username, "code", response.Code)
	return false
}

// VerifyTOTP validates a 6-digit code against a base32 secret.
func (a *Authenticator) VerifyTOTP(secret, code string) bool {
	if secret == "" {
		return false
	}
	return totp.Validate(code, secret)
}

func itoa(n int) string {
	// Small dependency-free integer to string for the port number.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
