// Package auth implements the credential checks used at login: RADIUS
// (PAP) authentication and TOTP verification. Local password comparison stays
// in the store/handlers because passwords are kept as plaintext for database
// compatibility.
package auth

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

// radiusTimeout bounds a single RADIUS exchange. It is generous (60s) because
// some RADIUS servers front a push/mobile MFA prompt: the Access-Request is not
// answered until the user approves (or the OTP is confirmed) on their phone.
const radiusTimeout = 60 * time.Second

// Authenticator performs RADIUS and TOTP checks.
type Authenticator struct {
	cfg    *config.Config
	logger *slog.Logger

	// usedTOTP tracks recently accepted TOTP codes (keyed by secret+code) so a
	// valid code cannot be replayed within its validity window: pquerna/otp's
	// Validate only checks time-skew and performs no one-time-use enforcement.
	totpMu   sync.Mutex
	usedTOTP map[string]time.Time
}

// New returns an Authenticator bound to the given config.
func New(cfg *config.Config, logger *slog.Logger) *Authenticator {
	return &Authenticator{cfg: cfg, logger: logger, usedTOTP: make(map[string]time.Time)}
}

// VerifyRadius returns true when the RADIUS server accepts the credentials.
// When RADIUS is disabled it always returns false (matching the Python guard).
func (a *Authenticator) VerifyRadius(username, password string) bool {
	if !a.cfg.RadiusEnabled {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), radiusTimeout)
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

	addr := net.JoinHostPort(a.cfg.RadiusServer, strconv.Itoa(a.cfg.RadiusPort))
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

// totpReplayWindow covers the full acceptance span of a code (current 30s
// period plus one skewed period on either side) with a safety margin.
const totpReplayWindow = 3 * 30 * time.Second

// VerifyTOTP validates a 6-digit code against a base32 secret. A code is
// accepted at most once per totpReplayWindow: replays within the validity
// window are rejected even though they are still time-valid.
func (a *Authenticator) VerifyTOTP(secret, code string) bool {
	if secret == "" {
		return false
	}

	a.totpMu.Lock()
	if a.usedTOTP == nil {
		a.usedTOTP = make(map[string]time.Time)
	}
	key := secret + "|" + code
	if usedAt, seen := a.usedTOTP[key]; seen && time.Since(usedAt) <= totpReplayWindow {
		a.totpMu.Unlock()
		return false
	}
	a.totpMu.Unlock()

	if !totp.Validate(code, secret) {
		return false
	}

	a.totpMu.Lock()
	a.usedTOTP[key] = time.Now()
	for k, usedAt := range a.usedTOTP {
		if time.Since(usedAt) > totpReplayWindow {
			delete(a.usedTOTP, k)
		}
	}
	a.totpMu.Unlock()
	return true
}
