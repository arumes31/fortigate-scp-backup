// Package auth implements the credential checks used at login: RADIUS
// (PAP) authentication and TOTP verification. Local password comparison stays
// in the store/handlers because passwords are kept as plaintext for database
// compatibility.
package auth

import (
	"context"
	"log/slog"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
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

const totpPeriod = 30

// VerifyTOTP validates a six-digit code and returns its exact accepted time
// step. The caller must atomically consume that step before creating a session.
func (a *Authenticator) VerifyTOTP(secret, code string) (int64, bool) {
	return verifyTOTPAt(secret, code, time.Now().UTC())
}

// verifyTOTPAt validates current and adjacent time steps around a fixed time.
func verifyTOTPAt(secret, code string, now time.Time) (int64, bool) {
	if secret == "" {
		return 0, false
	}
	current := int64(math.Floor(float64(now.Unix()) / totpPeriod))
	for _, step := range []int64{current, current + 1, current - 1} {
		valid, err := hotp.ValidateCustom(code, uint64(step), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if valid {
			return step, true
		}
	}
	return 0, false
}
