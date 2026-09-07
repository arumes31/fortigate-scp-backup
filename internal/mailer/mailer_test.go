package mailer

import (
	"crypto/tls"
	"net/smtp"
	"testing"
)

// TestSMTPTLSConfigRequiresTLS12 pins the explicit SMTP transport floor.
func TestSMTPTLSConfigRequiresTLS12(t *testing.T) {
	t.Parallel()
	config := smtpTLSConfig("smtp.example.com")
	if config.ServerName != "smtp.example.com" {
		t.Fatalf("ServerName = %q", config.ServerName)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", config.MinVersion)
	}
}

func TestSMTPAuthenticationSelectsAdvertisedMechanism(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		advertised string
		want       string
		wantError  bool
	}{
		{name: "plain", advertised: "PLAIN", want: "PLAIN"},
		{name: "login", advertised: "LOGIN", want: "LOGIN"},
		{name: "prefer plain", advertised: "LOGIN PLAIN", want: "PLAIN"},
		{name: "case insensitive", advertised: "login", want: "LOGIN"},
		{name: "unsupported", advertised: "XOAUTH2", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			auth, err := smtpAuthentication(
				test.advertised,
				"sender@example.com",
				"password",
				"smtp.example.com",
			)
			if test.wantError {
				if err == nil {
					t.Fatal("smtpAuthentication() succeeded without a supported mechanism")
				}
				return
			}
			if err != nil {
				t.Fatalf("smtpAuthentication() error = %v", err)
			}
			protocol, _, err := auth.Start(&smtp.ServerInfo{
				Name: "smtp.example.com",
				TLS:  true,
				Auth: []string{test.want},
			})
			if err != nil {
				t.Fatalf("Auth.Start() error = %v", err)
			}
			if protocol != test.want {
				t.Fatalf("Auth.Start() protocol = %q, want %q", protocol, test.want)
			}
		})
	}
}

func TestLoginAuthenticationRespondsWithUsernameAndPassword(t *testing.T) {
	t.Parallel()

	auth, err := smtpAuthentication(
		"LOGIN",
		"sender@example.com",
		"password",
		"smtp.example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Start(&smtp.ServerInfo{
		Name: "smtp.example.com",
		TLS:  true,
		Auth: []string{"LOGIN"},
	}); err != nil {
		t.Fatalf("Auth.Start() error = %v", err)
	}
	username, err := auth.Next([]byte("Username:"), true)
	if err != nil || string(username) != "sender@example.com" {
		t.Fatalf("first Auth.Next() = %q, %v", username, err)
	}
	password, err := auth.Next([]byte("Password:"), true)
	if err != nil || string(password) != "password" {
		t.Fatalf("second Auth.Next() = %q, %v", password, err)
	}
	if response, err := auth.Next(nil, false); err != nil || response != nil {
		t.Fatalf("final Auth.Next() = %q, %v, want nil, nil", response, err)
	}
}
