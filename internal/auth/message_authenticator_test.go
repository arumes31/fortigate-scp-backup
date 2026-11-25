package auth

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // RFC 3579 mandates HMAC-MD5.
	"encoding/binary"
	"testing"

	"layeh.com/radius"
)

// rawAccessAccept hand-assembles an Access-Accept whose Message-Authenticator
// is computed independently of the code under test (RFC 3579 §3.2).
func rawAccessAccept(t *testing.T, secret []byte, requestAuth [16]byte, filterID string) []byte {
	t.Helper()
	attrs := append([]byte{11, byte(2 + len(filterID))}, filterID...)
	attrs = append(attrs, 80, 18)
	maOffset := 20 + len(attrs)
	attrs = append(attrs, make([]byte, 16)...)
	b := make([]byte, 20, 20+len(attrs))
	b[0], b[1] = byte(radius.CodeAccessAccept), 7
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(attrs)))
	copy(b[4:20], requestAuth[:])
	b = append(b, attrs...)
	mac := hmac.New(md5.New, secret)
	mac.Write(b)
	copy(b[maOffset:], mac.Sum(nil))
	copy(b[4:20], []byte("response-auth-16")) // the real header carries the Response Authenticator
	return b
}

func TestValidResponseAuthenticator(t *testing.T) {
	secret := []byte("shared-secret-0123456789")
	requestAuth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	parse := func(b []byte) *radius.Packet {
		p, err := radius.Parse(b, secret)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	raw := rawAccessAccept(t, secret, requestAuth, "fortisafe-ops")
	if !validResponseAuthenticator(parse(raw), requestAuth) {
		t.Fatal("valid Message-Authenticator rejected")
	}

	tampered := append([]byte(nil), raw...)
	tampered[22] ^= 1 // flip a Filter-Id byte
	if validResponseAuthenticator(parse(tampered), requestAuth) {
		t.Fatal("tampered attributes accepted")
	}
	if validResponseAuthenticator(parse(raw), [16]byte{}) {
		t.Fatal("response bound to another request accepted")
	}
	missing := radius.New(radius.CodeAccessAccept, secret)
	if validResponseAuthenticator(missing, requestAuth) {
		t.Fatal("response without Message-Authenticator accepted")
	}
}

// The HMAC must cover attributes in wire order, including duplicates and a
// Message-Authenticator that is not last.
func TestValidResponseAuthenticatorWireOrder(t *testing.T) {
	secret := []byte("shared-secret-0123456789")
	requestAuth := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6}
	attr := func(typ byte, v string) []byte { return append([]byte{typ, byte(2 + len(v))}, v...) }
	attrs := []byte{80, 18}
	attrs = append(attrs, make([]byte, 16)...)
	attrs = append(attrs, attr(25, "class-z")...)
	attrs = append(attrs, attr(11, "fortisafe-ops")...)
	attrs = append(attrs, attr(11, "another-group")...)
	attrs = append(attrs, attr(25, "class-a")...)
	b := make([]byte, 20, 20+len(attrs))
	b[0], b[1] = byte(radius.CodeAccessAccept), 3
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(attrs)))
	copy(b[4:20], requestAuth[:])
	b = append(b, attrs...)
	mac := hmac.New(md5.New, secret)
	mac.Write(b)
	copy(b[22:38], mac.Sum(nil))
	copy(b[4:20], []byte("response-auth-16"))
	p, err := radius.Parse(b, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !validResponseAuthenticator(p, requestAuth) {
		t.Fatal("valid Message-Authenticator with reordered attributes rejected")
	}
}
