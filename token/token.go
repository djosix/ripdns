// Package token implements the ripdns IPv4 token format.
//
// A token is 16 hex characters (8 bytes):
//
//	tag   = HMAC-SHA256(secret, "ripdns/v1/mac" || ip)[0:4]
//	pad   = HMAC-SHA256(secret, "ripdns/v1/pad" || tag)[0:4]
//	token = hex( (ip XOR pad) || tag )
//
// ip is the 4 raw bytes of the IPv4 address and secret is used as raw bytes.
// Decoding derives pad from tag, recovers ip, and accepts the token only if
// tag == HMAC-SHA256(secret, "ripdns/v1/mac" || ip)[0:4]. Without the secret
// the IPv4 address cannot be recovered and a valid token cannot be forged.
// Encoding emits lowercase hex; decoding is case-insensitive, because DNS
// names are case-insensitive and resolvers may randomize case (0x20 bits).
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
)

// Len is the length of a token in hex characters.
const Len = 16

var (
	labelMAC = []byte("ripdns/v1/mac")
	labelPad = []byte("ripdns/v1/pad")
)

// Codec encodes and decodes tokens with a fixed secret.
type Codec struct {
	secret []byte
}

// New returns a Codec for secret, which must not be empty.
func New(secret []byte) (*Codec, error) {
	if len(secret) == 0 {
		return nil, errors.New("token: empty secret")
	}
	return &Codec{secret: append([]byte(nil), secret...)}, nil
}

func (c *Codec) prf(label, data []byte) [4]byte {
	h := hmac.New(sha256.New, c.secret)
	h.Write(label)
	h.Write(data)
	var out [4]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Encode returns the token for an IPv4 address (IPv4-mapped IPv6 is accepted).
func (c *Codec) Encode(ip netip.Addr) (string, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return "", errors.New("token: not an IPv4 address")
	}
	raw := ip.As4()
	tag := c.prf(labelMAC, raw[:])
	pad := c.prf(labelPad, tag[:])
	var buf [8]byte
	for i := range 4 {
		buf[i] = raw[i] ^ pad[i]
	}
	copy(buf[4:], tag[:])
	return hex.EncodeToString(buf[:]), nil
}

// Decode returns the IPv4 address in s if s is a valid token for this secret.
func (c *Codec) Decode(s string) (netip.Addr, bool) {
	if len(s) != Len {
		return netip.Addr{}, false
	}
	var buf [8]byte
	if _, err := hex.Decode(buf[:], []byte(s)); err != nil {
		return netip.Addr{}, false
	}
	tag := buf[4:]
	pad := c.prf(labelPad, tag)
	var raw [4]byte
	for i := range 4 {
		raw[i] = buf[i] ^ pad[i]
	}
	want := c.prf(labelMAC, raw[:])
	if !hmac.Equal(tag, want[:]) {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(raw), true
}
