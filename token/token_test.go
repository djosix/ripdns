package token

import (
	"net/netip"
	"strings"
	"testing"
)

// Vectors are shared with the Python reference implementation in README.md.
var vectors = []struct{ ip, token string }{
	{"0.0.0.0", "26628404061e6c09"},
	{"1.2.3.4", "4e225c24f6397855"},
	{"10.0.0.1", "760f678008a894c3"},
	{"192.168.1.100", "7ce72d1256395a05"},
	{"255.255.255.255", "258ef3f04c9d5e71"},
}

func mustNew(t *testing.T, secret string) *Codec {
	t.Helper()
	c, err := New([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVectors(t *testing.T) {
	c := mustNew(t, "test-secret")
	for _, v := range vectors {
		got, err := c.Encode(netip.MustParseAddr(v.ip))
		if err != nil || got != v.token {
			t.Errorf("Encode(%s) = %q, %v; want %q", v.ip, got, err, v.token)
		}
		for _, s := range []string{v.token, strings.ToUpper(v.token)} {
			ip, ok := c.Decode(s)
			if !ok || ip.String() != v.ip {
				t.Errorf("Decode(%s) = %v, %v; want %s", s, ip, ok, v.ip)
			}
		}
	}
}

func TestRoundTrip(t *testing.T) {
	c := mustNew(t, "another secret")
	for i := range 10000 {
		ip := netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), byte(i * 7), byte(i * 13)})
		tok, err := c.Encode(ip)
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != Len {
			t.Fatalf("len(%q) = %d", tok, len(tok))
		}
		got, ok := c.Decode(tok)
		if !ok || got != ip {
			t.Fatalf("Decode(Encode(%s)) = %s, %v", ip, got, ok)
		}
	}
}

func TestRejects(t *testing.T) {
	c := mustNew(t, "test-secret")
	other := mustNew(t, "wrong-secret")
	tok := vectors[1].token

	if _, ok := other.Decode(tok); ok {
		t.Error("token accepted with the wrong secret")
	}
	for i := range len(tok) {
		b := []byte(tok)
		b[i] = "0123456789abcdef"[(strings.IndexByte("0123456789abcdef", b[i])+1)%16]
		if _, ok := c.Decode(string(b)); ok {
			t.Errorf("tampered token %s accepted", b)
		}
	}
	for _, s := range []string{"", "4e225c24f63978", "4e225c24f639785500", "4e225c24f63978zz", "xn--4e225c24f63"} {
		if _, ok := c.Decode(s); ok {
			t.Errorf("Decode(%q) accepted", s)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) succeeded")
	}
	c := mustNew(t, "s")
	if _, err := c.Encode(netip.MustParseAddr("::1")); err == nil {
		t.Error("Encode(::1) succeeded")
	}
	tok, err := c.Encode(netip.MustParseAddr("::ffff:1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if ip, _ := c.Decode(tok); ip.String() != "1.2.3.4" {
		t.Errorf("mapped address decoded to %s", ip)
	}
}
