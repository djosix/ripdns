package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/djosix/ripdns/token"
	"github.com/miekg/dns"
)

func freePort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// startRipdns runs Serve on a free local port and returns its address.
func startRipdns(t *testing.T, cfg *Config) string {
	t.Helper()
	addr := freePort(t)
	cfg.Listen = []string{addr}
	codec, err := token.New([]byte(cfg.Secret))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(cfg, NewMatcher(cfg, codec), log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg, h, log) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	c := &dns.Client{Timeout: 100 * time.Millisecond}
	m := new(dns.Msg).SetQuestion(cfg.BaseDomain+".", dns.TypeSOA)
	for range 50 {
		if _, _, err := c.Exchange(m, addr); err == nil {
			return addr
		}
	}
	t.Fatal("ripdns did not start")
	return ""
}

// startUpstream runs a fake recursive resolver that answers every A query
// with 9.9.9.9 and every TXT query with 100 records (too large for 512 bytes).
func startUpstream(t *testing.T) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		m.RecursionAvailable = true
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			rr, _ := dns.NewRR(q.Name + " 60 IN A 9.9.9.9")
			m.Answer = append(m.Answer, rr)
		case dns.TypeTXT:
			for i := range 100 {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN TXT \"record %03d padding padding\"", q.Name, i))
				m.Answer = append(m.Answer, rr)
			}
		}
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			m.Truncate(dns.MinMsgSize)
		}
		w.WriteMsg(m)
	})

	addr := freePort(t)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go s.ActivateAndServe()
		<-started
		t.Cleanup(func() { s.Shutdown() })
	}
	return addr
}

func testConfig(upstreams ...string) *Config {
	return &Config{
		BaseDomain:      "route.example.com",
		Secret:          testSecret,
		TokenLevel:      1,
		TTL:             300,
		NegativeTTL:     60,
		NameServers:     []string{"ns1.example.com.", "ns2.example.com."},
		Upstreams:       upstreams,
		UpstreamTimeout: 300 * time.Millisecond,
		RelayAllow:      []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
}

func query(t *testing.T, addr, network, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: network, Timeout: 2 * time.Second}
	m := new(dns.Msg).SetQuestion(name, qtype)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s %s: %v", network, name, dns.TypeToString[qtype], err)
	}
	return resp
}

func expect(t *testing.T, resp *dns.Msg, rcode int, answers ...string) {
	t.Helper()
	if resp.Rcode != rcode {
		t.Errorf("%s: rcode %s, want %s", resp.Question[0].Name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
	}
	var got []string
	for _, rr := range resp.Answer {
		got = append(got, strings.TrimPrefix(rr.String(), rr.Header().String()))
	}
	if strings.Join(got, "|") != strings.Join(answers, "|") {
		t.Errorf("%s: answers %q, want %q", resp.Question[0].Name, got, answers)
	}
}

func expectSOA(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if len(resp.Ns) != 1 || resp.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("%s: authority %v, want one SOA", resp.Question[0].Name, resp.Ns)
	}
}

func TestAuthoritative(t *testing.T) {
	addr := startRipdns(t, testConfig())
	valid := "app-" + tok1234 + ".route.example.com."

	for _, network := range []string{"udp", "tcp"} {
		resp := query(t, addr, network, valid, dns.TypeA)
		expect(t, resp, dns.RcodeSuccess, "1.2.3.4")
		if !resp.Authoritative || resp.Answer[0].Header().Ttl != 300 {
			t.Errorf("%s: aa=%v ttl=%d", network, resp.Authoritative, resp.Answer[0].Header().Ttl)
		}
	}

	resp := query(t, addr, "udp", "x.y."+strings.ToUpper(tok1234)+".route.example.com.", dns.TypeA)
	expect(t, resp, dns.RcodeSuccess, "1.2.3.4")

	resp = query(t, addr, "udp", valid, dns.TypeAAAA)
	expect(t, resp, dns.RcodeSuccess)
	expectSOA(t, resp)

	for _, name := range []string{fakeHex + ".route.example.com.", "www.route.example.com."} {
		resp = query(t, addr, "udp", name, dns.TypeA)
		expect(t, resp, dns.RcodeNameError)
		expectSOA(t, resp)
	}

	resp = query(t, addr, "udp", "route.example.com.", dns.TypeSOA)
	expect(t, resp, dns.RcodeSuccess, "ns1.example.com. hostmaster.route.example.com. 1 3600 600 86400 60")
	resp = query(t, addr, "udp", "route.example.com.", dns.TypeNS)
	expect(t, resp, dns.RcodeSuccess, "ns1.example.com.", "ns2.example.com.")
	resp = query(t, addr, "udp", "route.example.com.", dns.TypeA)
	expect(t, resp, dns.RcodeSuccess)
	expectSOA(t, resp)

	// No upstream configured: other names are refused.
	resp = query(t, addr, "udp", "example.org.", dns.TypeA)
	expect(t, resp, dns.RcodeRefused)
}

func TestRelay(t *testing.T) {
	addr := startRipdns(t, testConfig(startUpstream(t)))

	resp := query(t, addr, "udp", "example.org.", dns.TypeA)
	expect(t, resp, dns.RcodeSuccess, "9.9.9.9")
	if !resp.RecursionAvailable {
		t.Error("relayed answer without RA")
	}

	resp = query(t, addr, "udp", "big.example.org.", dns.TypeTXT)
	if !resp.Truncated {
		t.Errorf("large UDP answer not truncated (%d records)", len(resp.Answer))
	}
	resp = query(t, addr, "tcp", "big.example.org.", dns.TypeTXT)
	if resp.Truncated || len(resp.Answer) != 100 {
		t.Errorf("TCP answer: tc=%v records=%d", resp.Truncated, len(resp.Answer))
	}

	// Our own names are never relayed.
	resp = query(t, addr, "udp", tok1234+".route.example.com.", dns.TypeA)
	expect(t, resp, dns.RcodeSuccess, "1.2.3.4")
}

func TestRelayFailover(t *testing.T) {
	dead := freePort(t)
	addr := startRipdns(t, testConfig(dead, startUpstream(t)))
	expect(t, query(t, addr, "udp", "example.org.", dns.TypeA), dns.RcodeSuccess, "9.9.9.9")
}

func TestRelayAllUpstreamsDown(t *testing.T) {
	addr := startRipdns(t, testConfig(freePort(t)))
	expect(t, query(t, addr, "udp", "example.org.", dns.TypeA), dns.RcodeServerFailure)
}

func TestRelayACL(t *testing.T) {
	cfg := testConfig(startUpstream(t))
	cfg.RelayAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	addr := startRipdns(t, cfg)

	expect(t, query(t, addr, "udp", "example.org.", dns.TypeA), dns.RcodeRefused)
	// Authoritative answers do not depend on the relay ACL.
	expect(t, query(t, addr, "udp", tok1234+".route.example.com.", dns.TypeA), dns.RcodeSuccess, "1.2.3.4")
}
