package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
)

// ednsSize is the UDP payload size advertised in our own responses.
const ednsSize = 1232

// Handler answers queries for the base domain and relays everything else.
type Handler struct {
	cfg     *Config
	matcher *Matcher
	log     *slog.Logger
	udp     *dns.Client
	tcp     *dns.Client
	soa     *dns.SOA
}

func NewHandler(cfg *Config, matcher *Matcher, log *slog.Logger) *Handler {
	apex := cfg.BaseDomain + "."
	mname := apex
	if len(cfg.NameServers) > 0 {
		mname = cfg.NameServers[0]
	}
	return &Handler{
		cfg:     cfg,
		matcher: matcher,
		log:     log,
		udp:     &dns.Client{Net: "udp", Timeout: cfg.UpstreamTimeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: cfg.UpstreamTimeout},
		soa: &dns.SOA{
			Hdr:     dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: cfg.NegativeTTL},
			Ns:      mname,
			Mbox:    "hostmaster." + apex,
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  cfg.NegativeTTL,
		},
	}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		h.write(w, r, m)
		return
	}
	q := r.Question[0]
	kind, ip := h.matcher.Match(q.Name)
	if kind == NotOurs {
		h.relay(w, r)
		return
	}
	h.answer(w, r, q, kind, ip)
}

func (h *Handler) answer(w dns.ResponseWriter, r *dns.Msg, q dns.Question, kind MatchKind, ip netip.Addr) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = h.canRelay(w.RemoteAddr())

	nodata := func() { m.Ns = []dns.RR{h.soa} }
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: h.cfg.TTL}
	}

	switch {
	case q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY:
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused

	case kind == Invalid:
		m.Rcode = dns.RcodeNameError
		nodata()

	case kind == Valid:
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: ip.AsSlice()})
		} else {
			nodata()
		}

	case kind == Apex:
		if q.Qtype == dns.TypeSOA || q.Qtype == dns.TypeANY {
			soa := *h.soa
			soa.Hdr.Name = q.Name
			m.Answer = append(m.Answer, &soa)
		}
		if q.Qtype == dns.TypeNS || q.Qtype == dns.TypeANY {
			for _, ns := range h.cfg.NameServers {
				m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(dns.TypeNS), Ns: ns})
			}
		}
		if len(m.Answer) == 0 {
			nodata()
		}
	}

	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(ednsSize, opt.Do())
	}

	h.log.Debug("answer",
		"client", w.RemoteAddr().String(),
		"name", q.Name,
		"type", dns.TypeToString[q.Qtype],
		"match", kind.String(),
		"ip", ip,
		"rcode", dns.RcodeToString[m.Rcode],
	)
	h.write(w, r, m)
}

func (h *Handler) relay(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	if !h.canRelay(w.RemoteAddr()) {
		h.log.Debug("refused", "client", w.RemoteAddr().String(), "name", q.Name, "type", dns.TypeToString[q.Qtype])
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		h.write(w, r, m)
		return
	}

	client := h.udp
	if isTCP(w) {
		client = h.tcp
	}
	for _, up := range h.cfg.Upstreams {
		resp, _, err := client.Exchange(r, up)
		if err != nil {
			h.log.Debug("upstream failed", "upstream", up, "name", q.Name, "err", err)
			continue
		}
		h.log.Debug("relay",
			"client", w.RemoteAddr().String(),
			"name", q.Name,
			"type", dns.TypeToString[q.Qtype],
			"upstream", up,
			"rcode", dns.RcodeToString[resp.Rcode],
		)
		h.write(w, r, resp)
		return
	}

	h.log.Warn("all upstreams failed", "name", q.Name, "type", dns.TypeToString[q.Qtype])
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	h.write(w, r, m)
}

func (h *Handler) canRelay(addr net.Addr) bool {
	if len(h.cfg.Upstreams) == 0 {
		return false
	}
	ip, ok := addrIP(addr)
	if !ok {
		return false
	}
	for _, p := range h.cfg.RelayAllow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// write sends m, truncating it to the client's UDP payload size if needed.
func (h *Handler) write(w dns.ResponseWriter, r, m *dns.Msg) {
	if !isTCP(w) {
		size := dns.MinMsgSize
		if opt := r.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
			size = int(opt.UDPSize())
		}
		m.Truncate(size)
	}
	if err := w.WriteMsg(m); err != nil {
		h.log.Debug("write failed", "client", w.RemoteAddr().String(), "err", err)
	}
}

func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

func addrIP(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		return netip.Addr{}, false
	}
	nip, ok := netip.AddrFromSlice(ip)
	return nip.Unmap(), ok
}

// Serve listens on every address in cfg.Listen over UDP and TCP until ctx is
// canceled. Listener errors are returned before serving starts.
func Serve(ctx context.Context, cfg *Config, handler dns.Handler, log *slog.Logger) error {
	var servers []*dns.Server
	closeAll := func() {
		for _, s := range servers {
			if s.PacketConn != nil {
				s.PacketConn.Close()
			}
			if s.Listener != nil {
				s.Listener.Close()
			}
		}
	}

	for _, addr := range cfg.Listen {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			closeAll()
			return err
		}
		servers = append(servers, &dns.Server{PacketConn: pc, Handler: handler})
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			return err
		}
		servers = append(servers, &dns.Server{Listener: ln, Handler: handler})
		log.Info("listening", "addr", addr)
	}

	errc := make(chan error, len(servers))
	var wg, started sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		started.Add(1)
		s.NotifyStartedFunc = started.Done
		go func() {
			defer wg.Done()
			if err := s.ActivateAndServe(); err != nil {
				errc <- err
			}
		}()
	}
	// Shutdown fails on a server that has not started yet, so wait first.
	started.Wait()

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	for _, s := range servers {
		s.Shutdown()
	}
	wg.Wait()
	return err
}
