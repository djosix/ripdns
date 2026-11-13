package main

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultRelayAllow = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7"

// Config holds all settings, read from RIPDNS_* environment variables.
type Config struct {
	BaseDomain      string // lowercase, no trailing dot
	Secret          string
	Listen          []string
	TokenLevel      int
	MaxLevels       int
	MaxTokens       int
	TTL             uint32
	NegativeTTL     uint32
	NameServers     []string // FQDNs
	Upstreams       []string // host:port
	UpstreamTimeout time.Duration
	RelayAllow      []netip.Prefix
	LogLevel        slog.Level
}

// LoadDotEnv sets variables from a KEY=VALUE file without overriding variables
// already present in the environment. Blank lines and lines starting with "#"
// are ignored; an optional "export " prefix and matching surrounding quotes
// are stripped.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected KEY=VALUE", path, lineNo)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
	return sc.Err()
}

// LoadConfig reads the configuration from the environment. When needServer is
// false, only the settings required for encoding and decoding are validated.
func LoadConfig(needServer bool) (*Config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	env := func(key, def string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return def
	}
	intVar := func(key string, def int) int {
		s := env(key, strconv.Itoa(def))
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			fail("%s: want a non-negative integer, got %q", key, s)
		}
		return v
	}
	ttlVar := func(key string, def uint32) uint32 {
		s := env(key, strconv.FormatUint(uint64(def), 10))
		v, err := strconv.ParseUint(s, 10, 31)
		if err != nil {
			fail("%s: want a TTL in seconds, got %q", key, s)
		}
		return uint32(v)
	}

	c := &Config{
		BaseDomain:  strings.Trim(strings.ToLower(env("RIPDNS_BASE_DOMAIN", "")), "."),
		Secret:      os.Getenv("RIPDNS_SECRET"),
		Listen:      splitList(env("RIPDNS_LISTEN", ":53")),
		TokenLevel:  intVar("RIPDNS_TOKEN_LEVEL", 1),
		MaxLevels:   intVar("RIPDNS_MAX_LEVELS", 0),
		MaxTokens:   intVar("RIPDNS_MAX_TOKENS", 0),
		TTL:         ttlVar("RIPDNS_TTL", 300),
		NegativeTTL: ttlVar("RIPDNS_NEGATIVE_TTL", 60),
	}

	if c.Secret == "" {
		fail("RIPDNS_SECRET is required")
	} else if len(c.Secret) < 16 {
		slog.Warn("RIPDNS_SECRET is short; use at least 32 random characters (openssl rand -hex 32)")
	}
	if c.BaseDomain != "" {
		if _, ok := dns.IsDomainName(c.BaseDomain); !ok {
			fail("RIPDNS_BASE_DOMAIN: invalid domain %q", c.BaseDomain)
		}
	}

	if !needServer {
		return c, errors.Join(errs...)
	}

	if c.BaseDomain == "" {
		fail("RIPDNS_BASE_DOMAIN is required")
	}
	if c.MaxLevels > 0 && c.TokenLevel > c.MaxLevels {
		fail("RIPDNS_TOKEN_LEVEL (%d) exceeds RIPDNS_MAX_LEVELS (%d)", c.TokenLevel, c.MaxLevels)
	}
	if len(c.Listen) == 0 {
		fail("RIPDNS_LISTEN is empty")
	}

	for _, ns := range splitList(env("RIPDNS_NS", "")) {
		if _, ok := dns.IsDomainName(ns); !ok {
			fail("RIPDNS_NS: invalid domain %q", ns)
			continue
		}
		c.NameServers = append(c.NameServers, dns.Fqdn(strings.ToLower(ns)))
	}

	for _, up := range splitList(env("RIPDNS_UPSTREAM", "")) {
		if _, _, err := net.SplitHostPort(up); err != nil {
			up = net.JoinHostPort(strings.Trim(up, "[]"), "53")
		}
		c.Upstreams = append(c.Upstreams, up)
	}
	timeout := env("RIPDNS_UPSTREAM_TIMEOUT", "2s")
	d, err := time.ParseDuration(timeout)
	if err != nil || d <= 0 {
		fail("RIPDNS_UPSTREAM_TIMEOUT: want a duration like 2s, got %q", timeout)
	}
	c.UpstreamTimeout = d

	for _, s := range splitList(env("RIPDNS_RELAY_ALLOW", defaultRelayAllow)) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			addr, err2 := netip.ParseAddr(s)
			if err2 != nil {
				fail("RIPDNS_RELAY_ALLOW: invalid CIDR %q", s)
				continue
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		c.RelayAllow = append(c.RelayAllow, p.Masked())
	}

	if err := c.LogLevel.UnmarshalText([]byte(env("RIPDNS_LOG_LEVEL", "info"))); err != nil {
		fail("RIPDNS_LOG_LEVEL: %v", err)
	}

	return c, errors.Join(errs...)
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
