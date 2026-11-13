package main

import (
	"net/netip"
	"strings"

	"github.com/djosix/ripdns/token"
	"github.com/miekg/dns"
)

// MatchKind classifies a query name relative to the base domain.
type MatchKind int

const (
	NotOurs MatchKind = iota // outside the base domain: relay or refuse
	Apex                     // the base domain itself
	Valid                    // under the base domain with a valid token
	Invalid                  // under the base domain, rejected by the rules
)

func (k MatchKind) String() string {
	switch k {
	case NotOurs:
		return "not-ours"
	case Apex:
		return "apex"
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	}
	return "unknown"
}

// Matcher applies the subdomain and token rules to query names.
type Matcher struct {
	suffix     string // "." + base + "." (lowercase)
	apex       string // base + "." (lowercase)
	tokenLevel int    // 1-based level holding the token; 0 = any level
	maxLevels  int    // max subdomain levels; 0 = unlimited
	maxTokens  int    // max "-" separated tokens considered; 0 = unlimited
	codec      *token.Codec
}

func NewMatcher(cfg *Config, codec *token.Codec) *Matcher {
	return &Matcher{
		suffix:     "." + cfg.BaseDomain + ".",
		apex:       cfg.BaseDomain + ".",
		tokenLevel: cfg.TokenLevel,
		maxLevels:  cfg.MaxLevels,
		maxTokens:  cfg.MaxTokens,
		codec:      codec,
	}
}

// Match classifies qname and, for Valid, returns the decoded IPv4 address.
//
// Levels count from the base domain outwards: in a.b.c.route.example.com with
// base route.example.com, "c" is level 1, "b" is level 2 and "a" is level 3.
func (m *Matcher) Match(qname string) (MatchKind, netip.Addr) {
	name := strings.ToLower(dns.Fqdn(qname))
	if name == m.apex {
		return Apex, netip.Addr{}
	}
	if !strings.HasSuffix(name, m.suffix) {
		return NotOurs, netip.Addr{}
	}
	labels := dns.SplitDomainName(strings.TrimSuffix(name, m.suffix))
	n := len(labels)
	if n == 0 {
		return Invalid, netip.Addr{}
	}
	if m.maxLevels > 0 && n > m.maxLevels {
		return Invalid, netip.Addr{}
	}

	var tokens []string
	if m.tokenLevel > 0 {
		if n < m.tokenLevel {
			return Invalid, netip.Addr{}
		}
		tokens = strings.Split(labels[n-m.tokenLevel], "-")
	} else {
		for i := n - 1; i >= 0; i-- { // level 1 first
			tokens = append(tokens, strings.Split(labels[i], "-")...)
		}
	}
	if m.maxTokens > 0 && len(tokens) > m.maxTokens {
		return Invalid, netip.Addr{}
	}

	for _, t := range tokens {
		if ip, ok := m.codec.Decode(t); ok {
			return Valid, ip
		}
	}
	return Invalid, netip.Addr{}
}
