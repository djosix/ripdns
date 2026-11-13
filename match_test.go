package main

import (
	"testing"

	"github.com/djosix/ripdns/token"
)

const (
	testSecret = "test-secret"
	tok1234    = "4e225c24f6397855" // 1.2.3.4
	tok10001   = "760f678008a894c3" // 10.0.0.1
	fakeHex    = "0123456789abcdef" // well-formed but unsigned
)

func newTestMatcher(t *testing.T, tokenLevel, maxLevels, maxTokens int) *Matcher {
	t.Helper()
	codec, err := token.New([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return NewMatcher(&Config{
		BaseDomain: "route.example.com",
		TokenLevel: tokenLevel,
		MaxLevels:  maxLevels,
		MaxTokens:  maxTokens,
	}, codec)
}

func TestMatch(t *testing.T) {
	type tc struct {
		name string
		kind MatchKind
		ip   string
	}
	tests := []struct {
		desc                             string
		tokenLevel, maxLevels, maxTokens int
		cases                            []tc
	}{
		{"defaults: level 1, unlimited", 1, 0, 0, []tc{
			{"route.example.com.", Apex, ""},
			{"ROUTE.Example.COM", Apex, ""},
			{"example.com.", NotOurs, ""},
			{"xroute.example.com.", NotOurs, ""},
			{"google.com.", NotOurs, ""},
			{tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"4E225C24F6397855.Route.Example.Com.", Valid, "1.2.3.4"},
			{"a.b.c." + tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"app-" + tok1234 + "-v2.route.example.com.", Valid, "1.2.3.4"},
			{fakeHex + "-" + tok10001 + "-" + tok1234 + ".route.example.com.", Valid, "10.0.0.1"},
			{tok1234 + ".x.route.example.com.", Invalid, ""},
			{fakeHex + ".route.example.com.", Invalid, ""},
			{"www.route.example.com.", Invalid, ""},
		}},
		{"max levels 1", 1, 1, 0, []tc{
			{tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"a." + tok1234 + ".route.example.com.", Invalid, ""},
		}},
		{"max levels 3", 1, 3, 0, []tc{
			{"a.b." + tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"a.b.c." + tok1234 + ".route.example.com.", Invalid, ""},
		}},
		{"max tokens 1", 1, 0, 1, []tc{
			{tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"a-b.c-d." + tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"app-" + tok1234 + ".route.example.com.", Invalid, ""},
		}},
		{"max tokens 2", 1, 0, 2, []tc{
			{"app-" + tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{"app-" + tok1234 + "-v2.route.example.com.", Invalid, ""},
		}},
		{"token level 2", 2, 0, 0, []tc{
			{tok1234 + ".anything.route.example.com.", Valid, "1.2.3.4"},
			{"a." + tok1234 + ".anything.route.example.com.", Valid, "1.2.3.4"},
			{tok1234 + ".route.example.com.", Invalid, ""},
			{"anything." + tok1234 + ".route.example.com.", Invalid, ""},
		}},
		{"any level", 0, 0, 0, []tc{
			{tok1234 + ".route.example.com.", Valid, "1.2.3.4"},
			{tok1234 + ".x.y.route.example.com.", Valid, "1.2.3.4"},
			{"a-" + tok1234 + ".x.route.example.com.", Valid, "1.2.3.4"},
			{tok1234 + "." + tok10001 + ".route.example.com.", Valid, "10.0.0.1"},
			{"a.b.route.example.com.", Invalid, ""},
		}},
		{"any level, max tokens 3 summed over levels", 0, 0, 3, []tc{
			{"a." + tok1234 + ".b.route.example.com.", Valid, "1.2.3.4"},
			{"a-b." + tok1234 + ".c.route.example.com.", Invalid, ""},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			m := newTestMatcher(t, tt.tokenLevel, tt.maxLevels, tt.maxTokens)
			for _, c := range tt.cases {
				kind, ip := m.Match(c.name)
				gotIP := ""
				if ip.IsValid() {
					gotIP = ip.String()
				}
				if kind != c.kind || gotIP != c.ip {
					t.Errorf("Match(%s) = %s %q; want %s %q", c.name, kind, gotIP, c.kind, c.ip)
				}
			}
		})
	}
}
