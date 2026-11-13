package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := `# comment
RIPDNS_BASE_DOMAIN=Route.Example.COM.
export RIPDNS_SECRET="s3cret value"
RIPDNS_UPSTREAM = 1.1.1.1, [2606:4700:4700::1111]:53 ,9.9.9.9:5353
RIPDNS_TOKEN_LEVEL=5
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RIPDNS_TOKEN_LEVEL", "2") // the real environment wins
	t.Setenv("RIPDNS_BASE_DOMAIN", "")
	os.Unsetenv("RIPDNS_BASE_DOMAIN")
	t.Setenv("RIPDNS_SECRET", "")
	os.Unsetenv("RIPDNS_SECRET")
	t.Setenv("RIPDNS_UPSTREAM", "")
	os.Unsetenv("RIPDNS_UPSTREAM")

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseDomain != "route.example.com" || cfg.Secret != "s3cret value" || cfg.TokenLevel != 2 {
		t.Errorf("got base=%q secret=%q level=%d", cfg.BaseDomain, cfg.Secret, cfg.TokenLevel)
	}
	want := []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53", "9.9.9.9:5353"}
	if !slices.Equal(cfg.Upstreams, want) {
		t.Errorf("upstreams %q, want %q", cfg.Upstreams, want)
	}
	if len(cfg.RelayAllow) == 0 || !slices.Equal(cfg.Listen, []string{":53"}) {
		t.Errorf("defaults: relay_allow=%v listen=%v", cfg.RelayAllow, cfg.Listen)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"RIPDNS_SECRET": ""}, "RIPDNS_SECRET is required"},
		{map[string]string{"RIPDNS_BASE_DOMAIN": ""}, "RIPDNS_BASE_DOMAIN is required"},
		{map[string]string{"RIPDNS_TOKEN_LEVEL": "2", "RIPDNS_MAX_LEVELS": "1"}, "exceeds RIPDNS_MAX_LEVELS"},
		{map[string]string{"RIPDNS_MAX_TOKENS": "-1"}, "RIPDNS_MAX_TOKENS"},
		{map[string]string{"RIPDNS_RELAY_ALLOW": "10.0.0.0/33"}, "RIPDNS_RELAY_ALLOW"},
		{map[string]string{"RIPDNS_UPSTREAM_TIMEOUT": "2"}, "RIPDNS_UPSTREAM_TIMEOUT"},
	}
	for _, tt := range tests {
		t.Setenv("RIPDNS_BASE_DOMAIN", "route.example.com")
		t.Setenv("RIPDNS_SECRET", "0123456789abcdef0123456789abcdef")
		for _, k := range []string{"RIPDNS_TOKEN_LEVEL", "RIPDNS_MAX_LEVELS", "RIPDNS_MAX_TOKENS", "RIPDNS_RELAY_ALLOW", "RIPDNS_UPSTREAM_TIMEOUT"} {
			t.Setenv(k, "")
		}
		for k, v := range tt.env {
			t.Setenv(k, v)
		}
		_, err := LoadConfig(true)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("env %v: err %v, want %q", tt.env, err, tt.want)
		}
	}
}
