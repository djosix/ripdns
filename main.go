// Command ripdns is a DNS server that resolves signed hostnames such as
// <token>.route.example.com to the IPv4 address encoded in the token, and
// relays all other queries to upstream DNS servers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/djosix/ripdns/token"
)

const usage = `Usage:
  ripdns [serve] [-env FILE]            run the DNS server
  ripdns encode [-env FILE] IPV4...     print the token and hostname for IPv4 addresses
  ripdns decode [-env FILE] NAME...     check tokens or hostnames and print the IPv4

Settings are read from RIPDNS_* environment variables. FILE (default .env) is
loaded first if it exists; variables already in the environment take
precedence. See .env.example for all settings.
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	fset := flag.NewFlagSet(cmd, flag.ExitOnError)
	fset.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	envFile := fset.String("env", ".env", "dotenv file to load")
	fset.Parse(args)

	envSet := false
	fset.Visit(func(f *flag.Flag) { envSet = envSet || f.Name == "env" })
	if err := LoadDotEnv(*envFile); err != nil && (envSet || !errors.Is(err, fs.ErrNotExist)) {
		fatal(err)
	}

	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "encode":
		err = encode(fset.Args())
	case "decode":
		err = decode(fset.Args())
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ripdns:", err)
	os.Exit(1)
}

func serve() error {
	cfg, err := LoadConfig(true)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	codec, err := token.New([]byte(cfg.Secret))
	if err != nil {
		return err
	}
	handler := NewHandler(cfg, NewMatcher(cfg, codec), log)

	log.Info("starting ripdns",
		"base", cfg.BaseDomain,
		"token_level", cfg.TokenLevel,
		"max_levels", cfg.MaxLevels,
		"max_tokens", cfg.MaxTokens,
		"upstreams", cfg.Upstreams,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Serve(ctx, cfg, handler, log); err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

func encode(ips []string) error {
	if len(ips) == 0 {
		return errors.New("encode: no IPv4 address given")
	}
	cfg, err := LoadConfig(false)
	if err != nil {
		return err
	}
	codec, err := token.New([]byte(cfg.Secret))
	if err != nil {
		return err
	}
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		tok, err := codec.Encode(ip)
		if err != nil {
			return fmt.Errorf("encode %s: %w", s, err)
		}
		if cfg.BaseDomain != "" {
			fmt.Printf("%s\t%s.%s\n", tok, tok, cfg.BaseDomain)
		} else {
			fmt.Println(tok)
		}
	}
	return nil
}

func decode(names []string) error {
	if len(names) == 0 {
		return errors.New("decode: no token or hostname given")
	}
	cfg, err := LoadConfig(false)
	if err != nil {
		return err
	}
	codec, err := token.New([]byte(cfg.Secret))
	if err != nil {
		return err
	}
	var matcher *Matcher
	if cfg.BaseDomain != "" {
		matcher = NewMatcher(cfg, codec)
	}

	failed := false
	for _, s := range names {
		if ip, ok := codec.Decode(s); ok {
			fmt.Printf("%s\t%s\n", s, ip)
			continue
		}
		if matcher != nil {
			if kind, ip := matcher.Match(s); kind == Valid {
				fmt.Printf("%s\t%s\n", s, ip)
				continue
			} else if kind != NotOurs {
				fmt.Printf("%s\t%s\n", s, kind)
				failed = true
				continue
			}
		}
		fmt.Printf("%s\tinvalid\n", s)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
	return nil
}
