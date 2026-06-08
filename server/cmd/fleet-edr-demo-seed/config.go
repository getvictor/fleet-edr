package main

import (
	"errors"
	"flag"
	"strconv"
	"time"
)

// Default timing knobs. The ready window covers MySQL warmup + migrations on first boot; the verify window covers the processor
// interval plus enroll/ingest round-trips.
const (
	defaultReadyTimeout  = 90 * time.Second
	defaultVerifyTimeout = 60 * time.Second
	defaultPollInterval  = 500 * time.Millisecond
)

// config is the resolved set of knobs the seeder reads. Every field has an env-var default so the binary runs with zero flags inside
// the demo compose stack, while flags stay available for local runs against `task dev:server`.
type config struct {
	serverURL    string
	enrollSecret string
	dsn          string
	insecure     bool
	force        bool

	// demoOIDCSubject is the dex-issued OIDC subject for the SSO demo user. Empty (the default) disables the demo-user seed entirely,
	// which is what a PR-1 run against `task dev:server` (break-glass only, no dex) wants. PR 2 wires the captured subject.
	demoEmail       string
	demoOIDCSubject string
	demoRole        string

	readyTimeout  time.Duration
	verifyTimeout time.Duration
	pollInterval  time.Duration
}

// resolveConfig builds the config from env-var defaults overridden by command-line flags. getenv is injected so tests exercise the
// env-default path without mutating the process environment.
func resolveConfig(getenv func(string) string, args []string) (config, error) {
	fs := flag.NewFlagSet("fleet-edr-demo-seed", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.serverURL, "server-url", envOr(getenv, "EDR_DEMO_SERVER_URL", "https://localhost:8088"),
		"base URL of the EDR server")
	fs.StringVar(&c.enrollSecret, "enroll-secret", envOr(getenv, "EDR_ENROLL_SECRET", "demo-enroll-secret"),
		"enrollment secret the server was started with")
	fs.StringVar(&c.dsn, "dsn", envOr(getenv, "EDR_DSN", ""),
		"MySQL DSN used to verify materialised demo data and seed the SSO demo user")
	fs.BoolVar(&c.insecure, "insecure", envBool(getenv, "EDR_DEMO_INSECURE", true),
		"skip TLS verification (the demo stack serves a self-signed localhost cert)")
	fs.BoolVar(&c.force, "force", envBool(getenv, "EDR_DEMO_FORCE", false),
		"replay scenarios even if demo data is already present")
	fs.StringVar(&c.demoEmail, "demo-email", envOr(getenv, "EDR_DEMO_EMAIL", "demo@fleet-edr.local"),
		"email of the SSO demo user")
	fs.StringVar(&c.demoOIDCSubject, "demo-oidc-subject", envOr(getenv, "EDR_DEMO_OIDC_SUBJECT", ""),
		"dex-issued OIDC subject for the demo user; empty disables the demo-user seed")
	fs.StringVar(&c.demoRole, "demo-role", envOr(getenv, "EDR_DEMO_ROLE", "senior_analyst"),
		"role bound to the SSO demo user (must be a seeded role id)")
	fs.DurationVar(&c.readyTimeout, "ready-timeout", envDuration(getenv, "EDR_DEMO_READY_TIMEOUT", defaultReadyTimeout),
		"how long to wait for the server's /readyz to report ok")
	fs.DurationVar(&c.verifyTimeout, "verify-timeout", envDuration(getenv, "EDR_DEMO_VERIFY_TIMEOUT", defaultVerifyTimeout),
		"how long to wait for the processor to materialise demo data")
	fs.DurationVar(&c.pollInterval, "poll-interval", envDuration(getenv, "EDR_DEMO_POLL_INTERVAL", defaultPollInterval),
		"poll cadence for readiness and verification")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if c.dsn == "" {
		return config{}, errors.New("a MySQL DSN is required: set EDR_DSN or pass --dsn")
	}
	return c, nil
}

// envOr returns the env var's value if set and non-empty, else fallback.
func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool parses a boolean env var, falling back on unset or unparseable input.
func envBool(getenv func(string) string, key string, fallback bool) bool {
	v := getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

// envDuration parses a Go duration env var, falling back on unset or unparseable input.
func envDuration(getenv func(string) string, key string, fallback time.Duration) time.Duration {
	v := getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}
