package main

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/edr/internal/keyring"
)

// Default timing knobs. The ready window covers MySQL warmup + migrations on first boot; the verify window covers the processor
// interval plus enroll/ingest round-trips. defaultHeadroom is the extra budget the overall run context allows beyond
// ready+verify for the enroll/ingest round-trips themselves.
const (
	defaultReadyTimeout  = 90 * time.Second
	defaultVerifyTimeout = 60 * time.Second
	defaultPollInterval  = 500 * time.Millisecond
	defaultHeadroom      = 30 * time.Second
)

// config is the resolved set of knobs the seeder reads. Every field has an env-var default so the binary runs with zero flags inside
// the demo compose stack, while flags stay available for local runs against `task dev:server`.
type config struct {
	serverURL    string
	enrollSecret string
	dsn          string
	chDSN        string
	caCertPath   string
	force        bool

	// demoOIDCSubject is the dex-issued OIDC subject for the SSO demo user. Empty (the default) disables the demo-user seed entirely,
	// which is what a PR-1 run against `task dev:server` (break-glass only, no dex) wants. PR 2 wires the captured subject.
	demoEmail       string
	demoOIDCSubject string
	demoRole        string

	// OIDC connection config the seeder writes to the durable oidc_config store so the demo/QA dex SSO is configured without the
	// server reading EDR_OIDC_* (issue #512 removed that env path). secretKey is the deployment root secret (must match the server's
	// EDR_SECRET_KEY) used to seal the client secret at rest. When oidcIssuer is empty the OIDC seed is skipped. oidcOnly seeds just the
	// OIDC config and exits, skipping the corpus replay (used by `task dev:server:qa-oidc`).
	secretKey        string
	oidcIssuer       string
	oidcClientID     string
	oidcClientSecret string
	oidcExternalURL  string
	oidcDefaultRole  string
	oidcJIT          bool
	oidcOnly         bool
	oidcForce        bool

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
	fs.StringVar(&c.chDSN, "clickhouse-dsn", envOr(getenv, "EDR_CLICKHOUSE_DSN", ""),
		"ClickHouse DSN for the event archive (ADR-0015); when set, the restart timestamp-refresh slides archived events too. Optional")
	fs.StringVar(&c.caCertPath, "ca-cert", envOr(getenv, "EDR_DEMO_CA_CERT", ""),
		"PEM CA/cert file to trust for the server's TLS (the demo stack's self-signed localhost cert); empty uses system roots")
	fs.BoolVar(&c.force, "force", envBool(getenv, "EDR_DEMO_FORCE", false),
		"replay scenarios even if demo data is already present")
	fs.StringVar(&c.demoEmail, "demo-email", envOr(getenv, "EDR_DEMO_EMAIL", "demo@fleet-edr.local"),
		"email of the SSO demo user")
	fs.StringVar(&c.demoOIDCSubject, "demo-oidc-subject", envOr(getenv, "EDR_DEMO_OIDC_SUBJECT", ""),
		"dex-issued OIDC subject for the demo user; empty disables the demo-user seed")
	fs.StringVar(&c.demoRole, "demo-role", envOr(getenv, "EDR_DEMO_ROLE", "senior_analyst"),
		"role bound to the SSO demo user (must be a seeded role id)")
	fs.StringVar(&c.secretKey, "secret-key", envOr(getenv, "EDR_SECRET_KEY", ""),
		"deployment root secret (matches the server's EDR_SECRET_KEY); required to seal the OIDC client secret when seeding SSO")
	fs.StringVar(&c.oidcIssuer, "oidc-issuer", envOr(getenv, "EDR_DEMO_OIDC_ISSUER", ""),
		"OIDC issuer URL to seed into the durable config; empty skips the SSO config seed")
	fs.StringVar(&c.oidcClientID, "oidc-client-id", envOr(getenv, "EDR_DEMO_OIDC_CLIENT_ID", ""),
		"OIDC client id to seed")
	fs.StringVar(&c.oidcClientSecret, "oidc-client-secret", envOr(getenv, "EDR_DEMO_OIDC_CLIENT_SECRET", ""),
		"OIDC client secret to seed (sealed at rest with the deployment root secret)")
	fs.StringVar(&c.oidcExternalURL, "oidc-external-url", envOr(getenv, "EDR_DEMO_OIDC_EXTERNAL_URL", ""),
		"deployment external URL the OIDC redirect is derived from (<url>/api/auth/callback)")
	fs.StringVar(&c.oidcDefaultRole, "oidc-default-role", envOr(getenv, "EDR_DEMO_OIDC_DEFAULT_ROLE", "analyst"),
		"role JIT-provisioned SSO users are bound to (must be a seeded role id)")
	fs.BoolVar(&c.oidcJIT, "oidc-jit", envBool(getenv, "EDR_DEMO_OIDC_JIT", true),
		"enable JIT provisioning of unknown SSO subjects in the seeded config")
	fs.BoolVar(&c.oidcOnly, "oidc-only", envBool(getenv, "EDR_DEMO_OIDC_ONLY", false),
		"seed only the durable OIDC config and exit, skipping the corpus replay (for local QA against dex)")
	fs.BoolVar(&c.oidcForce, "oidc-force", envBool(getenv, "EDR_DEMO_OIDC_FORCE", false),
		"overwrite an existing stored OIDC config instead of skipping it (test harnesses re-pointing the JIT toggle; not for the demo)")
	fs.DurationVar(&c.readyTimeout, "ready-timeout", envDuration(getenv, "EDR_DEMO_READY_TIMEOUT", defaultReadyTimeout),
		"how long to wait for the server's /readyz to report ok")
	fs.DurationVar(&c.verifyTimeout, "verify-timeout", envDuration(getenv, "EDR_DEMO_VERIFY_TIMEOUT", defaultVerifyTimeout),
		"how long to wait for the processor to materialise demo data")
	fs.DurationVar(&c.pollInterval, "poll-interval", envDuration(getenv, "EDR_DEMO_POLL_INTERVAL", defaultPollInterval),
		"poll cadence for readiness and verification")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	// Trim a trailing slash so path concatenation (serverURL + "/api/enroll") never produces a double slash.
	c.serverURL = strings.TrimSuffix(c.serverURL, "/")
	if c.dsn == "" {
		return config{}, errors.New("a MySQL DSN is required: set EDR_DSN or pass --dsn")
	}
	if c.oidcOnly && c.oidcIssuer == "" {
		return config{}, errors.New("--oidc-only requires an OIDC issuer: set EDR_DEMO_OIDC_ISSUER or pass --oidc-issuer")
	}
	// Once an issuer is set the seeder will write a durable oidc_config row; reject an incomplete block here so it fails fast with a
	// clear message instead of a late keyring error (missing secret key) or a stored row that makes OIDCEnabled true while sign-in is
	// broken (missing client id/secret).
	if c.oidcIssuer != "" {
		// Mirror the server's EDR_SECRET_KEY floor (keyring.MinRootKeyLen) so a too-short key fails here, not late at the sealing step
		// after a full corpus replay. len 0 is caught by the same check.
		if len(c.secretKey) < keyring.MinRootKeyLen {
			return config{}, fmt.Errorf("seeding OIDC requires the deployment root secret (EDR_SECRET_KEY / --secret-key) of at least %d bytes", keyring.MinRootKeyLen)
		}
		if c.oidcClientID == "" || c.oidcClientSecret == "" {
			return config{}, errors.New("seeding OIDC requires the client id + secret: set EDR_DEMO_OIDC_CLIENT_ID / EDR_DEMO_OIDC_CLIENT_SECRET or pass --oidc-client-id / --oidc-client-secret")
		}
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
