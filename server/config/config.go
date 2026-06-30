// Package config loads and validates environment-based configuration for the EDR server.
//
// Every required var is checked at startup; missing or malformed values produce an error
// that names the offending variable. Optional vars fall back to sensible defaults.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/fleetdm/edr/internal/envparse"
)

const (
	// DefaultProcessInterval is the cadence the server's process-graph builder ticks at. 500ms keeps tree freshness under a second on
	// the hot path while letting the batch worker amortise DB queries. Wired into the detection processor at boot (no longer an env knob).
	DefaultProcessInterval = 500 * time.Millisecond
	// DefaultProcessBatch is the maximum events processed per process-graph tick.
	DefaultProcessBatch = 500
	// DefaultProcessConcurrency is the number of in-process detection-processor workers a replica runs (issue #535). The processor is
	// I/O-round-trip bound, not compute bound, so a single goroutine leaves a saturated replica at ~25% CPU; running several workers
	// that each claim disjoint batches via SELECT ... FOR UPDATE SKIP LOCKED (ADR-0011) turns the idle CPU into parallel DB progress.
	// 4 is a conservative default sized for a small pilot replica; it is a fixed constant, not an env knob (server-configuration spec).
	DefaultProcessConcurrency = 4
	// defaultEnrollRatePerMin is the per-IP enrollment rate cap.
	defaultEnrollRatePerMin = 30
	// defaultRetentionDays is the event-row retention window.
	defaultRetentionDays = 30
	// DefaultRetentionInterval is how often the retention runner wakes up. Wired into the retention runner at boot (no longer an env knob).
	DefaultRetentionInterval = time.Hour
	// DefaultQueuePruneInterval is how often the event-queue sweep removes acked rows (ADR-0015). Far shorter than the retention
	// interval: the queue grows at the ingest rate, not the retention window, so a frequent cheap sweep keeps it to its working set.
	DefaultQueuePruneInterval = time.Minute
	// DefaultStaleProcessTTL is the fork-time age past which a still-running process row is force-exited by the freshness reconciler.
	// Long enough to cover an analyst's working window; short enough that overnight greens are gone by morning.
	DefaultStaleProcessTTL = 6 * time.Hour
	// DefaultStaleProcessInterval is how often the process-TTL reconciler runs.
	DefaultStaleProcessInterval = 10 * time.Minute
	// DefaultHostTokenLifetime is the TTL of a minted signed host token: how long it is valid before the agent must refresh it. The
	// agent refreshes well before expiry; 60 minutes matches SPIFFE hot-path workload-identity guidance.
	DefaultHostTokenLifetime = 60 * time.Minute
	// DefaultOIDCStateCookieTTL is how long the signed state cookie that carries (state, nonce, code_verifier) stays valid. 5 minutes
	// matches the IdP's typical authorization-code window: long enough to survive an MFA prompt, short enough to bound CSRF replay.
	DefaultOIDCStateCookieTTL = 5 * time.Minute
	// DefaultBreakglassBootstrapTokenTTL mirrors the package-side fallback in server/identity/internal/breakglass/tokens.go. Exposed
	// at the config layer so cmd/main can build the redemption-URL banner with a non-zero TTL string when the operator did not pin
	// EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL.
	DefaultBreakglassBootstrapTokenTTL = time.Hour
	// defaultShutdownDrain is how long the server keeps serving after SIGTERM before closing the listener, so a load balancer
	// observes /readyz flip to 503 and drains this replica from rotation first (server-availability). 30s suits the default
	// health-check interval of common load balancers; operators tune via EDR_SHUTDOWN_DRAIN (0 disables the wait, e.g. in tests).
	defaultShutdownDrain = 30 * time.Second
)

// DefaultOIDCScopes returns the scopes requested at AuthURL time. [openid, email, profile] gives the verifier the claims it needs
// (sub, email, name) without leaking unused permissions. Returned as a fresh slice so callers can't mutate a shared backing array.
func DefaultOIDCScopes() []string { return []string{"openid", "email", "profile"} }

// Config is the resolved server configuration.
type Config struct {
	DSN           string
	ClickHouseDSN string
	// ListenAddr is the single bind address for the whole server: the REST API, the embedded UI, and the agent control-channel gRPC
	// gateway are multiplexed on it (issue #477), so there is no separate control-channel address to configure.
	ListenAddr   string
	EnrollSecret string
	TLSCertFile  string
	TLSKeyFile   string
	// TLSTerminatedByProxy lets the server listen plaintext HTTP when a TLS-terminating proxy (a PaaS edge, an ALB, nginx, or
	// Cloudflare) sits in front. It is the gated exception to the mandatory-TLS default (issue #140): the default still refuses
	// to boot without certs, but an operator who sets EDR_TLS_TERMINATED_BY_PROXY=1 asserts that something in front terminates
	// TLS, so the data plane is still encrypted end-to-edge. Setting it together with cert files is rejected as ambiguous. This
	// is the same posture Fleet ships (FLEET_SERVER_TLS=false behind an ALB).
	TLSTerminatedByProxy bool
	// ShutdownDrain is how long RunAndShutdown keeps serving after SIGTERM (with /readyz reporting 503) before closing the
	// listener, so a load balancer drains this replica first. Default 30s; 0 disables the drain wait. From EDR_SHUTDOWN_DRAIN.
	ShutdownDrain    time.Duration
	EnrollRatePerMin int
	LogLevel         string
	LogFormat        string

	// Data lifecycle.
	//
	// RetentionDays is the age cap for events in days. 0 disables the retention
	// runner entirely (useful for operators who ship events to another store and
	// don't want MVP's default 30-day window). Default 30.
	RetentionDays int

	// Detection-rule false-positive allowlists and the disabled-rule list moved out of boot-time env to the DB-backed
	// detection-config surface (issue #459): per-host exclusions + per-rule mode, edited via the admin API/UI and audited.
	// The former EDR_LAUNCHAGENT_ALLOWLIST / EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST / EDR_SUDOERS_WRITER_ALLOWLIST /
	// EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST / EDR_DISABLED_RULES env vars are deleted (hard switch, no fallback).

	// TrustedProxies is the set of CIDRs (or bare IPs) the server will trust X-Forwarded-For from. Populated from EDR_TRUSTED_PROXIES
	// (comma-separated). Empty by default: XFF is ignored and the per-IP rate limiter + audit log see the direct TCP peer (issue #81).
	// Set this to your reverse proxy / load-balancer pool the moment you put an ALB / nginx / Cloudflare in front of fleet-edr-server,
	// or one user hitting the rate limit will lock out everyone behind the proxy.
	TrustedProxies []string

	// OIDC sign-in is configured at runtime through the Single sign-on admin page + API, backed by the durable oidc_config store
	// (issue #375); the store is the source of truth and the login routes are always mounted. The server reads no EDR_OIDC_* env vars and
	// boots without any OIDC configuration (the admin signs in via break-glass and configures SSO from the UI). See sso-configuration.

	// SecretKey is the deployment root secret. Every long-lived server-side key is derived from it via HKDF (internal/keyring) under a
	// versioned domain-separation label: the host-token HMAC pepper and the pre-auth cookie signing key (OIDC state + break-glass
	// challenge) are both derived, so a deployment provisions one secret rather than one per purpose. Populated from EDR_SECRET_KEY (or
	// EDR_SECRET_KEY_FILE for docker-secret mounts). Always required; validated at boot to be at least 32 bytes. Changing it invalidates
	// every existing host token (a breaking, operator-initiated fleet-wide re-enroll).
	SecretKey []byte

	// Break-glass surface knobs. Empty / zero values fall through to
	// the per-package defaults documented at each field.

	// BreakglassBootstrapTokenTTL bounds how long the redemption URL printed at first boot stays redeemable. Default 1h. Shorter caps the
	// value of an exfiltrated stderr log; longer gives a busy operator more time to redeem before re-launching.
	BreakglassBootstrapTokenTTL time.Duration
	// BreakglassIPAllowlist is the optional CIDR (or bare-IP) list the /admin/break-glass surface gates on. Off-list callers receive a
	// generic 404. Empty default = no gate (dev workflow shape; production should set this to the operator bastion's CIDR).
	BreakglassIPAllowlist []string
	// BreakglassRPID is the WebAuthn relying-party identifier: the canonical host that browser-stored credentials bind to. Typically
	// the registrable host portion of the EDR UI URL without scheme (e.g. "edr.example.com"). Required when the break-glass surface is
	// enabled; changing it post-deploy invalidates every registered credential.
	BreakglassRPID string
	// BreakglassRPOrigins enumerates the absolute URLs the RP accepts in the authenticator's origin attestation. At least one is required
	// when the break-glass surface is enabled; production typically pins the externally reachable HTTPS URL.
	BreakglassRPOrigins []string

	// Session timeouts + reauth window. All zero-valued fields fall
	// through to the sessions package defaults (Normal: 8h idle /
	// 24h absolute; Break-glass: 15m idle / 1h absolute; reauth
	// window: 30m). Operators tune these per deployment via the
	// corresponding env vars.
	//
	// SessionIdleTimeout is the inactivity cap for OIDC-minted
	// sessions. Idle is NOW() minus last_seen_at; the middleware slides
	// last_seen_at on every authenticated request so an active
	// operator never trips it.
	SessionIdleTimeout time.Duration
	// SessionAbsoluteTimeout is the hard age cap for OIDC-minted sessions. The session expires at created_at + this value regardless of
	// activity, forcing a periodic re-authentication.
	SessionAbsoluteTimeout time.Duration
	// BreakglassSessionIdleTimeout is the strict idle cap for the recovery surface. Recovery sessions are short-lived by design; a stolen
	// cookie has at most this much time to be abused before idle expiry kicks in.
	BreakglassSessionIdleTimeout time.Duration
	// BreakglassSessionAbsoluteTimeout is the absolute cap for recovery sessions. Tighter than the OIDC cap because the recovery account
	// carries elevated privilege.
	BreakglassSessionAbsoluteTimeout time.Duration
	// ReauthWindow is the freshness gate the chokepoint reads via Actor.SessionFresh. Destructive actions (host.isolate,
	// host.kill_process, host.run_script, alert.resolve when severity=critical) deny with reason="reauth_required" when last_auth_at is
	// older than this. The UI's useReauthRetry wrapper converts the deny into an inline reauth prompt.
	ReauthWindow time.Duration
}

// TLSEnabled reports whether the server terminates TLS itself (cert and key both set).
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// ExternalTLS reports whether the client-facing connection is HTTPS: either the server terminates TLS itself, or a front proxy
// does (EDR_TLS_TERMINATED_BY_PROXY). Browser-facing security wiring (Secure cookies, HSTS) keys on this rather than TLSEnabled
// so a behind-proxy deployment still marks cookies Secure and emits HSTS, since the browser only ever reaches us over HTTPS.
func (c Config) ExternalTLS() bool {
	return c.TLSEnabled() || c.TLSTerminatedByProxy
}

// Defaults returns a Config populated with default values. Callers should overlay env vars on top.
func defaults() Config {
	return Config{
		ListenAddr:       ":8088",
		LogLevel:         "info",
		LogFormat:        "json",
		EnrollRatePerMin: defaultEnrollRatePerMin,
		RetentionDays:    defaultRetentionDays,
		ShutdownDrain:    defaultShutdownDrain,
	}
}

// Load reads configuration from the environment. It returns an error aggregating every validation
// problem so the operator can fix all of them at once rather than playing whack-a-mole.
//
// Every string env var transparently supports a `*_FILE` sibling (Docker-secret
// convention): when `KEY` is unset but `KEY_FILE` points at a readable file, the
// file's trimmed contents are used as the value. Wired here so docker-compose
// + `secrets:` mounts work without plaintext in the compose env block.
func Load() (*Config, error) {
	return loadFrom(FileBackedGetenv(os.Getenv, slog.Default())) //nolint:forbidigo // approved config-load boundary; loadFrom takes a getenv fn so tests inject (issue #172)
}

// loadFrom is the testable core of Load; it takes a lookup function so tests can provide a fake env.
//
// The function fan-outs to per-section helpers (loadCoreEnv,
// loadTLSConfig, loadRateLimits, loadLogConfig,
// loadOIDCConfig, loadBreakglassConfig, loadSessionTimeouts) so the
// parent stays at a cognitive complexity Sonar's S3776 rule accepts.
// Order between helpers is preserved: TLS validation depends on the
// certificate paths the core helper read.
func loadFrom(getenv func(string) string) (*Config, error) {
	c := defaults()
	var errs []error

	loadCoreEnv(&c, getenv, &errs)
	loadSecretKey(&c, getenv, &errs)
	loadTLSConfig(&c, &errs)
	loadRateLimits(&c, getenv, &errs)
	loadLogConfig(&c, getenv, &errs)
	loadBreakglassConfig(&c, getenv, &errs)
	loadSessionTimeouts(&c, getenv, &errs)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &c, nil
}

// loadCoreEnv reads required strings + scalar feature flags. The TLS certificate paths land here too because they're optionalStr;
// their cross-field validation runs in loadTLSConfig once both sides are known.
func loadCoreEnv(c *Config, getenv func(string) string, errs *[]error) {
	// EDR_DSN is the canonical MySQL DSN; it is the only supported way to point the server at its database (use EDR_DSN_FILE for
	// docker-secret mounts). go-sql-driver does not URL-decode the DSN, so a password containing DSN metacharacters (@, :, /, ?)
	// is not supported in the raw DSN string and must be avoided.
	optionalStr(&c.DSN, "EDR_DSN", getenv)
	// EDR_CLICKHOUSE_DSN points the visibility event archive at ClickHouse (clickhouse-go DSN form). Optional: the archive is wired in
	// at the cutover, so an unset value leaves the server on the MySQL-only path (use EDR_CLICKHOUSE_DSN_FILE for docker-secret mounts).
	optionalStr(&c.ClickHouseDSN, "EDR_CLICKHOUSE_DSN", getenv)
	if c.DSN == "" {
		*errs = append(*errs, errors.New("EDR_DSN is required (use EDR_DSN_FILE for docker-secret mounts)"))
	}
	optionalStr(&c.ListenAddr, "EDR_LISTEN_ADDR", getenv)
	requireStr(&c.EnrollSecret, "EDR_ENROLL_SECRET", getenv, errs, true)
	optionalStr(&c.TLSCertFile, "EDR_TLS_CERT_FILE", getenv)
	optionalStr(&c.TLSKeyFile, "EDR_TLS_KEY_FILE", getenv)

	c.TLSTerminatedByProxy = getenv("EDR_TLS_TERMINATED_BY_PROXY") == "1"
	// NonNegative (not Positive): 0 is the documented "disable the drain wait" sentinel. RunAndShutdown skips the drain phase and
	// shuts down immediately. Integration + single-process tests set EDR_SHUTDOWN_DRAIN=0 so they don't sleep the drain window.
	envparse.NonNegativeDuration(getenv, "EDR_SHUTDOWN_DRAIN", &c.ShutdownDrain, errs)

	if v := getenv("EDR_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = splitCSV(v)
	}
}

// secretKeyMinBytes is the floor for EDR_SECRET_KEY. 32 bytes matches the HKDF-SHA256 output width every derived key uses; a shorter
// root would cap the entropy of the host-token pepper and the cookie signing key regardless of their requested length.
const secretKeyMinBytes = 32

// loadSecretKey reads + validates the deployment root secret. Unlike the OIDC signing key it replaces, it is required unconditionally:
// the host-token HMAC pepper derives from it and host tokens are used by every deployment, OIDC or not. The EDR_SECRET_KEY_FILE
// docker-secret sibling is honored transparently by the FileBackedGetenv wrapper.
func loadSecretKey(c *Config, getenv func(string) string, errs *[]error) {
	v := getenv("EDR_SECRET_KEY")
	if v == "" {
		*errs = append(*errs, errors.New(
			"EDR_SECRET_KEY is required (at least 32 bytes; use EDR_SECRET_KEY_FILE for docker-secret mounts)"))
		return
	}
	if len(v) < secretKeyMinBytes {
		*errs = append(*errs, fmt.Errorf("EDR_SECRET_KEY must be at least %d bytes, got %d", secretKeyMinBytes, len(v)))
		return
	}
	c.SecretKey = []byte(v)
}

// loadTLSConfig validates the TLS configuration's cross-field
// invariants now that loadCoreEnv has populated the cert paths.
func loadTLSConfig(c *Config, errs *[]error) {
	if c.TLSTerminatedByProxy {
		// Gated exception to #140: a TLS-terminating proxy is in front, so the server listens plaintext HTTP. Reject cert files
		// alongside it: the operator either terminates TLS here (cert files, no flag) or at the proxy (flag, no cert files), never
		// a confused half-and-half where the cert files silently win or are silently ignored.
		if c.TLSCertFile != "" || c.TLSKeyFile != "" {
			*errs = append(*errs, errors.New(
				"EDR_TLS_TERMINATED_BY_PROXY=1 is mutually exclusive with EDR_TLS_CERT_FILE/EDR_TLS_KEY_FILE: "+
					"terminate TLS at the proxy (flag only) or at the server (cert files only), not both"))
		}
		return
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		*errs = append(*errs, errors.New(
			"EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE are both required unless EDR_TLS_TERMINATED_BY_PROXY=1: "+
				"the server has no unguarded plaintext-HTTP mode (issue #140)"))
		return
	}
	// Fail fast on unreadable / mismatched cert material so boot exits before bootstrap.New mutates the DB (admin seeding prints
	// a one-time password the operator can lose to log noise on a misconfigured retry). configureTLS in cmd/main would otherwise
	// catch this only AFTER ApplySchema + seedAdmin had already run (CodeRabbit review on PR #182).
	if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
		*errs = append(*errs, fmt.Errorf("EDR_TLS_CERT_FILE/EDR_TLS_KEY_FILE unreadable or mismatched: %w", err))
	}
}

// loadRateLimits parses the per-minute enrollment throttle alongside the retention window. Enroll rate must be strictly positive;
// retention permits 0 as the documented "disable" sentinel.
func loadRateLimits(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveInt(getenv, "EDR_ENROLL_RATE_PER_MIN", &c.EnrollRatePerMin, errs)
	envparse.NonNegativeInt(getenv, "EDR_RETENTION_DAYS", &c.RetentionDays, errs)
}

// loadLogConfig reads + validates the slog handler's level + format knobs. Lowercases for downstream consumers regardless of how the
// operator spelled the env var.
func loadLogConfig(c *Config, getenv func(string) string, errs *[]error) {
	if v := getenv("EDR_LOG_LEVEL"); v != "" {
		// Normalize to the canonical lowercase form so downstream slog handlers see one of the
		// documented values regardless of how the operator spelled it (e.g. "INFO", "Warn").
		c.LogLevel = strings.ToLower(v)
	}
	if !validLogLevel(c.LogLevel) {
		*errs = append(*errs, fmt.Errorf("EDR_LOG_LEVEL=%q must be one of debug, info, warn, error", c.LogLevel))
	}
	if v := getenv("EDR_LOG_FORMAT"); v != "" {
		c.LogFormat = strings.ToLower(v)
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		*errs = append(*errs, fmt.Errorf("EDR_LOG_FORMAT=%q must be 'json' or 'text'", c.LogFormat))
	}
}

func requireStr(dst *string, key string, getenv func(string) string, errs *[]error, nonEmpty bool) {
	v := getenv(key)
	if v == "" && nonEmpty {
		*errs = append(*errs, fmt.Errorf("required env var %s is not set", key))
		return
	}
	*dst = v
}

func optionalStr(dst *string, key string, getenv func(string) string) {
	if v := getenv(key); v != "" {
		*dst = v
	}
}

// splitCSV trims and drops empty tokens from a comma-separated value. CIDR validation is deferred to httpserver.NewClientIPResolver so
// a bad token errors with a uniform message at startup.
func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validLogLevel(lvl string) bool {
	switch strings.ToLower(lvl) {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}

// loadBreakglassConfig reads the break-glass surface knobs. All fields are optional; the bootstrap layer treats an unset RPID
// as "break-glass not configured" and falls back to a localhost default for dev workflows so an operator running `task dev:server`
// gets a working surface without explicit env vars. Production deployments MUST set EDR_BREAKGLASS_RP_ID + EDR_BREAKGLASS_RP_ORIGINS;
// the bootstrap layer enforces that with a refuse-to-start error.
func loadBreakglassConfig(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveDuration(getenv,
		"EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL",
		&c.BreakglassBootstrapTokenTTL, errs)
	if v := getenv("EDR_BREAKGLASS_IP_ALLOWLIST"); v != "" {
		c.BreakglassIPAllowlist = splitCSV(v)
	}
	optionalStr(&c.BreakglassRPID, "EDR_BREAKGLASS_RP_ID", getenv)
	if v := getenv("EDR_BREAKGLASS_RP_ORIGINS"); v != "" {
		c.BreakglassRPOrigins = splitCSV(v)
	}
}

// loadSessionTimeouts reads the session-timeout knobs. Every field is optional; bootstrap passes zero values through to the
// sessions package which substitutes its documented defaults (8h/24h normal, 15m/1h break-glass, 30m reauth window).
func loadSessionTimeouts(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveDuration(getenv,
		"EDR_SESSION_IDLE_TIMEOUT", &c.SessionIdleTimeout, errs)
	envparse.PositiveDuration(getenv,
		"EDR_SESSION_ABSOLUTE_TIMEOUT", &c.SessionAbsoluteTimeout, errs)
	envparse.PositiveDuration(getenv,
		"EDR_BREAKGLASS_SESSION_IDLE_TIMEOUT", &c.BreakglassSessionIdleTimeout, errs)
	envparse.PositiveDuration(getenv,
		"EDR_BREAKGLASS_SESSION_ABSOLUTE_TIMEOUT", &c.BreakglassSessionAbsoluteTimeout, errs)
	envparse.PositiveDuration(getenv,
		"EDR_REAUTH_WINDOW", &c.ReauthWindow, errs)
}
