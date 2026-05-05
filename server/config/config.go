// Package config loads and validates environment-based configuration for the EDR server.
//
// Every required var is checked at startup; missing or malformed values produce an error
// that names the offending variable. Optional vars fall back to sensible defaults.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/fleetdm/edr/internal/envparse"
)

const (
	// defaultProcessInterval is the cadence the server's process-graph
	// builder ticks at. 500ms keeps tree freshness under a second on the
	// hot path while letting the batch worker amortise DB queries.
	defaultProcessInterval = 500 * time.Millisecond
	// defaultProcessBatch is the maximum events processed per tick.
	defaultProcessBatch = 500
	// defaultEnrollRatePerMin is the per-IP enrollment rate cap.
	defaultEnrollRatePerMin = 30
	// defaultLoginRatePerMin is the per-IP login attempt cap. Tighter than
	// enroll because a brute-force login is the higher-value target.
	defaultLoginRatePerMin = 6
	// defaultRetentionDays is the event-row retention window.
	defaultRetentionDays = 30
	// defaultStaleProcessTTL is the fork-time age past which a still-running
	// process row is force-exited by the freshness reconciler. Long enough
	// to cover an analyst's working window; short enough that overnight
	// greens are gone by morning.
	defaultStaleProcessTTL = 6 * time.Hour
	// defaultStaleProcessInterval is how often the process-TTL reconciler runs.
	defaultStaleProcessInterval = 10 * time.Minute
	// defaultHostTokenLifetime is how long a host's bearer token is good for
	// before the verify path triggers an automatic rotation (issue #86).
	defaultHostTokenLifetime = 24 * time.Hour
	// defaultHostTokenGrace is how long a just-rotated previous token still
	// verifies after rotation. Wider than an agent's poll interval so an
	// in-flight request does not 401 mid-cycle.
	defaultHostTokenGrace = 5 * time.Minute
	// defaultOIDCStateCookieTTL is how long the signed state cookie that
	// carries (state, nonce, code_verifier) stays valid. 5 minutes
	// matches the IdP's typical authorization-code window — long enough
	// to survive an MFA prompt, short enough to bound CSRF replay.
	defaultOIDCStateCookieTTL = 5 * time.Minute
)

// Config is the resolved server configuration.
type Config struct {
	DSN               string
	ListenAddr        string
	EnrollSecret      string
	TLSCertFile       string
	TLSKeyFile        string
	AllowInsecureHTTP bool
	AllowTLS12        bool
	EnrollRatePerMin  int
	LoginRatePerMin   int
	LogLevel          string
	LogFormat         string
	ProcessInterval   time.Duration
	ProcessBatch      int

	// Data lifecycle + observability.
	//
	// RetentionDays is the age cap for events in days. 0 disables the retention
	// runner entirely (useful for operators who ship events to another store and
	// don't want MVP's default 30-day window). Default 30.
	RetentionDays int
	// RetentionInterval is how often the retention runner wakes up. Default 1h.
	RetentionInterval time.Duration

	// Process-tree freshness TTL (issue #6).
	//
	// StaleProcessTTL is the fork-time age past which a still-running
	// process is force-exited by the reconciler. 0 disables the runner.
	// Default 6h — long enough to cover normal analyst-session work but
	// short enough that overnight greens are gone by morning.
	StaleProcessTTL time.Duration
	// StaleProcessInterval is how often the process-TTL reconciler runs.
	// Default 10m.
	StaleProcessInterval time.Duration

	// LaunchAgentAllowlist is the set of plist paths the `persistence_launchagent` rule
	// should silently accept. Populated from EDR_LAUNCHAGENT_ALLOWLIST (comma-separated
	// absolute paths). Empty by default — every plist load fires.
	LaunchAgentAllowlist map[string]struct{}

	// LaunchDaemonTeamIDAllowlist is the set of code-signing team IDs the
	// `privilege_launchd_plist_write` rule should silently accept when they
	// write to /Library/LaunchDaemons. Populated from
	// EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST (comma-separated team IDs).
	// Apple-signed platform binaries (installd, system_installd, ...) are
	// always allowed; this list is for non-Apple MDM agents that legitimately
	// drop daemons (Munki, Kandji, JumpCloud, ...). Empty by default.
	LaunchDaemonTeamIDAllowlist map[string]struct{}

	// SudoersWriterAllowlist is the set of writer-process absolute paths
	// the `sudoers_tamper` rule should silently accept. Populated from
	// EDR_SUDOERS_WRITER_ALLOWLIST (comma-separated). Empty by default.
	// visudo doesn't need to be here — it writes via temp-file + rename
	// and never opens /etc/sudoers in write mode, so the rule never
	// sees it.
	SudoersWriterAllowlist map[string]struct{}

	// SuspiciousExecParentAllowlist is the set of non-shell parent paths
	// the `suspicious_exec` rule should treat as benign roots even when
	// they sit at the root of a "non-shell -> shell -> /tmp/binary" chain.
	// Populated from EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST (comma-separated).
	// Empty by default. The recommended value for fleets that allow
	// interactive admin SSH is `/usr/libexec/sshd-session,
	// /Applications/Terminal.app/Contents/MacOS/Terminal,
	// /Applications/iTerm.app/Contents/MacOS/iTerm2`. Leave empty on
	// servers where interactive SSH is unusual — the rule's "non-shell
	// -> shell -> /tmp/" shape is then a clean attacker indicator.
	SuspiciousExecParentAllowlist map[string]struct{}

	// HostTokenLifetime is the maximum age of an agent's bearer token
	// before the verify path triggers an automatic rotation (issue #86).
	// Populated from EDR_HOST_TOKEN_LIFETIME. Default 24h: short enough
	// that an exfiltrated token has bounded value, long enough that the
	// per-host rotation traffic is negligible.
	HostTokenLifetime time.Duration
	// HostTokenGrace is the window during which a just-rotated previous
	// token still verifies. Populated from EDR_HOST_TOKEN_GRACE.
	// Default 5m: comfortably wider than an agent's poll interval so an
	// in-flight request doesn't 401 mid-cycle.
	HostTokenGrace time.Duration

	// TrustedProxies is the set of CIDRs (or bare IPs) the server will
	// trust X-Forwarded-For from. Populated from EDR_TRUSTED_PROXIES
	// (comma-separated). Empty by default — XFF is ignored and the
	// per-IP rate limiter + audit log see the direct TCP peer (issue
	// #81). Set this to your reverse proxy / load-balancer pool the
	// moment you put an ALB / nginx / Cloudflare in front of
	// fleet-edr-server, or one user hitting the rate limit will lock
	// out everyone behind the proxy.
	TrustedProxies []string

	// AuthzShadowMode is the wave-1 rollout knob for the authorization
	// chokepoint. When true, every Allow call evaluates the policy and
	// audits the would-be decision but ALWAYS returns Allow=true so
	// pilot deployments observe the deny dashboard before enforcement
	// flips on. Populated from EDR_AUTHZ_SHADOW_MODE; default false
	// (enforcement on) for fresh deployments. The flag is read at
	// boot only — flipping it in production is a restart in wave 1
	// (a future admin endpoint or file-watch can call
	// Identity.SetAuthzShadowMode atomically; the in-memory engine
	// flag is already hot-swap-safe via atomic.Bool).
	AuthzShadowMode bool

	// AuditReadSampling is the inclusion probability (0.0-1.0) the
	// chokepoint applies to read-action allow events before submitting
	// them to the async writer. Default 0.0 (audit zero non-carve-out
	// read-allow events). Operators set EDR_AUDIT_READ_SAMPLING=1.0 to
	// keep the wave-1 historical behavior of auditing every decision.
	// Carve-outs ALWAYS audit regardless of rate: break-glass actor +
	// ActionAuditRead (the audit-of-audit row).
	AuditReadSampling float64

	// AuditAsyncQueueCap sizes the bounded buffer in the async audit
	// writer. Default 8192 (~minutes of read-burst headroom at wave-1
	// volumes). Larger reduces drop probability under burst at the cost
	// of more memory; smaller catches a queue-leak earlier. Populated
	// from EDR_AUDIT_ASYNC_QUEUE_CAP. Zero -> use the package default.
	AuditAsyncQueueCap int

	// OIDC authentication configuration. When OIDCIssuer is non-empty,
	// the server enables the OIDC sign-in flow at /api/auth/login +
	// /api/auth/callback. When OIDCIssuer is empty, the server refuses
	// to start unless AuthAllowNoOIDC=true (which lets dev workflows
	// run break-glass-only). All fields are populated from
	// EDR_OIDC_* env vars.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	// OIDCScopes are the scopes requested at AuthURL time. Default is
	// [openid, email, profile] which gives the verifier the claims it
	// needs (sub, email, name) without leaking unused permissions.
	// Wave-2 will add `groups` for role mapping.
	OIDCScopes []string
	// OIDCAllowJITProvisioning controls whether a successful OIDC
	// sign-in by an unknown subject creates a user + identity + default
	// role binding. true = create on first sign-in (recommended for
	// most deployments); false = require an admin to pre-provision the
	// user. Default true.
	OIDCAllowJITProvisioning bool
	// OIDCStateCookieTTL bounds how long the signed state cookie
	// (carrying state + nonce + PKCE verifier) stays valid. Defaults
	// to 5m; tune up for slow IdPs / MFA prompts.
	OIDCStateCookieTTL time.Duration

	// AuthAllowNoOIDC is the dedicated dev flag that lets the server
	// boot in break-glass-only mode (no OIDC). Default false:
	// production deployments without OIDC config refuse to start with
	// an explicit error pointing the operator at the missing env vars.
	// Set EDR_AUTH_ALLOW_NO_OIDC=1 in dev environments where running
	// against a real IdP is overkill. Pattern mirrors
	// EDR_ALLOW_INSECURE_HTTP=1's "you must opt in to the unsafe
	// path" shape.
	AuthAllowNoOIDC bool

	// SessionSigningKey is the HMAC key the OIDC state cookie uses to
	// sign + verify per-flow secrets (state, nonce, PKCE verifier).
	// Phase 5 will reuse the same key for signed session metadata.
	// Populated from EDR_SESSION_SIGNING_KEY (or EDR_SESSION_SIGNING_KEY_FILE
	// for docker-secret mounts). Required when OIDC is enabled;
	// validated at boot to be at least 32 bytes.
	SessionSigningKey []byte
}

// TLSEnabled reports whether TLS cert and key are both set.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// Defaults returns a Config populated with default values. Callers should overlay env vars on top.
func defaults() Config {
	return Config{
		ListenAddr:               ":8088",
		LogLevel:                 "info",
		LogFormat:                "json",
		ProcessInterval:          defaultProcessInterval,
		ProcessBatch:             defaultProcessBatch,
		EnrollRatePerMin:         defaultEnrollRatePerMin,
		LoginRatePerMin:          defaultLoginRatePerMin,
		RetentionDays:            defaultRetentionDays,
		RetentionInterval:        time.Hour,
		StaleProcessTTL:          defaultStaleProcessTTL,
		StaleProcessInterval:     defaultStaleProcessInterval,
		HostTokenLifetime:        defaultHostTokenLifetime,
		HostTokenGrace:           defaultHostTokenGrace,
		OIDCScopes:               []string{"openid", "email", "profile"},
		OIDCAllowJITProvisioning: true,
		OIDCStateCookieTTL:       defaultOIDCStateCookieTTL,
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
	return loadFrom(fileBackedGetenv(os.Getenv, slog.Default()))
}

// loadFrom is the testable core of Load; it takes a lookup function so tests can provide a fake env.
//
// The function fan-outs to per-section helpers (loadCoreEnv,
// loadTLSConfig, loadRateLimits, loadHostTokenConfig, loadAllowlists,
// loadLogConfig, loadProcessConfig) so the parent stays at a
// cognitive complexity Sonar's S3776 rule accepts. Order between
// helpers is preserved: TLS validation depends on the certificate
// paths the core helper read; the host-token cross-field check
// depends on both durations being parsed first.
func loadFrom(getenv func(string) string) (*Config, error) {
	c := defaults()
	var errs []error

	loadCoreEnv(&c, getenv, &errs)
	loadTLSConfig(&c, &errs)
	loadRateLimits(&c, getenv, &errs)
	loadHostTokenConfig(&c, getenv, &errs)
	loadAllowlists(&c, getenv)
	loadLogConfig(&c, getenv, &errs)
	loadProcessConfig(&c, getenv, &errs)
	loadOIDCConfig(&c, getenv, &errs)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &c, nil
}

// loadCoreEnv reads required strings + scalar feature flags. The TLS
// certificate paths land here too because they're optionalStr; their
// cross-field validation runs in loadTLSConfig once both sides are
// known.
func loadCoreEnv(c *Config, getenv func(string) string, errs *[]error) {
	requireStr(&c.DSN, "EDR_DSN", getenv, errs, true)
	optionalStr(&c.ListenAddr, "EDR_LISTEN_ADDR", getenv)
	requireStr(&c.EnrollSecret, "EDR_ENROLL_SECRET", getenv, errs, true)
	// UI + admin surfaces authenticate via the session cookie minted by
	// POST /api/session. The first-boot seeder prints the admin password
	// once so the operator can log in.
	optionalStr(&c.TLSCertFile, "EDR_TLS_CERT_FILE", getenv)
	optionalStr(&c.TLSKeyFile, "EDR_TLS_KEY_FILE", getenv)

	c.AllowInsecureHTTP = getenv("EDR_ALLOW_INSECURE_HTTP") == "1"
	c.AllowTLS12 = getenv("EDR_TLS_ALLOW_TLS12") == "1"
	c.AuthzShadowMode = getenv("EDR_AUTHZ_SHADOW_MODE") == "1"
	envparse.UnitFraction(getenv, "EDR_AUDIT_READ_SAMPLING", &c.AuditReadSampling, errs)
	envparse.NonNegativeInt(getenv, "EDR_AUDIT_ASYNC_QUEUE_CAP", &c.AuditAsyncQueueCap, errs)

	if v := getenv("EDR_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = splitCSV(v)
	}
}

// loadTLSConfig validates the TLS configuration's cross-field
// invariants now that loadCoreEnv has populated the cert paths.
func loadTLSConfig(c *Config, errs *[]error) {
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		*errs = append(*errs, errors.New(
			"EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE must be set together (or both left unset)"))
	}
	// TLS is required in production. The opt-out is deliberately noisy so operators
	// don't accidentally ship plaintext.
	if !c.TLSEnabled() && !c.AllowInsecureHTTP {
		*errs = append(*errs, errors.New(
			"EDR_TLS_CERT_FILE is required (set EDR_ALLOW_INSECURE_HTTP=1 for dev)"))
	}
}

// loadRateLimits parses the per-minute throttles for enroll + login
// alongside the retention/process-reconciler windows. All but
// retention require strictly-positive values; retention permits 0 as
// the documented "disable" sentinel.
func loadRateLimits(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveInt(getenv, "EDR_ENROLL_RATE_PER_MIN", &c.EnrollRatePerMin, errs)
	envparse.PositiveInt(getenv, "EDR_LOGIN_RATE_PER_MIN", &c.LoginRatePerMin, errs)
	envparse.NonNegativeInt(getenv, "EDR_RETENTION_DAYS", &c.RetentionDays, errs)
	envparse.PositiveDuration(getenv, "EDR_RETENTION_INTERVAL", &c.RetentionInterval, errs)
	envparse.NonNegativeDuration(getenv, "EDR_STALE_PROCESS_TTL", &c.StaleProcessTTL, errs)
	envparse.PositiveDuration(getenv, "EDR_STALE_PROCESS_INTERVAL", &c.StaleProcessInterval, errs)
}

// loadHostTokenConfig parses the wave-1 host-token rotation knobs and
// enforces the cross-field invariant: grace MUST be strictly shorter
// than lifetime. Both must be positive; "disable rotation" is not a
// supported deployment mode (a never-rotating bearer token is the
// very thing this feature exists to fix). With grace >= lifetime,
// two consecutive rotations would leave THREE valid tokens at once
// (current + previous still in grace + previous-previous's grace
// window stretching past the next rotation), which the
// previous_token_* schema columns can't represent.
func loadHostTokenConfig(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveDuration(getenv, "EDR_HOST_TOKEN_LIFETIME", &c.HostTokenLifetime, errs)
	envparse.PositiveDuration(getenv, "EDR_HOST_TOKEN_GRACE", &c.HostTokenGrace, errs)
	if c.HostTokenLifetime > 0 && c.HostTokenGrace > 0 && c.HostTokenGrace >= c.HostTokenLifetime {
		*errs = append(*errs, fmt.Errorf(
			"EDR_HOST_TOKEN_GRACE (%s) must be strictly shorter than EDR_HOST_TOKEN_LIFETIME (%s)",
			c.HostTokenGrace, c.HostTokenLifetime))
	}
}

// loadAllowlists reads each detection-rule allowlist env var. Each is
// optional; nil-or-empty leaves the catalog default in place.
func loadAllowlists(c *Config, getenv func(string) string) {
	if allowlist := envparse.Allowlist(getenv("EDR_LAUNCHAGENT_ALLOWLIST")); allowlist != nil {
		c.LaunchAgentAllowlist = allowlist
	}
	if allowlist := envparse.Allowlist(getenv("EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST")); allowlist != nil {
		c.LaunchDaemonTeamIDAllowlist = allowlist
	}
	if allowlist := envparse.Allowlist(getenv("EDR_SUDOERS_WRITER_ALLOWLIST")); allowlist != nil {
		c.SudoersWriterAllowlist = allowlist
	}
	if allowlist := envparse.Allowlist(getenv("EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST")); allowlist != nil {
		c.SuspiciousExecParentAllowlist = allowlist
	}
}

// loadLogConfig reads + validates the slog handler's level + format
// knobs. Lowercases for downstream consumers regardless of how the
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

// loadProcessConfig parses the detection processor cadence knobs.
// Interval must be strictly positive (processor.Run feeds it into
// time.NewTicker which panics on non-positive values); batch must be
// strictly positive (a zero-batch loop spins).
func loadProcessConfig(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveDuration(getenv, "EDR_PROCESS_INTERVAL", &c.ProcessInterval, errs)
	envparse.PositiveInt(getenv, "EDR_PROCESS_BATCH", &c.ProcessBatch, errs)
}

// loadOIDCConfig parses the Phase-4 authentication knobs and enforces
// the "OIDC required unless explicitly opted out" gate. When
// EDR_OIDC_ISSUER is non-empty, the rest of the config block is
// validated as a coherent set; missing client_id / redirect URL
// surfaces a focused error. When EDR_OIDC_ISSUER is empty, the gate
// requires EDR_AUTH_ALLOW_NO_OIDC=1 so dev workflows can opt into
// break-glass-only mode without a silent fallback in production.
func loadOIDCConfig(c *Config, getenv func(string) string, errs *[]error) {
	optionalStr(&c.OIDCIssuer, "EDR_OIDC_ISSUER", getenv)
	optionalStr(&c.OIDCClientID, "EDR_OIDC_CLIENT_ID", getenv)
	optionalStr(&c.OIDCClientSecret, "EDR_OIDC_CLIENT_SECRET", getenv)
	optionalStr(&c.OIDCRedirectURL, "EDR_OIDC_REDIRECT_URL", getenv)
	if v := getenv("EDR_OIDC_SCOPES"); v != "" {
		c.OIDCScopes = splitCSV(v)
		// openid is mandatory for the discovery + ID-token flow; an
		// override that drops it leaves the operator with a worse
		// failure mode (token endpoint succeeds, ID-token absent at
		// callback) than a startup refusal.
		if !containsString(c.OIDCScopes, "openid") {
			*errs = append(*errs, errors.New(
				"EDR_OIDC_SCOPES must include \"openid\" (the OIDC core scope)"))
		}
	}
	if v := getenv("EDR_OIDC_ALLOW_JIT_PROVISIONING"); v != "" {
		c.OIDCAllowJITProvisioning = v == "1"
	}
	envparse.PositiveDuration(getenv, "EDR_OIDC_STATE_COOKIE_TTL", &c.OIDCStateCookieTTL, errs)
	c.AuthAllowNoOIDC = getenv("EDR_AUTH_ALLOW_NO_OIDC") == "1"
	if v := getenv("EDR_SESSION_SIGNING_KEY"); v != "" {
		c.SessionSigningKey = []byte(v)
	}
	if c.OIDCIssuer != "" && len(c.SessionSigningKey) < 32 {
		*errs = append(*errs, errors.New(
			"EDR_SESSION_SIGNING_KEY is required when OIDC is enabled; "+
				"must be at least 32 bytes (use EDR_SESSION_SIGNING_KEY_FILE for docker-secret mounts)"))
	}

	// Enforcement: every OIDC field is set together, OR none is set
	// AND AuthAllowNoOIDC is the explicit dev opt-out. Anything else
	// is a misconfiguration the operator should surface at boot rather
	// than silently fall back to break-glass-only mode. The
	// allow-no-oidc opt-out specifically does NOT excuse partial
	// configuration: if any EDR_OIDC_* knob is set, the operator clearly
	// intends OIDC and a missing companion is a typo, not an opt-out.
	partialOIDC := c.OIDCClientID != "" || c.OIDCClientSecret != "" || c.OIDCRedirectURL != ""
	switch {
	case c.OIDCIssuer == "" && partialOIDC:
		*errs = append(*errs, errors.New(
			"EDR_OIDC_CLIENT_ID/CLIENT_SECRET/REDIRECT_URL set without EDR_OIDC_ISSUER; "+
				"set EDR_OIDC_ISSUER to enable OIDC, or unset the partial values to opt out"))
	case c.OIDCIssuer == "" && !c.AuthAllowNoOIDC:
		*errs = append(*errs, errors.New(
			"EDR_OIDC_ISSUER is required (set EDR_AUTH_ALLOW_NO_OIDC=1 for break-glass-only dev mode)"))
	case c.OIDCIssuer != "":
		if c.OIDCClientID == "" {
			*errs = append(*errs, errors.New("EDR_OIDC_CLIENT_ID is required when EDR_OIDC_ISSUER is set"))
		}
		if c.OIDCClientSecret == "" {
			*errs = append(*errs, errors.New(
				"EDR_OIDC_CLIENT_SECRET is required when EDR_OIDC_ISSUER is set"+
					" (use EDR_OIDC_CLIENT_SECRET_FILE for docker-secret mounts)"))
		}
		if c.OIDCRedirectURL == "" {
			*errs = append(*errs, errors.New("EDR_OIDC_REDIRECT_URL is required when EDR_OIDC_ISSUER is set"))
		}
	}
}

// containsString reports whether ss contains s. Wrapper around
// slices.Contains kept so the call site reads in domain terms
// (does the configured scope set include the openid scope) rather
// than in stdlib terms.
func containsString(ss []string, s string) bool {
	return slices.Contains(ss, s)
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

// splitCSV trims and drops empty tokens from a comma-separated value.
// CIDR validation is deferred to httpserver.NewClientIPResolver so a
// bad token errors with a uniform message at startup.
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
