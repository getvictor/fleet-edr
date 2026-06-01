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
	"slices"
	"strings"
	"time"

	"github.com/fleetdm/edr/internal/envparse"
)

const (
	// defaultProcessInterval is the cadence the server's process-graph builder ticks at. 500ms keeps tree freshness under a second on the
	// hot path while letting the batch worker amortise DB queries.
	defaultProcessInterval = 500 * time.Millisecond
	// defaultProcessBatch is the maximum events processed per tick.
	defaultProcessBatch = 500
	// defaultEnrollRatePerMin is the per-IP enrollment rate cap.
	defaultEnrollRatePerMin = 30
	// defaultRetentionDays is the event-row retention window.
	defaultRetentionDays = 30
	// defaultStaleProcessTTL is the fork-time age past which a still-running process row is force-exited by the freshness reconciler.
	// Long enough to cover an analyst's working window; short enough that overnight greens are gone by morning.
	defaultStaleProcessTTL = 6 * time.Hour
	// defaultStaleProcessInterval is how often the process-TTL reconciler runs.
	defaultStaleProcessInterval = 10 * time.Minute
	// defaultHostTokenLifetime is how long a host's bearer token is good for
	// before the verify path triggers an automatic rotation (issue #86).
	defaultHostTokenLifetime = 24 * time.Hour
	// defaultHostTokenGrace is how long a just-rotated previous token still verifies after rotation. Wider than an agent's poll interval
	// so an in-flight request does not 401 mid-cycle.
	defaultHostTokenGrace = 5 * time.Minute
	// defaultOIDCStateCookieTTL is how long the signed state cookie that carries (state, nonce, code_verifier) stays valid. 5 minutes
	// matches the IdP's typical authorization-code window — long enough to survive an MFA prompt, short enough to bound CSRF replay.
	defaultOIDCStateCookieTTL = 5 * time.Minute
	// DefaultBreakglassBootstrapTokenTTL mirrors the package-side fallback in server/identity/internal/breakglass/tokens.go. Exposed
	// at the config layer so cmd/main can build the redemption-URL banner with a non-zero TTL string when the operator did not pin
	// EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL.
	DefaultBreakglassBootstrapTokenTTL = time.Hour
	// defaultShutdownDrain is how long the server keeps serving after SIGTERM before closing the listener, so a load balancer
	// observes /readyz flip to 503 and drains this replica from rotation first (server-availability). 30s suits the default
	// health-check interval of common load balancers; operators tune via EDR_SHUTDOWN_DRAIN (0 disables the wait, e.g. in tests).
	defaultShutdownDrain = 30 * time.Second
)

// Config is the resolved server configuration.
type Config struct {
	DSN          string
	ListenAddr   string
	EnrollSecret string
	TLSCertFile  string
	TLSKeyFile   string
	AllowTLS12   bool
	// ShutdownDrain is how long RunAndShutdown keeps serving after SIGTERM (with /readyz reporting 503) before closing the
	// listener, so a load balancer drains this replica first. Default 30s; 0 disables the drain wait. From EDR_SHUTDOWN_DRAIN.
	ShutdownDrain    time.Duration
	EnrollRatePerMin int
	LogLevel         string
	LogFormat        string
	ProcessInterval  time.Duration
	ProcessBatch     int

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

	// LaunchAgentAllowlist is the set of plist paths the `persistence_launchagent` rule should silently accept. Populated from
	// EDR_LAUNCHAGENT_ALLOWLIST (comma-separated absolute paths). Empty by default — every plist load fires.
	LaunchAgentAllowlist map[string]struct{}

	// LaunchDaemonTeamIDAllowlist is the set of code-signing team IDs the `privilege_launchd_plist_write` rule should silently accept when
	// they write to /Library/LaunchDaemons. Populated from EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST (comma-separated team IDs). Apple-signed
	// platform binaries (installd, system_installd, ...) are always allowed; this list is for non-Apple MDM agents that legitimately drop
	// daemons (Munki, Kandji, JumpCloud, ...). Empty by default.
	LaunchDaemonTeamIDAllowlist map[string]struct{}

	// SudoersWriterAllowlist is the set of writer-process absolute paths the `sudoers_tamper` rule should silently accept. Populated from
	// EDR_SUDOERS_WRITER_ALLOWLIST (comma-separated). Empty by default. visudo doesn't need to be here — it writes via temp-file + rename
	// and never opens /etc/sudoers in write mode, so the rule never sees it.
	SudoersWriterAllowlist map[string]struct{}

	// SuspiciousExecParentAllowlist is the set of non-shell parent paths the `suspicious_exec` rule should treat as benign roots even
	// when they sit at the root of a "non-shell -> shell -> /tmp/binary" chain. Populated from EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST
	// (comma-separated). Empty by default. The recommended value for fleets that allow interactive admin SSH is
	// `/usr/libexec/sshd-session, /Applications/Terminal.app/Contents/MacOS/Terminal, /Applications/iTerm.app/Contents/MacOS/iTerm2`.
	// Leave empty on servers where interactive SSH is unusual — the rule's "non-shell -> shell -> /tmp/" shape is then a clean attacker
	// indicator.
	SuspiciousExecParentAllowlist map[string]struct{}

	// DisabledRuleIDs is the boot-time list of rule IDs to drop from the detection registry. Populated from EDR_DISABLED_RULES
	// (comma-separated rule_id values). A disabled rule is gone from the engine's active set AND from Engine.Catalog() so
	// tools/gen-rule-docs + the GET /api/rules surface stop listing it. Empty by default. Unknown IDs WARN at boot but never
	// fail the boot, so a stale operator config doesn't take a deployment down. Hot reload is intentionally out of scope --
	// see spec server-detection-rules-engine/operator-toggling-of-individual-rules for the boot-time contract.
	DisabledRuleIDs []string

	// HostTokenLifetime is the maximum age of an agent's bearer token before the verify path triggers an automatic rotation (issue #86).
	// Populated from EDR_HOST_TOKEN_LIFETIME. Default 24h: short enough that an exfiltrated token has bounded value, long enough that the
	// per-host rotation traffic is negligible.
	HostTokenLifetime time.Duration
	// HostTokenGrace is the window during which a just-rotated previous token still verifies. Populated from EDR_HOST_TOKEN_GRACE. Default
	// 5m: comfortably wider than an agent's poll interval so an in-flight request doesn't 401 mid-cycle.
	HostTokenGrace time.Duration

	// TrustedProxies is the set of CIDRs (or bare IPs) the server will trust X-Forwarded-For from. Populated from EDR_TRUSTED_PROXIES
	// (comma-separated). Empty by default — XFF is ignored and the per-IP rate limiter + audit log see the direct TCP peer (issue #81).
	// Set this to your reverse proxy / load-balancer pool the moment you put an ALB / nginx / Cloudflare in front of fleet-edr-server,
	// or one user hitting the rate limit will lock out everyone behind the proxy.
	TrustedProxies []string

	// AuditReadSampling is the inclusion probability (0.0-1.0) the chokepoint applies to read-action allow events before submitting
	// them to the async writer. Default 0.0 (audit zero non-carve-out read-allow events). Operators set EDR_AUDIT_READ_SAMPLING=1.0 to
	// keep the wave-1 historical behavior of auditing every decision. Carve-outs ALWAYS audit regardless of rate: break-glass actor +
	// ActionAuditRead (the audit-of-audit row).
	AuditReadSampling float64

	// AuditAsyncQueueCap sizes the bounded buffer in the async audit writer. Default 8192 (~minutes of read-burst headroom at wave-1
	// volumes). Larger reduces drop probability under burst at the cost of more memory; smaller catches a queue-leak earlier. Populated
	// from EDR_AUDIT_ASYNC_QUEUE_CAP. Zero -> use the package default.
	AuditAsyncQueueCap int

	// OIDC authentication configuration. When OIDCIssuer is non-empty, the server enables the OIDC sign-in flow at /api/auth/login +
	// /api/auth/callback. When OIDCIssuer is empty, the server refuses to start unless AuthAllowNoOIDC=true (which lets dev workflows run
	// break-glass-only). All fields are populated from EDR_OIDC_* env vars.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	// OIDCScopes are the scopes requested at AuthURL time. Default is [openid, email, profile] which gives the verifier the claims it
	// needs (sub, email, name) without leaking unused permissions. Wave-2 will add `groups` for role mapping.
	OIDCScopes []string
	// OIDCAllowJITProvisioning controls whether a successful OIDC sign-in by an unknown subject creates a user + identity + default role
	// binding. true = create on first sign-in (recommended for most deployments); false = require an admin to pre-provision the user.
	// Default true.
	OIDCAllowJITProvisioning bool
	// OIDCStateCookieTTL bounds how long the signed state cookie (carrying state + nonce + PKCE verifier) stays valid. Defaults to 5m;
	// tune up for slow IdPs / MFA prompts.
	OIDCStateCookieTTL time.Duration

	// AuthAllowNoOIDC is the dedicated dev flag that lets the server boot in break-glass-only mode (no OIDC). Default false:
	// production deployments without OIDC config refuse to start with an explicit error pointing the operator at the missing
	// env vars. Set EDR_AUTH_ALLOW_NO_OIDC=1 in dev environments where running against a real IdP is overkill. The TLS posture
	// has no equivalent opt-out: TLS cert + key are unconditionally required (issue #140).
	AuthAllowNoOIDC bool

	// SessionSigningKey is the HMAC key the OIDC state cookie uses to sign + verify per-flow secrets (state, nonce, PKCE verifier).
	// The same key may be reused for signed session metadata. Populated from EDR_SESSION_SIGNING_KEY (or EDR_SESSION_SIGNING_KEY_FILE
	// for docker-secret mounts). Required when OIDC is enabled; validated at boot to be at least 32 bytes.
	SessionSigningKey []byte

	// Break-glass surface knobs. Empty / zero values fall through to
	// the per-package defaults documented at each field.

	// BreakglassBootstrapTokenTTL bounds how long the redemption URL printed at first boot stays redeemable. Default 1h. Shorter caps the
	// value of an exfiltrated stderr log; longer gives a busy operator more time to redeem before re-launching.
	BreakglassBootstrapTokenTTL time.Duration
	// BreakglassIPAllowlist is the optional CIDR (or bare-IP) list the /admin/break-glass surface gates on. Off-list callers receive a
	// generic 404. Empty default = no gate (dev workflow shape; production should set this to the operator bastion's CIDR).
	BreakglassIPAllowlist []string
	// BreakglassRPID is the WebAuthn relying-party identifier — the canonical host that browser-stored credentials bind to. Typically
	// the registrable host portion of the EDR UI URL without scheme (e.g. "edr.example.com"). Required when the break-glass surface is
	// enabled; changing it post-deploy invalidates every registered credential.
	BreakglassRPID string
	// BreakglassRPDisplayName is the operator-visible name shown by the browser during authenticator enrollment. Defaults to "EDR
	// Break-glass" if unset.
	BreakglassRPDisplayName string
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
	// sessions. Idle = NOW() - last_seen_at; the middleware slides
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
		RetentionDays:            defaultRetentionDays,
		RetentionInterval:        time.Hour,
		StaleProcessTTL:          defaultStaleProcessTTL,
		StaleProcessInterval:     defaultStaleProcessInterval,
		HostTokenLifetime:        defaultHostTokenLifetime,
		HostTokenGrace:           defaultHostTokenGrace,
		ShutdownDrain:            defaultShutdownDrain,
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
	return loadFrom(FileBackedGetenv(os.Getenv, slog.Default())) //nolint:forbidigo // approved config-load boundary; loadFrom takes a getenv fn so tests inject (issue #172)
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
	requireStr(&c.DSN, "EDR_DSN", getenv, errs, true)
	optionalStr(&c.ListenAddr, "EDR_LISTEN_ADDR", getenv)
	requireStr(&c.EnrollSecret, "EDR_ENROLL_SECRET", getenv, errs, true)
	optionalStr(&c.TLSCertFile, "EDR_TLS_CERT_FILE", getenv)
	optionalStr(&c.TLSKeyFile, "EDR_TLS_KEY_FILE", getenv)

	c.AllowTLS12 = getenv("EDR_TLS_ALLOW_TLS12") == "1"
	// NonNegative (not Positive): 0 is the documented "disable the drain wait" sentinel — RunAndShutdown skips the drain phase and
	// shuts down immediately. Integration + single-process tests set EDR_SHUTDOWN_DRAIN=0 so they don't sleep the drain window.
	envparse.NonNegativeDuration(getenv, "EDR_SHUTDOWN_DRAIN", &c.ShutdownDrain, errs)
	envparse.UnitFraction(getenv, "EDR_AUDIT_READ_SAMPLING", &c.AuditReadSampling, errs)
	envparse.NonNegativeInt(getenv, "EDR_AUDIT_ASYNC_QUEUE_CAP", &c.AuditAsyncQueueCap, errs)

	if v := getenv("EDR_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = splitCSV(v)
	}
}

// loadTLSConfig validates the TLS configuration's cross-field
// invariants now that loadCoreEnv has populated the cert paths.
func loadTLSConfig(c *Config, errs *[]error) {
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		*errs = append(*errs, errors.New(
			"EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE are both required: the server has no plaintext-HTTP mode (issue #140)"))
		return
	}
	// Fail fast on unreadable / mismatched cert material so boot exits before bootstrap.New mutates the DB (admin seeding prints
	// a one-time password the operator can lose to log noise on a misconfigured retry). configureTLS in cmd/main would otherwise
	// catch this only AFTER ApplySchema + seedAdmin had already run (CodeRabbit review on PR #182).
	if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
		*errs = append(*errs, fmt.Errorf("EDR_TLS_CERT_FILE/EDR_TLS_KEY_FILE unreadable or mismatched: %w", err))
	}
}

// loadRateLimits parses the per-minute throttles for enroll + login alongside the retention/process-reconciler windows. All but
// retention require strictly-positive values; retention permits 0 as the documented "disable" sentinel.
func loadRateLimits(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveInt(getenv, "EDR_ENROLL_RATE_PER_MIN", &c.EnrollRatePerMin, errs)
	envparse.NonNegativeInt(getenv, "EDR_RETENTION_DAYS", &c.RetentionDays, errs)
	envparse.PositiveDuration(getenv, "EDR_RETENTION_INTERVAL", &c.RetentionInterval, errs)
	envparse.NonNegativeDuration(getenv, "EDR_STALE_PROCESS_TTL", &c.StaleProcessTTL, errs)
	envparse.PositiveDuration(getenv, "EDR_STALE_PROCESS_INTERVAL", &c.StaleProcessInterval, errs)
}

// loadHostTokenConfig parses the wave-1 host-token rotation knobs and enforces the cross-field invariant: grace MUST be strictly
// shorter than lifetime. Both must be positive; "disable rotation" is not a supported deployment mode (a never-rotating bearer
// token is the very thing this feature exists to fix). With grace >= lifetime, two consecutive rotations would leave THREE valid
// tokens at once (current + previous still in grace + previous-previous's grace window stretching past the next rotation), which the
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
	if disabled := splitCSV(getenv("EDR_DISABLED_RULES")); len(disabled) > 0 {
		c.DisabledRuleIDs = disabled
	}
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

// loadProcessConfig parses the detection processor cadence knobs. Interval must be strictly positive (processor.Run feeds it into
// time.NewTicker which panics on non-positive values); batch must be strictly positive (a zero-batch loop spins).
func loadProcessConfig(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveDuration(getenv, "EDR_PROCESS_INTERVAL", &c.ProcessInterval, errs)
	envparse.PositiveInt(getenv, "EDR_PROCESS_BATCH", &c.ProcessBatch, errs)
}

// loadOIDCConfig parses the Phase-4 authentication knobs and enforces the "OIDC required unless explicitly opted out" gate.
// When EDR_OIDC_ISSUER is non-empty, the rest of the config block is validated as a coherent set; missing client_id / redirect URL
// surfaces a focused error. When EDR_OIDC_ISSUER is empty, the gate requires EDR_AUTH_ALLOW_NO_OIDC=1 so dev workflows can opt into
// break-glass-only mode without a silent fallback in production.
func loadOIDCConfig(c *Config, getenv func(string) string, errs *[]error) {
	optionalStr(&c.OIDCIssuer, "EDR_OIDC_ISSUER", getenv)
	optionalStr(&c.OIDCClientID, "EDR_OIDC_CLIENT_ID", getenv)
	optionalStr(&c.OIDCClientSecret, "EDR_OIDC_CLIENT_SECRET", getenv)
	optionalStr(&c.OIDCRedirectURL, "EDR_OIDC_REDIRECT_URL", getenv)
	parseOIDCOverrides(c, getenv, errs)
	envparse.PositiveDuration(getenv, "EDR_OIDC_STATE_COOKIE_TTL", &c.OIDCStateCookieTTL, errs)
	c.AuthAllowNoOIDC = getenv("EDR_AUTH_ALLOW_NO_OIDC") == "1"
	if v := getenv("EDR_SESSION_SIGNING_KEY"); v != "" {
		c.SessionSigningKey = []byte(v)
	}
	enforceOIDCGate(c, errs)
}

// parseOIDCOverrides reads the optional override env vars (EDR_OIDC_SCOPES, EDR_OIDC_ALLOW_JIT_PROVISIONING) onto c. Pulled out so
// loadOIDCConfig stays under the cognitive-complexity budget.
func parseOIDCOverrides(c *Config, getenv func(string) string, errs *[]error) {
	if v := getenv("EDR_OIDC_SCOPES"); v != "" {
		c.OIDCScopes = splitCSV(v)
		// openid is mandatory for the discovery + ID-token flow; an override that drops it leaves the operator with a worse failure mode
		// (token endpoint succeeds, ID-token absent at callback) than a startup refusal.
		if !slices.Contains(c.OIDCScopes, "openid") {
			*errs = append(*errs, errors.New(
				"EDR_OIDC_SCOPES must include \"openid\" (the OIDC core scope)"))
		}
	}
	if v := getenv("EDR_OIDC_ALLOW_JIT_PROVISIONING"); v != "" {
		c.OIDCAllowJITProvisioning = v == "1"
	}
}

// enforceOIDCGate cross-checks the OIDC env block: every OIDC field is set together, OR none is set AND AuthAllowNoOIDC is the
// explicit dev opt-out. Anything else is a misconfiguration the operator should surface at boot rather than silently fall back to
// break-glass-only mode. The allow-no-oidc opt-out specifically does NOT excuse partial configuration: if any EDR_OIDC_* knob is set,
// the operator clearly intends OIDC and a missing companion is a typo, not an opt-out.
func enforceOIDCGate(c *Config, errs *[]error) {
	if c.OIDCIssuer != "" && len(c.SessionSigningKey) < oidcSigningKeyMinBytes {
		*errs = append(*errs, errors.New(
			"EDR_SESSION_SIGNING_KEY is required when OIDC is enabled; "+
				"must be at least 32 bytes (use EDR_SESSION_SIGNING_KEY_FILE for docker-secret mounts)"))
	}
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
		appendIfMissing(c.OIDCClientID, "EDR_OIDC_CLIENT_ID is required when EDR_OIDC_ISSUER is set", errs)
		appendIfMissing(c.OIDCClientSecret, "EDR_OIDC_CLIENT_SECRET is required when EDR_OIDC_ISSUER is set"+
			" (use EDR_OIDC_CLIENT_SECRET_FILE for docker-secret mounts)", errs)
		appendIfMissing(c.OIDCRedirectURL, "EDR_OIDC_REDIRECT_URL is required when EDR_OIDC_ISSUER is set", errs)
	}
}

// oidcSigningKeyMinBytes is the wave-1 floor for EDR_SESSION_SIGNING_KEY. 32 bytes matches the HMAC-SHA256 block size used by the
// state cookie signer; shorter keys silently weaken the signature without an obvious runtime symptom.
const oidcSigningKeyMinBytes = 32

// appendIfMissing emits msg when v is empty. Tiny helper so the gate switch reads as a list of cross-checks rather than three near-
// identical branches.
func appendIfMissing(v, msg string, errs *[]error) {
	if v == "" {
		*errs = append(*errs, errors.New(msg))
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
	optionalStr(&c.BreakglassRPDisplayName, "EDR_BREAKGLASS_RP_DISPLAY_NAME", getenv)
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
