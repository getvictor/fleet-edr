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

	mysqldriver "github.com/go-sql-driver/mysql"

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
	// defaultHostTokenLifetime is the TTL of a minted signed host token: how long it is valid before the agent must refresh it. The
	// agent refreshes well before expiry; 60 minutes matches SPIFFE hot-path workload-identity guidance.
	defaultHostTokenLifetime = 60 * time.Minute
	// defaultOIDCStateCookieTTL is how long the signed state cookie that carries (state, nonce, code_verifier) stays valid. 5 minutes
	// matches the IdP's typical authorization-code window: long enough to survive an MFA prompt, short enough to bound CSRF replay.
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
	// Default 6h: long enough to cover normal analyst-session work but
	// short enough that overnight greens are gone by morning.
	StaleProcessTTL time.Duration
	// StaleProcessInterval is how often the process-TTL reconciler runs.
	// Default 10m.
	StaleProcessInterval time.Duration

	// LaunchAgentAllowlist is the set of plist paths the `persistence_launchagent` rule should silently accept. Populated from
	// EDR_LAUNCHAGENT_ALLOWLIST (comma-separated absolute paths). Empty by default: every plist load fires.
	LaunchAgentAllowlist map[string]struct{}

	// LaunchDaemonTeamIDAllowlist is the set of code-signing team IDs the `privilege_launchd_plist_write` rule should silently accept when
	// they write to /Library/LaunchDaemons. Populated from EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST (comma-separated team IDs). Apple-signed
	// platform binaries (installd, system_installd, ...) are always allowed; this list is for non-Apple MDM agents that legitimately drop
	// daemons (Munki, Kandji, JumpCloud, ...). Empty by default.
	LaunchDaemonTeamIDAllowlist map[string]struct{}

	// SudoersWriterAllowlist is the set of writer-process absolute paths the `sudoers_tamper` rule should silently accept. Populated from
	// EDR_SUDOERS_WRITER_ALLOWLIST (comma-separated). Empty by default. visudo doesn't need to be here: it writes via temp-file + rename
	// and never opens /etc/sudoers in write mode, so the rule never sees it.
	SudoersWriterAllowlist map[string]struct{}

	// SuspiciousExecParentAllowlist is the set of non-shell parent paths the `suspicious_exec` rule should treat as benign roots even
	// when they sit at the root of a "non-shell -> shell -> /tmp/binary" chain. Populated from EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST
	// (comma-separated). Empty by default. The recommended value for fleets that allow interactive admin SSH is
	// `/usr/libexec/sshd-session, /Applications/Terminal.app/Contents/MacOS/Terminal, /Applications/iTerm.app/Contents/MacOS/iTerm2`.
	// Leave empty on servers where interactive SSH is unusual: the rule's "non-shell -> shell -> /tmp/" shape is then a clean attacker
	// indicator.
	SuspiciousExecParentAllowlist map[string]struct{}

	// DisabledRuleIDs is the boot-time list of rule IDs to drop from the detection registry. Populated from EDR_DISABLED_RULES
	// (comma-separated rule_id values). A disabled rule is gone from the engine's active set AND from Engine.Catalog() so
	// tools/gen-rule-docs + the GET /api/rules surface stop listing it. Empty by default. Unknown IDs WARN at boot but never
	// fail the boot, so a stale operator config doesn't take a deployment down. Hot reload is intentionally out of scope --
	// see spec server-detection-rules-engine/operator-toggling-of-individual-rules for the boot-time contract.
	DisabledRuleIDs []string

	// HostTokenLifetime is the TTL of a minted signed host token: how long it is valid before the agent must refresh it. Populated from
	// EDR_HOST_TOKEN_LIFETIME. Default 60m: short enough that a leaked token has bounded value, long enough that refresh traffic is
	// negligible.
	HostTokenLifetime time.Duration

	// TrustedProxies is the set of CIDRs (or bare IPs) the server will trust X-Forwarded-For from. Populated from EDR_TRUSTED_PROXIES
	// (comma-separated). Empty by default: XFF is ignored and the per-IP rate limiter + audit log see the direct TCP peer (issue #81).
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
	// OIDCDefaultRole is the role a JIT-provisioned OIDC user is bound to. Populated from EDR_OIDC_DEFAULT_ROLE; empty falls through to
	// the identity context's default (`analyst`). Must name a seeded role. Lets a deployment land SSO users at a higher role without
	// per-user pre-provisioning (the docker demo uses it to land its single SSO user at `admin`).
	OIDCDefaultRole string
	// OIDCStateCookieTTL bounds how long the signed state cookie (carrying state + nonce + PKCE verifier) stays valid. Defaults to 5m;
	// tune up for slow IdPs / MFA prompts.
	OIDCStateCookieTTL time.Duration

	// AuthAllowNoOIDC is the dedicated dev flag that lets the server boot in break-glass-only mode (no OIDC). Default false:
	// production deployments without OIDC config refuse to start with an explicit error pointing the operator at the missing
	// env vars. Set EDR_AUTH_ALLOW_NO_OIDC=1 in dev environments where running against a real IdP is overkill. The TLS posture
	// has no equivalent opt-out: TLS cert + key are unconditionally required (issue #140).
	AuthAllowNoOIDC bool

	// SecretKey is the deployment root secret. Every long-lived server-side key is derived from it via HKDF (internal/keyring) under a
	// versioned domain-separation label: the host-token signing key and the pre-auth cookie signing key (OIDC state + break-glass
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

// composeDSN builds a go-sql-driver DSN from discrete EDR_MYSQL_* parts, or returns "" if any required part is missing. The parts
// mirror the values a PaaS blueprint can wire from a managed/bundled MySQL service (host:port + generated user/password/db). It
// goes through go-sql-driver's Config.FormatDSN rather than fmt.Sprintf so a generated password containing DSN metacharacters
// (`@`, `:`, `/`, `?`) is escaped instead of corrupting the DSN. PaaS blueprints generate such passwords routinely, so naive
// string interpolation would intermittently brick boot (the same round-trip rationale as testdb's replaceDBName).
func composeDSN(getenv func(string) string) string {
	addr := getenv("EDR_MYSQL_ADDRESS")
	user := getenv("EDR_MYSQL_USERNAME")
	pass := getenv("EDR_MYSQL_PASSWORD")
	db := getenv("EDR_MYSQL_DATABASE")
	if addr == "" || user == "" || pass == "" || db == "" {
		return ""
	}
	dc := mysqldriver.NewConfig()
	dc.User = user
	dc.Passwd = pass
	dc.Net = "tcp"
	dc.Addr = addr
	dc.DBName = db
	dc.ParseTime = true
	return dc.FormatDSN()
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
	loadSecretKey(&c, getenv, &errs)
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
	// EDR_DSN is the canonical single-string DSN. When it is empty, compose one from discrete parts
	// (EDR_MYSQL_ADDRESS/USERNAME/PASSWORD/DATABASE). Some PaaS blueprints (Fly, ECS, and similar) hand the DB host:port and a
	// generated password to separate env vars and cannot interpolate them into one DSN string, so the compose-from-parts path is
	// what makes a one-click blueprint work. An explicit EDR_DSN always wins.
	optionalStr(&c.DSN, "EDR_DSN", getenv)
	if c.DSN == "" {
		c.DSN = composeDSN(getenv)
	}
	if c.DSN == "" {
		*errs = append(*errs, errors.New(
			"EDR_DSN is required (or supply EDR_MYSQL_ADDRESS + EDR_MYSQL_USERNAME + EDR_MYSQL_PASSWORD + EDR_MYSQL_DATABASE)"))
	}
	optionalStr(&c.ListenAddr, "EDR_LISTEN_ADDR", getenv)
	requireStr(&c.EnrollSecret, "EDR_ENROLL_SECRET", getenv, errs, true)
	optionalStr(&c.TLSCertFile, "EDR_TLS_CERT_FILE", getenv)
	optionalStr(&c.TLSKeyFile, "EDR_TLS_KEY_FILE", getenv)

	c.AllowTLS12 = getenv("EDR_TLS_ALLOW_TLS12") == "1"
	c.TLSTerminatedByProxy = getenv("EDR_TLS_TERMINATED_BY_PROXY") == "1"
	// NonNegative (not Positive): 0 is the documented "disable the drain wait" sentinel. RunAndShutdown skips the drain phase and
	// shuts down immediately. Integration + single-process tests set EDR_SHUTDOWN_DRAIN=0 so they don't sleep the drain window.
	envparse.NonNegativeDuration(getenv, "EDR_SHUTDOWN_DRAIN", &c.ShutdownDrain, errs)
	envparse.UnitFraction(getenv, "EDR_AUDIT_READ_SAMPLING", &c.AuditReadSampling, errs)
	envparse.NonNegativeInt(getenv, "EDR_AUDIT_ASYNC_QUEUE_CAP", &c.AuditAsyncQueueCap, errs)

	if v := getenv("EDR_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = splitCSV(v)
	}
}

// secretKeyMinBytes is the floor for EDR_SECRET_KEY. 32 bytes matches the HKDF-SHA256 output width every derived key uses; a shorter
// root would cap the entropy of the host-token signing key and the cookie signing key regardless of their requested length.
const secretKeyMinBytes = 32

// loadSecretKey reads + validates the deployment root secret. Unlike the OIDC signing key it replaces, it is required unconditionally:
// the host-token signing key derives from it and host tokens are used by every deployment, OIDC or not. The EDR_SECRET_KEY_FILE
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

// loadRateLimits parses the per-minute throttles for enroll + login alongside the retention/process-reconciler windows. All but
// retention require strictly-positive values; retention permits 0 as the documented "disable" sentinel.
func loadRateLimits(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveInt(getenv, "EDR_ENROLL_RATE_PER_MIN", &c.EnrollRatePerMin, errs)
	envparse.NonNegativeInt(getenv, "EDR_RETENTION_DAYS", &c.RetentionDays, errs)
	envparse.PositiveDuration(getenv, "EDR_RETENTION_INTERVAL", &c.RetentionInterval, errs)
	envparse.NonNegativeDuration(getenv, "EDR_STALE_PROCESS_TTL", &c.StaleProcessTTL, errs)
	envparse.PositiveDuration(getenv, "EDR_STALE_PROCESS_INTERVAL", &c.StaleProcessInterval, errs)
}

// loadHostTokenConfig parses the host-token lifetime. Under the self-validating-token model there is no rotation grace window: the
// agent pulls a fresh token before expiry, and credential cycling is an epoch bump that takes effect once the revocation snapshot
// catches up, not a rotate-with-grace. Lifetime must be positive when set; zero falls back to the service default.
func loadHostTokenConfig(c *Config, getenv func(string) string, errs *[]error) {
	envparse.PositiveDuration(getenv, "EDR_HOST_TOKEN_LIFETIME", &c.HostTokenLifetime, errs)
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
	enforceOIDCGate(c, errs)
}

// builtinRoleIDs is the set of seeded RBAC role IDs that EDR_OIDC_DEFAULT_ROLE may name. Kept in sync with the canonical list in
// server/identity/internal/seed/roles.go; config is a platform package and cannot import an identity-context internal package, so
// the list is duplicated here behind this sync note. Validating against it at boot turns a mistyped role into a clear startup
// error instead of an opaque foreign-key failure on the first SSO sign-in.
var builtinRoleIDs = []string{"super_admin", "admin", "senior_analyst", "analyst", "auditor"}

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
	if v := getenv("EDR_OIDC_DEFAULT_ROLE"); v != "" {
		// Normalize away whitespace + case typos; role IDs are canonically lower-case.
		role := strings.ToLower(strings.TrimSpace(v))
		if !slices.Contains(builtinRoleIDs, role) {
			*errs = append(*errs, fmt.Errorf("EDR_OIDC_DEFAULT_ROLE %q is not a known role; allowed values: %s",
				v, strings.Join(builtinRoleIDs, ", ")))
		}
		c.OIDCDefaultRole = role
	}
}

// enforceOIDCGate cross-checks the OIDC env block: every OIDC field is set together, OR none is set AND AuthAllowNoOIDC is the
// explicit dev opt-out. Anything else is a misconfiguration the operator should surface at boot rather than silently fall back to
// break-glass-only mode. The allow-no-oidc opt-out specifically does NOT excuse partial configuration: if any EDR_OIDC_* knob is set,
// the operator clearly intends OIDC and a missing companion is a typo, not an opt-out.
func enforceOIDCGate(c *Config, errs *[]error) {
	partialOIDC := c.OIDCClientID != "" || c.OIDCClientSecret != "" || c.OIDCRedirectURL != "" || c.OIDCDefaultRole != ""
	switch {
	case c.OIDCIssuer == "" && partialOIDC:
		*errs = append(*errs, errors.New(
			"EDR_OIDC_CLIENT_ID/CLIENT_SECRET/REDIRECT_URL/DEFAULT_ROLE set without EDR_OIDC_ISSUER; "+
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
