package config

import (
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envMap(pairs map[string]string) func(string) string {
	return func(k string) string {
		return pairs[k]
	}
}

func TestLoad(t *testing.T) {
	// Minimal env mirrors the wave-1 dev workflow: TLS off + the Phase-4 break-glass-only opt-out. Production sets neither flag and
	// provides EDR_OIDC_*; that interaction is covered in a dedicated sub-test below.
	minEnv := map[string]string{
		"EDR_DSN":                 "root@tcp(127.0.0.1:3306)/edr?parseTime=true",
		"EDR_ENROLL_SECRET":       "enroll-me",
		"EDR_ALLOW_INSECURE_HTTP": "1",
		"EDR_AUTH_ALLOW_NO_OIDC":  "1",
	}

	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		validate func(t *testing.T, c *Config)
	}{
		{
			name: "happy path with required vars only",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "root@tcp(127.0.0.1:3306)/edr?parseTime=true", c.DSN)
				assert.Equal(t, "enroll-me", c.EnrollSecret)
				assert.True(t, c.AllowInsecureHTTP)
				assert.Equal(t, ":8088", c.ListenAddr)
				assert.Equal(t, "info", c.LogLevel)
				assert.Equal(t, "json", c.LogFormat)
				assert.Equal(t, 500*time.Millisecond, c.ProcessInterval)
				assert.Equal(t, 500, c.ProcessBatch)
				assert.Equal(t, 30, c.EnrollRatePerMin)
				assert.False(t, c.TLSEnabled())
			},
		},
		{
			name: "missing EDR_DSN",
			env: map[string]string{
				"EDR_ENROLL_SECRET":       "s",
				"EDR_ALLOW_INSECURE_HTTP": "1",
			},
			wantErr: "EDR_DSN",
		},
		{
			name: "missing EDR_ENROLL_SECRET",
			env: map[string]string{
				"EDR_DSN":                 "x",
				"EDR_ALLOW_INSECURE_HTTP": "1",
			},
			wantErr: "EDR_ENROLL_SECRET",
		},
		{
			name: "TLS required unless EDR_ALLOW_INSECURE_HTTP=1",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_ENROLL_SECRET": "s",
			},
			wantErr: "EDR_TLS_CERT_FILE is required",
		},
		{
			name: "missing every required var reports each",
			env:  map[string]string{},
			validate: func(t *testing.T, _ *Config) {
				t.Helper()
				t.Fatalf("validate should not be called when wantErr is set")
			},
			wantErr: "EDR_DSN\nrequired env var EDR_ENROLL_SECRET",
		},
		{
			name: "TLS key without cert",
			env: withExtra(minEnv, map[string]string{
				"EDR_TLS_KEY_FILE": "/tmp/edr.key",
			}),
			wantErr: "EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE must be set together",
		},
		{
			name: "TLS cert without key",
			env: withExtra(minEnv, map[string]string{
				"EDR_TLS_CERT_FILE": "/tmp/edr.crt",
			}),
			wantErr: "EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE must be set together",
		},
		{
			name: "TLS both set",
			env: withExtra(minEnv, map[string]string{
				"EDR_TLS_CERT_FILE": "/tmp/edr.crt",
				"EDR_TLS_KEY_FILE":  "/tmp/edr.key",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.True(t, c.TLSEnabled())
			},
		},
		{
			name: "bad log level",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_LEVEL": "spam",
			}),
			wantErr: `EDR_LOG_LEVEL="spam" must be one of debug, info, warn, error`,
		},
		{
			name: "bad log format",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_FORMAT": "xml",
			}),
			wantErr: `EDR_LOG_FORMAT="xml" must be 'json' or 'text'`,
		},
		{
			name: "bad process interval",
			env: withExtra(minEnv, map[string]string{
				"EDR_PROCESS_INTERVAL": "not-a-duration",
			}),
			wantErr: "EDR_PROCESS_INTERVAL",
		},
		{
			name: "zero process interval rejected (would panic ticker)",
			env: withExtra(minEnv, map[string]string{
				"EDR_PROCESS_INTERVAL": "0s",
			}),
			wantErr: `EDR_PROCESS_INTERVAL="0s" must be positive`,
		},
		{
			name: "negative process interval rejected",
			env: withExtra(minEnv, map[string]string{
				"EDR_PROCESS_INTERVAL": "-500ms",
			}),
			wantErr: "must be positive",
		},
		{
			name: "log level normalized to lowercase",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_LEVEL": "WARN",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "warn", c.LogLevel)
			},
		},
		{
			name: "log format normalized to lowercase",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_FORMAT": "JSON",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "json", c.LogFormat)
			},
		},
		{
			name: "bad process batch",
			env: withExtra(minEnv, map[string]string{
				"EDR_PROCESS_BATCH": "banana",
			}),
			wantErr: "EDR_PROCESS_BATCH",
		},
		{
			name: "zero process batch rejected",
			env: withExtra(minEnv, map[string]string{
				"EDR_PROCESS_BATCH": "0",
			}),
			wantErr: "EDR_PROCESS_BATCH=0 must be positive",
		},
		{
			name: "optional overrides applied",
			env: withExtra(minEnv, map[string]string{
				"EDR_LISTEN_ADDR":      "127.0.0.1:9090",
				"EDR_LOG_LEVEL":        "debug",
				"EDR_LOG_FORMAT":       "text",
				"EDR_PROCESS_INTERVAL": "1s",
				"EDR_PROCESS_BATCH":    "200",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "127.0.0.1:9090", c.ListenAddr)
				assert.Equal(t, "enroll-me", c.EnrollSecret)
				assert.Equal(t, "debug", c.LogLevel)
				assert.Equal(t, "text", c.LogFormat)
				assert.Equal(t, time.Second, c.ProcessInterval)
				assert.Equal(t, 200, c.ProcessBatch)
			},
		},
		{
			name: "EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST parsed and trimmed",
			env: withExtra(minEnv, map[string]string{
				// Mixed whitespace + an empty entry to exercise envparse.Allowlist's
				// trim/empty-skip behaviour, same way every other allowlist env var
				// is documented to behave.
				"EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST": "/usr/libexec/sshd-session, /Applications/Terminal.app/Contents/MacOS/Terminal,,/Applications/iTerm.app/Contents/MacOS/iTerm2",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Len(t, c.SuspiciousExecParentAllowlist, 3,
					"allowlist must skip the empty entry")
				for _, want := range []string{
					"/usr/libexec/sshd-session",
					"/Applications/Terminal.app/Contents/MacOS/Terminal",
					"/Applications/iTerm.app/Contents/MacOS/iTerm2",
				} {
					_, ok := c.SuspiciousExecParentAllowlist[want]
					assert.True(t, ok, "allowlist must trim whitespace and contain %q", want)
				}
			},
		},
		{
			name: "EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST empty leaves nil map",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Nil(t, c.SuspiciousExecParentAllowlist,
					"unset env should leave the map nil so the rule treats every parent as not allowlisted")
			},
		},
		{
			name: "EDR_TRUSTED_PROXIES populates and trims",
			env: withExtra(minEnv, map[string]string{
				// Mixed CIDR forms + whitespace + an empty entry. CIDR
				// validation is deferred to httpserver.NewClientIPResolver,
				// so config-level parsing only trims and drops empties.
				"EDR_TRUSTED_PROXIES": " 10.0.0.0/8 , 192.168.1.5,, fd00::/8",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t,
					[]string{"10.0.0.0/8", "192.168.1.5", "fd00::/8"},
					c.TrustedProxies,
					"split must trim entries and drop the empty token")
			},
		},
		{
			name: "EDR_TRUSTED_PROXIES unset leaves nil slice",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Nil(t, c.TrustedProxies,
					"unset env keeps the secure default — XFF ignored, peer IP used")
			},
		},
		{
			name: "EDR_TRUSTED_PROXIES with only whitespace yields nil",
			env: withExtra(minEnv, map[string]string{
				"EDR_TRUSTED_PROXIES": " , , ",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Nil(t, c.TrustedProxies,
					"all-empty input must collapse to nil rather than an empty slice")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadFrom(envMap(tc.env))
			if tc.wantErr != "" {
				require.Error(t, err)
				for fragment := range strings.SplitSeq(tc.wantErr, "\n") {
					assert.Contains(t, err.Error(), fragment)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			if tc.validate != nil {
				tc.validate(t, got)
			}
		})
	}
}

// TestLoad_OIDCConfig covers the Phase-4a auth-mode enforcement: a production deployment without OIDC config refuses to start;
// dev mode opts out via EDR_AUTH_ALLOW_NO_OIDC=1; setting OIDC_ISSUER without the rest produces focused per-field errors.
func TestLoad_OIDCConfig(t *testing.T) {
	prodLikeEnv := map[string]string{
		"EDR_DSN":                 "root@tcp(127.0.0.1:3306)/edr?parseTime=true",
		"EDR_ENROLL_SECRET":       "enroll-me",
		"EDR_ALLOW_INSECURE_HTTP": "1",
	}

	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		validate func(t *testing.T, c *Config)
	}{
		{
			name:    "no OIDC + no dev flag -> refuse",
			env:     prodLikeEnv,
			wantErr: "EDR_OIDC_ISSUER is required",
		},
		{
			name: "no OIDC + dev flag -> ok",
			env:  withExtra(prodLikeEnv, map[string]string{"EDR_AUTH_ALLOW_NO_OIDC": "1"}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.True(t, c.AuthAllowNoOIDC)
				assert.Empty(t, c.OIDCIssuer)
			},
		},
		{
			name: "issuer set without client_id -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER": "https://example.okta.com",
			}),
			wantErr: "EDR_OIDC_CLIENT_ID is required",
		},
		{
			name: "issuer + client_id without secret -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":    "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID": "edr",
			}),
			wantErr: "EDR_OIDC_CLIENT_SECRET is required",
		},
		{
			name: "issuer + client_id + secret without redirect -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
			}),
			wantErr: "EDR_OIDC_REDIRECT_URL is required",
		},
		{
			name: "OIDC enabled without signing key -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
				"EDR_OIDC_REDIRECT_URL":  "https://edr.example.com/api/auth/callback",
			}),
			wantErr: "EDR_SESSION_SIGNING_KEY is required",
		},
		{
			name: "OIDC enabled with short signing key -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":         "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":      "edr",
				"EDR_OIDC_CLIENT_SECRET":  "shh",
				"EDR_OIDC_REDIRECT_URL":   "https://edr.example.com/api/auth/callback",
				"EDR_SESSION_SIGNING_KEY": "tooshort",
			}),
			wantErr: "EDR_SESSION_SIGNING_KEY is required",
		},
		{
			name: "complete OIDC config -> ok with default scopes",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":         "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":      "edr",
				"EDR_OIDC_CLIENT_SECRET":  "shh",
				"EDR_OIDC_REDIRECT_URL":   "https://edr.example.com/api/auth/callback",
				"EDR_SESSION_SIGNING_KEY": "0123456789abcdef0123456789abcdef",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "https://example.okta.com", c.OIDCIssuer)
				assert.Equal(t, "edr", c.OIDCClientID)
				assert.Equal(t, "shh", c.OIDCClientSecret)
				assert.Equal(t, "https://edr.example.com/api/auth/callback", c.OIDCRedirectURL)
				assert.Equal(t, []string{"openid", "email", "profile"}, c.OIDCScopes)
				assert.True(t, c.OIDCAllowJITProvisioning)
				assert.Equal(t, 5*time.Minute, c.OIDCStateCookieTTL)
				assert.False(t, c.AuthAllowNoOIDC)
			},
		},
		{
			name: "EDR_OIDC_SCOPES override",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":         "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":      "edr",
				"EDR_OIDC_CLIENT_SECRET":  "shh",
				"EDR_OIDC_REDIRECT_URL":   "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_SCOPES":         "openid,email",
				"EDR_SESSION_SIGNING_KEY": "0123456789abcdef0123456789abcdef",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, []string{"openid", "email"}, c.OIDCScopes)
			},
		},
		{
			name: "EDR_OIDC_ALLOW_JIT_PROVISIONING=0 disables JIT",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":                 "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":              "edr",
				"EDR_OIDC_CLIENT_SECRET":          "shh",
				"EDR_OIDC_REDIRECT_URL":           "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_ALLOW_JIT_PROVISIONING": "0",
				"EDR_SESSION_SIGNING_KEY":         "0123456789abcdef0123456789abcdef",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.False(t, c.OIDCAllowJITProvisioning)
			},
		},
		{
			name: "EDR_OIDC_STATE_COOKIE_TTL override",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":           "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":        "edr",
				"EDR_OIDC_CLIENT_SECRET":    "shh",
				"EDR_OIDC_REDIRECT_URL":     "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_STATE_COOKIE_TTL": "10m",
				"EDR_SESSION_SIGNING_KEY":   "0123456789abcdef0123456789abcdef",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, 10*time.Minute, c.OIDCStateCookieTTL)
			},
		},
		{
			// EDR_OIDC_SCOPES override that drops "openid" must refuse
			// to start. Without openid the discovery + ID-token flow
			// has no contract; the failure is "token endpoint succeeds,
			// id_token absent at callback" which is harder to debug
			// than a startup error.
			name: "EDR_OIDC_SCOPES without openid is rejected",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":         "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":      "edr",
				"EDR_OIDC_CLIENT_SECRET":  "shh",
				"EDR_OIDC_REDIRECT_URL":   "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_SCOPES":         "email,profile",
				"EDR_SESSION_SIGNING_KEY": "0123456789abcdef0123456789abcdef",
			}),
			wantErr: "EDR_OIDC_SCOPES must include \"openid\"",
		},
		{
			// Partial OIDC config + EDR_AUTH_ALLOW_NO_OIDC=1 must NOT
			// silently disable OIDC. A typo in EDR_OIDC_ISSUER while
			// EDR_OIDC_CLIENT_ID is set is unmistakeably an OIDC
			// intent; falling through to break-glass-only mode masks
			// the misconfiguration.
			name: "partial OIDC config + allow-no-oidc still refuses",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_AUTH_ALLOW_NO_OIDC": "1",
				"EDR_OIDC_CLIENT_ID":     "edr",
			}),
			wantErr: "set without EDR_OIDC_ISSUER",
		},
		{
			// Same as above but with the secret set instead of client_id.
			name: "partial OIDC (secret only) + allow-no-oidc still refuses",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_AUTH_ALLOW_NO_OIDC": "1",
				"EDR_OIDC_CLIENT_SECRET": "shh",
			}),
			wantErr: "set without EDR_OIDC_ISSUER",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadFrom(envMap(tc.env))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			if tc.validate != nil {
				tc.validate(t, got)
			}
		})
	}
}

func withExtra(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

// TestLoad_AuditEnvKnobs covers the Phase 3 read-sampling + async-queue env knobs in isolation. Mirrors the pattern in TestLoad so a
// regression on either parser surfaces with a focused failure message rather than a single-line "test failed".
func TestLoad_AuditEnvKnobs(t *testing.T) {
	minEnv := map[string]string{
		"EDR_DSN":                 "root@tcp(127.0.0.1:3306)/edr?parseTime=true",
		"EDR_ENROLL_SECRET":       "enroll-me",
		"EDR_ALLOW_INSECURE_HTTP": "1",
		"EDR_AUTH_ALLOW_NO_OIDC":  "1",
	}

	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		validate func(t *testing.T, c *Config)
	}{
		{
			name: "defaults: read sampling 0.0 + async queue cap 0 (uses package default)",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.InDelta(t, 0.0, c.AuditReadSampling, 0.0001)
				assert.Equal(t, 0, c.AuditAsyncQueueCap,
					"zero stays zero so identity bootstrap can fall back to the audit pkg default")
			},
		},
		{
			name: "EDR_AUDIT_READ_SAMPLING=1.0 audits all read events",
			env:  withExtra(minEnv, map[string]string{"EDR_AUDIT_READ_SAMPLING": "1.0"}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.InDelta(t, 1.0, c.AuditReadSampling, 0.0001)
			},
		},
		{
			name: "EDR_AUDIT_READ_SAMPLING=0.5 mid-band sampling",
			env:  withExtra(minEnv, map[string]string{"EDR_AUDIT_READ_SAMPLING": "0.5"}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.InDelta(t, 0.5, c.AuditReadSampling, 0.0001)
			},
		},
		{
			name:    "EDR_AUDIT_READ_SAMPLING=-0.1 rejected",
			env:     withExtra(minEnv, map[string]string{"EDR_AUDIT_READ_SAMPLING": "-0.1"}),
			wantErr: "EDR_AUDIT_READ_SAMPLING",
		},
		{
			name:    "EDR_AUDIT_READ_SAMPLING=1.5 rejected (out of [0,1])",
			env:     withExtra(minEnv, map[string]string{"EDR_AUDIT_READ_SAMPLING": "1.5"}),
			wantErr: "EDR_AUDIT_READ_SAMPLING",
		},
		{
			name:    "EDR_AUDIT_READ_SAMPLING=abc rejected as non-numeric",
			env:     withExtra(minEnv, map[string]string{"EDR_AUDIT_READ_SAMPLING": "abc"}),
			wantErr: "EDR_AUDIT_READ_SAMPLING",
		},
		{
			name: "EDR_AUDIT_ASYNC_QUEUE_CAP=4096 picks operator-tuned size",
			env:  withExtra(minEnv, map[string]string{"EDR_AUDIT_ASYNC_QUEUE_CAP": "4096"}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, 4096, c.AuditAsyncQueueCap)
			},
		},
		{
			name:    "EDR_AUDIT_ASYNC_QUEUE_CAP=-1 rejected",
			env:     withExtra(minEnv, map[string]string{"EDR_AUDIT_ASYNC_QUEUE_CAP": "-1"}),
			wantErr: "EDR_AUDIT_ASYNC_QUEUE_CAP",
		},
		{
			name:    "EDR_AUDIT_ASYNC_QUEUE_CAP=notanint rejected",
			env:     withExtra(minEnv, map[string]string{"EDR_AUDIT_ASYNC_QUEUE_CAP": "notanint"}),
			wantErr: "EDR_AUDIT_ASYNC_QUEUE_CAP",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadFrom(envMap(tc.env))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			if tc.validate != nil {
				tc.validate(t, got)
			}
		})
	}
}
