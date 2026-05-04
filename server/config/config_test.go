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
	minEnv := map[string]string{
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
				assert.Equal(t, 6, c.LoginRatePerMin)
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
				"EDR_LISTEN_ADDR":        "127.0.0.1:9090",
				"EDR_LOG_LEVEL":          "debug",
				"EDR_LOG_FORMAT":         "text",
				"EDR_PROCESS_INTERVAL":   "1s",
				"EDR_PROCESS_BATCH":      "200",
				"EDR_LOGIN_RATE_PER_MIN": "20",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "127.0.0.1:9090", c.ListenAddr)
				assert.Equal(t, "enroll-me", c.EnrollSecret)
				assert.Equal(t, "debug", c.LogLevel)
				assert.Equal(t, "text", c.LogFormat)
				assert.Equal(t, time.Second, c.ProcessInterval)
				assert.Equal(t, 200, c.ProcessBatch)
				assert.Equal(t, 20, c.LoginRatePerMin)
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
			name: "invalid login rate rejected",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOGIN_RATE_PER_MIN": "banana",
			}),
			wantErr: "EDR_LOGIN_RATE_PER_MIN",
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
		{
			name: "zero login rate rejected",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOGIN_RATE_PER_MIN": "0",
			}),
			wantErr: "EDR_LOGIN_RATE_PER_MIN=0 must be positive",
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

func withExtra(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

// TestLoad_AuditEnvKnobs covers the Phase 3 read-sampling +
// async-queue env knobs in isolation. Mirrors the pattern in TestLoad
// so a regression on either parser surfaces with a focused failure
// message rather than a single-line "test failed".
func TestLoad_AuditEnvKnobs(t *testing.T) {
	minEnv := map[string]string{
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
