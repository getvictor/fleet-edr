package config

import (
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envMap(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

func TestLoad(t *testing.T) {
	minEnv := map[string]string{
		"EDR_SERVER_URL": "https://edr.example.com",
	}

	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		validate func(t *testing.T, c *Config)
	}{
		{
			name: "happy path",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "https://edr.example.com", c.ServerURL)
				assert.Equal(t, "/var/db/fleet-edr/events.db", c.QueueDBPath)
				assert.Equal(t, "json", c.LogFormat)
			},
		},
		{
			// Removed tuning knobs must be inert: setting them (even to unparseable junk the old parsers would have rejected)
			// must not fail startup. The trimmed agent ignores them and uses the fixed defaults.
			// spec:agent-configuration/the-agent-configuration-surface-is-intentionally-minimal/a-removed-tuning-variable-is-ignored-at-startup
			name: "removed tuning variables are inert",
			env: withExtra(minEnv, map[string]string{
				"EDR_BATCH_SIZE":              "notanint",
				"EDR_UPLOAD_INTERVAL":         "soon",
				"EDR_PRUNE_AGE":               "nope",
				"EDR_NETWORK_COALESCE_WINDOW": "garbage",
				"EDR_AGENT_QUEUE_MAX_BYTES":   "xxl",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "https://edr.example.com", c.ServerURL, "kept config unaffected by inert vars")
				assert.Equal(t, "json", c.LogFormat)
			},
		},
		{
			name:    "missing server url",
			env:     map[string]string{},
			wantErr: "EDR_SERVER_URL",
		},
		{
			name: "http without EDR_ALLOW_INSECURE rejected",
			env: map[string]string{
				"EDR_SERVER_URL": "http://insecure",
			},
			wantErr: "EDR_ALLOW_INSECURE",
		},
		{
			name: "http with EDR_ALLOW_INSECURE=1 accepted",
			env: map[string]string{
				"EDR_SERVER_URL":     "http://dev",
				"EDR_ALLOW_INSECURE": "1",
			},
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.True(t, c.AllowInsecure)
			},
		},
		{
			name: "bad log level",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_LEVEL": "spam",
			}),
			wantErr: "EDR_LOG_LEVEL",
		},
		{
			name: "bad log format",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_FORMAT": "xml",
			}),
			wantErr: "EDR_LOG_FORMAT",
		},
		{
			name: "invalid server URL rejected",
			env: map[string]string{
				"EDR_SERVER_URL": "://not a url",
			},
			wantErr: "must be a valid http(s) URL",
		},
		{
			name: "unsupported scheme rejected",
			env: map[string]string{
				"EDR_SERVER_URL": "ws://host:8088",
			},
			wantErr: "must use http or https",
		},
		{
			name: "scheme case-insensitive; HTTP:// still requires EDR_ALLOW_INSECURE",
			env: map[string]string{
				"EDR_SERVER_URL": "HTTP://host:8088",
			},
			wantErr: "EDR_ALLOW_INSECURE",
		},
		{
			name: "uppercase HTTPS accepted",
			env: map[string]string{
				"EDR_SERVER_URL": "HTTPS://host:8088",
			},
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "HTTPS://host:8088", c.ServerURL)
			},
		},
		{
			name: "log level normalized to lowercase",
			env: map[string]string{
				"EDR_SERVER_URL": "https://x",
				"EDR_LOG_LEVEL":  "WARN",
			},
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "warn", c.LogLevel)
			},
		},
		{
			name: "optional overrides",
			env: withExtra(minEnv, map[string]string{
				"EDR_QUEUE_DB_PATH":   "/tmp/test.db",
				"EDR_XPC_SERVICE":     "my-xpc",
				"EDR_NET_XPC_SERVICE": "my-net-xpc",
				"EDR_HOST_ID":         "override-host",
				"EDR_LOG_LEVEL":       "debug",
				"EDR_LOG_FORMAT":      "text",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "/tmp/test.db", c.QueueDBPath)
				assert.Equal(t, "my-xpc", c.XPCService)
				assert.Equal(t, "my-net-xpc", c.NetXPCService)
				assert.Equal(t, "override-host", c.HostIDOverride)
				assert.Equal(t, "debug", c.LogLevel)
				assert.Equal(t, "text", c.LogFormat)
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

func withExtra(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}
