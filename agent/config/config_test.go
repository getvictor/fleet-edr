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
	return func(k string) string { return pairs[k] }
}

func TestLoad(t *testing.T) {
	minEnv := map[string]string{
		"EDR_SERVER_URL":   "https://edr.example.com",
		"EDR_BEARER_TOKEN": "s3cret",
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
				assert.Equal(t, "s3cret", c.BearerToken)
				assert.Equal(t, 100, c.BatchSize)
				assert.Equal(t, time.Second, c.UploadInterval)
				assert.Equal(t, "/var/db/fleet-edr/events.db", c.QueueDBPath)
				assert.Equal(t, "json", c.LogFormat)
			},
		},
		{
			name:    "missing server url",
			env:     map[string]string{"EDR_BEARER_TOKEN": "s"},
			wantErr: "EDR_SERVER_URL",
		},
		{
			name:    "missing bearer token",
			env:     map[string]string{"EDR_SERVER_URL": "https://x"},
			wantErr: "EDR_BEARER_TOKEN",
		},
		{
			name: "http without EDR_ALLOW_INSECURE rejected",
			env: map[string]string{
				"EDR_SERVER_URL":   "http://insecure",
				"EDR_BEARER_TOKEN": "s",
			},
			wantErr: "EDR_ALLOW_INSECURE",
		},
		{
			name: "http with EDR_ALLOW_INSECURE=1 accepted",
			env: map[string]string{
				"EDR_SERVER_URL":     "http://dev",
				"EDR_BEARER_TOKEN":   "s",
				"EDR_ALLOW_INSECURE": "1",
			},
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.True(t, c.AllowInsecure)
			},
		},
		{
			name: "bad batch size",
			env: withExtra(minEnv, map[string]string{
				"EDR_BATCH_SIZE": "zero",
			}),
			wantErr: "EDR_BATCH_SIZE",
		},
		{
			name: "zero batch size rejected",
			env: withExtra(minEnv, map[string]string{
				"EDR_BATCH_SIZE": "0",
			}),
			wantErr: "must be positive",
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
			name: "bad upload interval",
			env: withExtra(minEnv, map[string]string{
				"EDR_UPLOAD_INTERVAL": "not-a-dur",
			}),
			wantErr: "EDR_UPLOAD_INTERVAL",
		},
		{
			name: "optional overrides",
			env: withExtra(minEnv, map[string]string{
				"EDR_QUEUE_DB_PATH":   "/tmp/test.db",
				"EDR_XPC_SERVICE":     "my-xpc",
				"EDR_NET_XPC_SERVICE": "my-net-xpc",
				"EDR_BATCH_SIZE":      "250",
				"EDR_UPLOAD_INTERVAL": "2s",
				"EDR_PRUNE_AGE":       "48h",
				"EDR_HOST_ID":         "override-host",
				"EDR_LOG_LEVEL":       "debug",
				"EDR_LOG_FORMAT":      "text",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "/tmp/test.db", c.QueueDBPath)
				assert.Equal(t, "my-xpc", c.XPCService)
				assert.Equal(t, "my-net-xpc", c.NetXPCService)
				assert.Equal(t, 250, c.BatchSize)
				assert.Equal(t, 2*time.Second, c.UploadInterval)
				assert.Equal(t, 48*time.Hour, c.PruneAge)
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
