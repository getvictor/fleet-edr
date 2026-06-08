package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/test/fakeagent"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testHTTPClient builds the default (system-roots) client tests use when they don't exercise CA-cert handling.
func testHTTPClient() *http.Client { c, _ := newHTTPClient(""); return c }

// httpSeeder builds a seeder pointed at a test server, with short timeouts so polling paths run fast.
func httpSeeder(serverURL string) *seeder {
	cfg := config{
		serverURL:    serverURL,
		enrollSecret: "test-secret",
		pollInterval: time.Millisecond,
		readyTimeout: time.Second,
	}
	client, _ := newHTTPClient("")
	return newSeeder(cfg, nil, client, discardLogger())
}

func TestResolveConfig(t *testing.T) {
	t.Run("defaults with dsn from env", func(t *testing.T) {
		env := map[string]string{"EDR_DSN": "root@tcp(localhost:3306)/edr"}
		c, err := resolveConfig(func(k string) string { return env[k] }, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8088", c.serverURL)
		assert.Equal(t, "demo-enroll-secret", c.enrollSecret)
		assert.Equal(t, "demo@fleet-edr.local", c.demoEmail)
		assert.Equal(t, "senior_analyst", c.demoRole)
		assert.Empty(t, c.demoOIDCSubject)
		assert.Empty(t, c.caCertPath)
		assert.False(t, c.force)
		assert.Equal(t, 90*time.Second, c.readyTimeout)
	})

	t.Run("flags override env defaults", func(t *testing.T) {
		env := map[string]string{"EDR_DSN": "from-env"}
		args := []string{
			"--server-url=https://demo.example:9000",
			"--dsn=from-flag",
			"--force",
			"--ca-cert=/etc/tls/dev.crt",
			"--demo-oidc-subject=ChdkZW1v",
			"--demo-role=admin",
			"--poll-interval=250ms",
		}
		c, err := resolveConfig(func(k string) string { return env[k] }, args)
		require.NoError(t, err)
		assert.Equal(t, "https://demo.example:9000", c.serverURL)
		assert.Equal(t, "from-flag", c.dsn)
		assert.True(t, c.force)
		assert.Equal(t, "/etc/tls/dev.crt", c.caCertPath)
		assert.Equal(t, "ChdkZW1v", c.demoOIDCSubject)
		assert.Equal(t, "admin", c.demoRole)
		assert.Equal(t, 250*time.Millisecond, c.pollInterval)
	})

	t.Run("trims trailing slash from server-url", func(t *testing.T) {
		env := map[string]string{"EDR_DSN": "d", "EDR_DEMO_SERVER_URL": "https://localhost:8088/"}
		c, err := resolveConfig(func(k string) string { return env[k] }, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8088", c.serverURL)
	})

	t.Run("missing dsn is an error", func(t *testing.T) {
		_, err := resolveConfig(func(string) string { return "" }, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DSN is required")
	})
}

func TestEnvHelpers(t *testing.T) {
	get := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	assert.Equal(t, "v", envOr(get(map[string]string{"K": "v"}), "K", "fallback"))
	assert.Equal(t, "fallback", envOr(get(nil), "K", "fallback"))

	assert.True(t, envBool(get(map[string]string{"K": "true"}), "K", false))
	assert.False(t, envBool(get(map[string]string{"K": "0"}), "K", true))
	assert.True(t, envBool(get(map[string]string{"K": "garbage"}), "K", true), "unparseable falls back")
	assert.True(t, envBool(get(nil), "K", true), "unset falls back")

	assert.Equal(t, 5*time.Second, envDuration(get(map[string]string{"K": "5s"}), "K", time.Minute))
	assert.Equal(t, time.Minute, envDuration(get(map[string]string{"K": "nope"}), "K", time.Minute))
	assert.Equal(t, time.Minute, envDuration(get(nil), "K", time.Minute))
}

func TestLoadScenarios(t *testing.T) {
	scenarios, err := loadScenarios()
	require.NoError(t, err)
	require.Len(t, scenarios, len(corpusManifest))

	byFile := map[string]demoScenario{}
	hostIDs := map[string]bool{}
	for _, sc := range scenarios {
		require.NotNil(t, sc.Scenario, "scenario %s parsed", sc.File)
		require.NotEmpty(t, sc.Scenario.Host.ID)
		assert.False(t, hostIDs[sc.Scenario.Host.ID], "host id %s is unique across the corpus", sc.Scenario.Host.ID)
		hostIDs[sc.Scenario.Host.ID] = true
		byFile[sc.File] = sc
	}

	// Attack scenarios must name the catalog rule they trip.
	for _, f := range []string{"keychain-dump.yaml", "sudoers-tamper.yaml", "launchagent-persistence.yaml"} {
		sc, ok := byFile[f]
		require.True(t, ok, "manifest includes %s", f)
		assert.Equal(t, kindAttack, sc.Kind)
		assert.NotEmpty(t, sc.ExpectRule)
	}

	// The app-control scenario must carry an exec the block event can target.
	ac, ok := byFile["app-control-blocked-app.yaml"]
	require.True(t, ok)
	assert.Equal(t, kindAppControl, ac.Kind)
	_, _, hasExec := firstExec(ac.Scenario)
	assert.True(t, hasExec, "app-control scenario has an exec event")
}

func TestFirstExec(t *testing.T) {
	withExec := &fakeagent.Scenario{Timeline: []fakeagent.Event{
		{Type: "fork", ChildPID: 10, ParentPID: 1},
		{Type: "exec", PID: 10, Path: "/bin/zsh"},
	}}
	pid, p, ok := firstExec(withExec)
	require.True(t, ok)
	assert.Equal(t, 10, pid)
	assert.Equal(t, "/bin/zsh", p)

	forkOnly := &fakeagent.Scenario{Timeline: []fakeagent.Event{{Type: "fork", ChildPID: 5, ParentPID: 1}}}
	_, _, ok = firstExec(forkOnly)
	assert.False(t, ok)
}

func TestBuildBlockEnvelope(t *testing.T) {
	env := buildBlockEnvelope("HOST-1", 6123, "/Applications/CoinMiner.app/Contents/MacOS/CoinMiner", 1700000000000000000)
	assert.Equal(t, "HOST-1", env.HostID)
	assert.Equal(t, appControlEventType, env.EventType)
	assert.Equal(t, int64(1700000000000000000), env.TimestampNs)
	assert.Len(t, env.EventID, 32)

	var p map[string]any
	require.NoError(t, json.Unmarshal(env.Payload, &p))
	assert.EqualValues(t, 6123, p["pid"])
	assert.Equal(t, "/Applications/CoinMiner.app/Contents/MacOS/CoinMiner", p["path"])
	assert.Equal(t, "/Applications/CoinMiner.app/Contents/MacOS/CoinMiner", p["identifier"])
	assert.Equal(t, appControlRuleID, p["rule_id"])
	assert.Equal(t, appControlRuleType, p["rule_type"])
	assert.Equal(t, appControlSeverity, p["severity"])
	assert.Equal(t, appControlMessage, p["custom_msg"])
	assert.EqualValues(t, 1, p["policy_id"])
	assert.EqualValues(t, 1, p["policy_version"])
}

func TestEnroll(t *testing.T) {
	t.Run("returns the issued token and echoes host id", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/enroll", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			var req map[string]string
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(t, "test-secret", req["enroll_secret"])
			_ = json.NewEncoder(w).Encode(map[string]any{"host_id": req["hardware_uuid"], "host_token": "tok-" + req["hardware_uuid"]})
		}))
		defer ts.Close()

		token, err := httpSeeder(ts.URL).enroll(context.Background(), "HOST-9", "host9.local")
		require.NoError(t, err)
		assert.Equal(t, "tok-HOST-9", token)
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()
		_, err := httpSeeder(ts.URL).enroll(context.Background(), "HOST-9", "h")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 403")
	})

	t.Run("missing token is an error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"host_id": "HOST-9", "host_token": ""})
		}))
		defer ts.Close()
		_, err := httpSeeder(ts.URL).enroll(context.Background(), "HOST-9", "h")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing host_token")
	})
}

func TestPostEnvelopes(t *testing.T) {
	t.Run("2xx succeeds and sends bearer token", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/events", r.URL.Path)
			assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
			var envs []fakeagent.Envelope
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&envs))
			assert.Len(t, envs, 1)
			_, _ = w.Write([]byte(`{"accepted":1}`))
		}))
		defer ts.Close()
		err := httpSeeder(ts.URL).postEnvelopes(context.Background(), "tok",
			[]fakeagent.Envelope{buildBlockEnvelope("H", 1, "/x", 1)})
		require.NoError(t, err)
	})

	t.Run("non-2xx is an error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		err := httpSeeder(ts.URL).postEnvelopes(context.Background(), "tok", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 500")
	})
}

func TestWaitReady(t *testing.T) {
	t.Run("becomes ready after initial 503s", func(t *testing.T) {
		var calls atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		require.NoError(t, httpSeeder(ts.URL).waitReady(context.Background()))
		assert.GreaterOrEqual(t, calls.Load(), int32(3))
	})

	t.Run("times out while never ready", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer ts.Close()
		s := httpSeeder(ts.URL)
		s.cfg.readyTimeout = 20 * time.Millisecond
		err := s.waitReady(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not met within")
	})
}
