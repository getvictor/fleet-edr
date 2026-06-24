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
	t.Parallel()
	t.Run("defaults with dsn from env", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
		env := map[string]string{"EDR_DSN": "d", "EDR_DEMO_SERVER_URL": "https://localhost:8088/"}
		c, err := resolveConfig(func(k string) string { return env[k] }, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8088", c.serverURL)
	})

	t.Run("missing dsn is an error", func(t *testing.T) {
		t.Parallel()
		_, err := resolveConfig(func(string) string { return "" }, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DSN is required")
	})
}

func TestEnvHelpers(t *testing.T) {
	t.Parallel()
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

// TestWovenAttacksLoadAndValidate confirms every attack woven into the host manifest parses + validates, that each kindAttack
// names the rule it trips, that there is exactly one app-control attack (carrying an exec for the block to target), and that all
// the demo's headline detections are represented across the hosts.
func TestWovenAttacksLoadAndValidate(t *testing.T) {
	t.Parallel()
	rules := map[string]bool{}
	appControls, total := 0, 0
	for _, h := range hostManifest {
		for _, atk := range h.Attacks {
			sc, err := loadAttackScenario(atk.File)
			require.NoErrorf(t, err, "attack %s loads + validates", atk.File)
			total++
			switch atk.Kind {
			case kindAttack:
				assert.NotEmptyf(t, atk.ExpectRule, "%s names the rule it trips", atk.File)
				rules[atk.ExpectRule] = true
			case kindAppControl:
				appControls++
				_, _, ok := firstExec(sc)
				assert.Truef(t, ok, "app-control scenario %s has an exec the block targets", atk.File)
			}
		}
	}
	assert.Positive(t, total, "at least one attack is woven")
	assert.Equal(t, 1, appControls, "exactly one app-control attack across the hosts")
	for _, want := range []string{"credential_keychain_dump", "dns_c2_beacon", "sudoers_tamper", "persistence_launchagent"} {
		assert.Truef(t, rules[want], "detection %s is woven into a host", want)
	}
}

// TestReplayHostErrors covers replayHost's two HTTP failure branches (enroll and the events POST) against a real captured host
// from the manifest, with no DB: an error at either step must abort the replay.
func TestReplayHostErrors(t *testing.T) {
	t.Parallel()
	t.Run("enroll failure aborts replay", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden) // enroll -> 403
		}))
		defer ts.Close()
		err := httpSeeder(ts.URL).replayHost(context.Background(), hostManifest[0])
		require.Error(t, err)
	})

	t.Run("events POST failure aborts replay", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/enroll" {
				_ = json.NewEncoder(w).Encode(map[string]any{"host_id": "H", "host_token": "tok"})
				return
			}
			w.WriteHeader(http.StatusInternalServerError) // /api/events -> 500
		}))
		defer ts.Close()
		err := httpSeeder(ts.URL).replayHost(context.Background(), hostManifest[0])
		require.Error(t, err)
	})
}

func TestFirstExec(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	t.Run("returns the issued token and echoes host id", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()
		_, err := httpSeeder(ts.URL).enroll(context.Background(), "HOST-9", "h")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 403")
	})

	t.Run("missing token is an error", func(t *testing.T) {
		t.Parallel()
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
	t.Parallel()
	t.Run("2xx succeeds and sends bearer token", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
	t.Parallel()
	t.Run("becomes ready after initial 503s", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
