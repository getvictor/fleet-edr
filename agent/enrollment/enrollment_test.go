package enrollment

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

// fakeEnrollServer returns a server that accepts a fixed enroll secret and returns a
// deterministic token. If hits is non-nil, every request increments it — tests can use the
// counter to assert throttling + retry behaviour without fragile time-based sleeps.
func fakeEnrollServer(t *testing.T, secret, wantToken string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if r.URL.Path != "/api/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if body["enroll_secret"] != secret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "secret_mismatch"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host_id":     body["hardware_uuid"],
			"host_token":  wantToken,
			"enrolled_at": "2026-04-18T20:00:00Z",
		})
	}))
}

func TestEnsure_FirstBootEnrolls(t *testing.T) {
	srv := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", nil)
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	tp, err := Ensure(t.Context(), Options{
		ServerURL:      srv.URL,
		EnrollSecret:   "secret",
		TokenFile:      tokenFile,
		HostIDOverride: testUUID,
		AgentVersion:   "0.0.1-test",
		AllowInsecure:  true, // httptest uses plain http
		Logger:         slog.Default(),
	})
	require.NoError(t, err)
	assert.Equal(t, testUUID, tp.HostID())
	assert.NotEmpty(t, tp.Token())

	// Token file must be 0600.
	st, err := os.Stat(tokenFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	// File contents round-trip: a second Ensure with no EDR_ENROLL_SECRET must succeed via load.
	tp2, err := Ensure(t.Context(), Options{
		ServerURL: srv.URL,
		TokenFile: tokenFile,
		Logger:    slog.Default(),
	})
	require.NoError(t, err)
	assert.Equal(t, tp.HostID(), tp2.HostID())
	assert.Equal(t, tp.Token(), tp2.Token())
}

func TestEnsure_RefusesWorldReadableTokenFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	require.NoError(t, os.WriteFile(tokenFile, []byte(`<plist></plist>`), 0o644))

	_, err := Ensure(t.Context(), Options{
		ServerURL: "http://unused",
		TokenFile: tokenFile,
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure permissions")
}

func TestEnsure_FailsWithoutSecretAndNoFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	_, err := Ensure(t.Context(), Options{
		ServerURL: "http://unused",
		TokenFile: tokenFile,
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EDR_ENROLL_SECRET is not set")
}

func TestOnUnauthorized_Throttles(t *testing.T) {
	var hits atomic.Int64
	srv := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", &hits)
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	tp, err := Ensure(t.Context(), Options{
		ServerURL:      srv.URL,
		EnrollSecret:   "secret",
		TokenFile:      tokenFile,
		HostIDOverride: testUUID,
		AgentVersion:   "v",
		AllowInsecure:  true,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), hits.Load(), "first-boot enroll should hit the server once")

	// Two rapid OnUnauthorized calls. Only the first triggers a re-enroll; the second is
	// throttled to the 1-per-minute limit. The counter makes this observable — without it, a
	// broken throttle would still pass the "no panic" bar.
	ctx := context.Background()
	tp.OnUnauthorized(ctx)
	tp.OnUnauthorized(ctx)
	assert.Equal(t, int64(2), hits.Load(), "first-boot + one re-enroll only; second OnUnauthorized must be throttled")
}

// TestOnUnauthorized_EmptySecretRefuses covers the Phase-1 recovery edge case: an agent that
// restarted from a persisted token without EDR_ENROLL_SECRET cannot fix itself by re-enrolling.
// OnUnauthorized must refuse up front rather than burn through retry attempts.
func TestOnUnauthorized_EmptySecretRefuses(t *testing.T) {
	var hits atomic.Int64
	srv := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", &hits)
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	// First-boot with the secret to populate the token file.
	_, err := Ensure(t.Context(), Options{
		ServerURL:      srv.URL,
		EnrollSecret:   "secret",
		TokenFile:      tokenFile,
		HostIDOverride: testUUID,
		AgentVersion:   "v",
		AllowInsecure:  true,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), hits.Load())

	// Second-boot from persisted token WITHOUT the secret.
	tp2, err := Ensure(t.Context(), Options{
		ServerURL:     srv.URL,
		TokenFile:     tokenFile,
		AllowInsecure: true,
		Logger:        slog.Default(),
	})
	require.NoError(t, err)

	tp2.OnUnauthorized(context.Background())
	assert.Equal(t, int64(1), hits.Load(), "OnUnauthorized with empty secret must not hit the enroll endpoint")
}
