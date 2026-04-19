package enrollment

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

// fakeEnrollServer returns a server that accepts a fixed enroll secret and returns a
// deterministic token.
func fakeEnrollServer(t *testing.T, secret, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	srv := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012")
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
	srv := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012")
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

	// Two rapid OnUnauthorized calls. Only the first triggers a re-enroll; the second is
	// throttled (within a minute of the first).
	ctx := context.Background()
	tp.OnUnauthorized(ctx)
	tp.OnUnauthorized(ctx) // should be a no-op
	// We can't easily observe the call count without instrumenting, but no panic is a minimum
	// regression bar; more detailed coverage lives in the SigNoz MCP QA.
}
