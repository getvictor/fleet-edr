package authn

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/store"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

// enrolledHost constructs a store with a single enrolled host and returns its token.
func enrolledHost(t *testing.T) (*enrollment.Store, string) {
	t.Helper()
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	res, err := es.Register(t.Context(), enrollment.RegisterRequest{
		HostID: testUUID, Hostname: "qa", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)
	return es, res.HostToken
}

func downstream(t *testing.T, wantHostID string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := HostIDFromContext(r.Context())
		if !ok {
			t.Errorf("downstream: host_id not pinned on context")
		}
		if wantHostID != "" {
			assert.Equal(t, wantHostID, hostID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestHostToken_ValidToken(t *testing.T) {
	es, tok := enrolledHost(t)
	mw := HostToken(es, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, testUUID)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestHostToken_MissingBearer(t *testing.T) {
	es, _ := enrolledHost(t)
	mw := HostToken(es, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)

	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "missing_bearer", parsed["error"])
}

func TestHostToken_EmptyBearerSuffixRejected(t *testing.T) {
	es, _ := enrolledHost(t)
	mw := HostToken(es, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHostToken_WrongToken(t *testing.T) {
	es, _ := enrolledHost(t)
	mw := HostToken(es, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Must be the right length so we hit the hash-compare path, not the cheap length filter.
	badToken := "abcdefghijklmnopqrstuvwxyz0123456789012345_"
	require.Len(t, badToken, 43)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+badToken)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "invalid_token", parsed["error"])
}

func TestHostToken_RevokedToken(t *testing.T) {
	es, tok := enrolledHost(t)
	require.NoError(t, es.Revoke(t.Context(), testUUID, "qa-revoke", "tester"))

	mw := HostToken(es, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// The Phase 1 AdminToken tests used to live here; Phase 3 replaces AdminToken with
// Session + CSRF. Session middleware coverage lives in session_test.go (full happy
// path + CSRF + expiry). The smoke tests below are kept to lock in the basics so the
// shared fail/failStatus path keeps working as we refactor.

func TestHostIDFromContext_Nil(t *testing.T) {
	_, ok := HostIDFromContext(t.Context())
	assert.False(t, ok)
}
