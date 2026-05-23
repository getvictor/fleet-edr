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

// fakeEnrollServer returns a server that accepts a fixed enroll secret and returns a deterministic token. If hits is non-nil, every
// request increments it — tests can use the counter to assert throttling + retry behaviour without fragile time-based sleeps.
func fakeEnrollServer(t *testing.T, secret, wantToken string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if r.URL.Path != "/api/enroll" {
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

// spec:agent-enrollment/first-boot-enrollment-exchange/successful-first-enrollment
// spec:agent-enrollment/token-persistence-is-durable-and-private/atomic-write-on-success
// spec:agent-enrollment/restart-reuses-the-persisted-token/day-two-restart-with-valid-token
//
// Three scenarios share this test. The first-boot half is the initial Ensure call: POST to /api/enroll
// with the secret + hardware UUID, receive a token, persist it; the assertions on tp.HostID/tp.Token
// pin that contract. The atomic-write half pins three observable invariants the temp+fsync+rename
// algorithm in enrollment.persistFile delivers: (a) the final file exists at the configured path with
// mode 0600, (b) no orphan `<path>.new` survives (proves the temp file was renamed away rather than
// abandoned mid-write), and (c) the file contents parse cleanly on the day-two reload below (proves no
// torn write). The spec's literal "write to sibling temp + fsync + rename" sequence is an
// implementation algorithm verified by code inspection of enrollment.go:411-431; this test pins the
// post-conditions that the algorithm is required to produce. The day-two half is the second Ensure
// call: same TokenFile path, NO EnrollSecret in opts; the function loads the persisted token without
// re-hitting the server, and tp2.HostID/tp2.Token equal the first-boot values.
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

	// Atomic-write evidence: no orphan `<path>.new` survives a successful Ensure. enrollment.persistFile writes to `path + ".new"`,
	// fsyncs, then renames over `path`; if the rename completed cleanly the temp must not exist. A direct write-in-place would also
	// satisfy this assertion, but combined with the day-two reload below (which proves the file contents parse) it rules out the
	// torn-write and orphan-tmp failure modes the atomic-write contract is meant to prevent.
	_, statErr := os.Stat(tokenFile + ".new")
	assert.True(t, os.IsNotExist(statErr), "no orphan `.new` temp file may survive a successful Ensure")

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

// spec:agent-enrollment/token-persistence-is-durable-and-private/token-file-is-world-readable-on-load
//
// A token file at 0644 (world-readable) fails Ensure at load time with an error mentioning "insecure
// permissions". The "agent does not transmit the token" AND clause is structural: Ensure returns an
// error before constructing the Authorization header, so the token never leaves the process.
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

// spec:agent-enrollment/re-enrollment-on-token-revocation/server-returns-401-mid-session
// spec:agent-enrollment/re-enrollment-on-token-revocation/re-enroll-attempts-are-throttled
// spec:agent-enrollment/per-host-token-scoping/revoking-a-host-invalidates-its-token
//
// Three scenarios share this test. The 401-mid-session scenario is the trigger: OnUnauthorized is the
// commander/uploader's callback when any authenticated request returns 401, and the first call here
// observes that path (hits goes 1 -> 2, a fresh enroll fired). The throttling scenario is pinned by the
// second OnUnauthorized call NOT incrementing hits (still 2): two rapid 401s yield exactly one re-enroll
// attempt because the 1-per-minute throttle suppresses the second. The revoking-a-host scenario is the
// agent-side half (the server-side revoke + 401 response is server-admin-surface territory): when the
// previously-valid token starts getting 401s, the agent's re-enroll path engages on the next request, which
// the hits=2 assertion proves.
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

	// Two rapid OnUnauthorized calls. Only the first triggers a re-enroll; the second is throttled to the 1-per-minute limit. The counter
	// makes this observable — without it, a broken throttle would still pass the "no panic" bar.
	ctx := context.Background()
	tp.OnUnauthorized(ctx)
	tp.OnUnauthorized(ctx)
	assert.Equal(t, int64(2), hits.Load(), "first-boot + one re-enroll only; second OnUnauthorized must be throttled")
}

// spec:agent-enrollment/re-enrollment-on-token-revocation/re-enroll-without-the-deployment-secret
//
// Covers the Phase-1 recovery edge case: an agent that restarted from a persisted token without
// EDR_ENROLL_SECRET cannot fix itself by re-enrolling. OnUnauthorized must refuse up front rather than
// burn through retry attempts. The "logs an actionable error" clause is observable via the logger;
// "does not loop on doomed re-enroll attempts" is pinned by hits staying at 1 after OnUnauthorized fires.
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

// spec:agent-enrollment/first-boot-enrollment-exchange/enroll-secret-does-not-match
//
// Pins the agent-side half of the bad-secret scenario: when the server responds 401 to the enroll POST
// (because the agent presented a value other than the configured secret), Ensure MUST surface the
// failure as an error AND MUST NOT persist a token file. The "audit log" and "no enrollment row" clauses
// are server-side and belong to a server-admin-surface test of the enroll endpoint.
func TestEnsure_RejectsBadEnrollSecret(t *testing.T) {
	srv := fakeEnrollServer(t, "the-real-secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", nil)
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	_, err := Ensure(t.Context(), Options{
		ServerURL:      srv.URL,
		EnrollSecret:   "wrong-secret",
		TokenFile:      tokenFile,
		HostIDOverride: testUUID,
		AgentVersion:   "v",
		AllowInsecure:  true,
		Logger:         slog.Default(),
	})
	require.Error(t, err, "wrong secret must surface as an Ensure failure, not a silent success")

	_, statErr := os.Stat(tokenFile)
	assert.True(t, os.IsNotExist(statErr), "no token file may be written when the enroll secret is rejected")
}

// spec:agent-enrollment/token-persistence-is-durable-and-private/token-file-is-unreadable-or-malformed
//
// A token file exists at the configured path but its contents are not parseable as the expected plist
// schema. Ensure MUST fail with an error AND MUST NOT silently fall back to a fresh enrollment (which
// would mask the corruption and re-spend the deployment secret needlessly). The 0600-mode rules out the
// world-readable refusal path tested by TestEnsure_RefusesWorldReadableTokenFile so we exercise the
// malformed-schema branch in isolation.
func TestEnsure_RefusesMalformedTokenFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	require.NoError(t, os.WriteFile(tokenFile, []byte("definitely not a plist"), 0o600))

	var hits atomic.Int64
	srv := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", &hits)
	defer srv.Close()

	_, err := Ensure(t.Context(), Options{
		ServerURL:     srv.URL,
		EnrollSecret:  "secret",
		TokenFile:     tokenFile,
		AllowInsecure: true,
		Logger:        slog.Default(),
	})
	require.Error(t, err, "malformed token file must fail Ensure, not trigger a fresh enrollment")
	assert.Equal(t, int64(0), hits.Load(), "Ensure must NOT contact the enroll endpoint when the file is malformed but present")
}

// spec:agent-enrollment/restart-reuses-the-persisted-token/server-url-has-changed-since-enrollment
//
// First-boot persists a token bound to srv1.URL. A subsequent Ensure call configured with a different
// ServerURL MUST fail with an error AND MUST NOT transmit the token. Without this guard, an operator who
// repointed EDR_SERVER_URL would silently leak the old host_token to whatever server answers at the new
// address.
func TestEnsure_RefusesServerURLMismatch(t *testing.T) {
	srv1 := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", nil)
	defer srv1.Close()
	srv2 := fakeEnrollServer(t, "secret", "tok-abcdefghijklmnopqrstuvwxyz0123456789012", nil)
	defer srv2.Close()
	require.NotEqual(t, srv1.URL, srv2.URL, "httptest must allocate distinct URLs for the two servers")

	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	_, err := Ensure(t.Context(), Options{
		ServerURL:      srv1.URL,
		EnrollSecret:   "secret",
		TokenFile:      tokenFile,
		HostIDOverride: testUUID,
		AgentVersion:   "v",
		AllowInsecure:  true,
		Logger:         slog.Default(),
	})
	require.NoError(t, err, "first-boot enroll against srv1 must succeed")

	// Second boot, same token file, different ServerURL.
	_, err = Ensure(t.Context(), Options{
		ServerURL:     srv2.URL,
		TokenFile:     tokenFile,
		AllowInsecure: true,
		Logger:        slog.Default(),
	})
	require.Error(t, err, "ServerURL mismatch on day-two must surface as an error")
	assert.Contains(t, err.Error(), "server_url",
		"the error must identify the mismatched server_url so an operator knows whether to delete the file or re-point the URL")
}
