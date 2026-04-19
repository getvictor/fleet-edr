package enrollment

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/store"
)

const (
	testSecret = "test-enroll-secret"
	testUUID   = "93DFC6F5-763D-5075-B305-8AC145D12F96"
)

// newTestStore wraps store.OpenTestStore and exposes the raw sqlx.DB the enrollment.Store needs.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := store.OpenTestStore(t)
	return NewStore(s.DB())
}

func TestHashRoundTrip(t *testing.T) {
	tok, err := generateToken()
	require.NoError(t, err)
	require.Len(t, tok, 43)

	hash, salt, err := hashToken(tok)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	require.Len(t, salt, argonSaltLen)

	assert.True(t, verifyToken(tok, hash, salt))
	assert.False(t, verifyToken("not-the-right-token-not-the-right-token-xxx", hash, salt))
	assert.False(t, verifyToken(tok, nil, salt))
	assert.False(t, verifyToken(tok, hash, nil))
}

func TestRegister_HappyPath(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	res, err := s.Register(ctx, RegisterRequest{
		HostID:       testUUID,
		Hostname:     "qa-host",
		AgentVersion: "0.0.1-dev",
		OSVersion:    "macOS 15.3",
		SourceIP:     "127.0.0.1",
	})
	require.NoError(t, err)
	assert.Equal(t, testUUID, res.HostID)
	assert.Len(t, res.HostToken, 43)
	assert.WithinDuration(t, time.Now(), res.EnrolledAt, 2*time.Second)

	// Verify the token round-trips.
	hostID, err := s.Verify(ctx, res.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, hostID)

	// An obviously-wrong token is rejected fast (length check short-circuits argon2).
	_, err = s.Verify(ctx, "nope")
	assert.ErrorIs(t, err, ErrTokenMismatch)
}

// TestVerify_LookupByTokenID exercises the SHA-256-keyed Verify path with a non-trivial
// number of enrollments. Asymptotic complexity can't be proven in a unit test; this just
// verifies correctness for many hosts in one DB, which a regression to the old full-table
// scan would still pass. The stronger O(1) contract is enforced at code-review time by
// pointing at the `WHERE host_token_id = ?` SQL in Verify.
func TestVerify_LookupByTokenID(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Register a handful of hosts so the active-enrollments table is non-trivial.
	want := make(map[string]string, 10)
	for i := range 10 {
		uuid := fmt.Sprintf("11111111-2222-3333-4444-%012d", i)
		res, err := s.Register(ctx, RegisterRequest{
			HostID: uuid, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
		})
		require.NoError(t, err)
		want[uuid] = res.HostToken
	}

	// Every real token resolves to its own host_id.
	for uuid, tok := range want {
		got, err := s.Verify(ctx, tok)
		require.NoError(t, err)
		assert.Equal(t, uuid, got)
	}

	// An unknown token with the correct length is ErrTokenMismatch — Verify must not
	// silently tolerate mis-shaped tokens by iterating the table.
	_, err := s.Verify(ctx, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	assert.ErrorIs(t, err, ErrTokenMismatch)
}

func TestRegister_ReenrollRevokesPrevious(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	first, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h1", AgentVersion: "v1", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	second, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h1-reimaged", AgentVersion: "v1", OSVersion: "o", SourceIP: "127.0.0.2",
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.HostToken, second.HostToken)

	// The previous token no longer validates.
	_, err = s.Verify(ctx, first.HostToken)
	require.ErrorIs(t, err, ErrTokenMismatch)

	// The current one does.
	hostID, err := s.Verify(ctx, second.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, hostID)
}

func TestList_RedactsTokenColumns(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	_, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	rows, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	// Round-trip through JSON: make sure no token material leaks.
	buf, err := json.Marshal(rows)
	require.NoError(t, err)
	assert.NotContains(t, string(buf), "host_token")
	assert.NotContains(t, string(buf), "token_hash")
	assert.NotContains(t, string(buf), "token_salt")
}

func TestRevoke_IdempotentAndAfterwardsRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	reg, err := s.Register(ctx, RegisterRequest{
		HostID: testUUID, Hostname: "h", AgentVersion: "v", OSVersion: "o", SourceIP: "127.0.0.1",
	})
	require.NoError(t, err)

	require.NoError(t, s.Revoke(ctx, testUUID, "compromised", "jane@customer.com"))

	// Token no longer verifies after revoke.
	_, err = s.Verify(ctx, reg.HostToken)
	require.ErrorIs(t, err, ErrTokenMismatch)

	// Second revoke is idempotent and preserves the first actor/reason.
	before, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, testUUID, "different-reason", "someoneElse"))
	after, err := s.Get(ctx, testUUID)
	require.NoError(t, err)
	assert.Equal(t, before.RevokeReason, after.RevokeReason)
	assert.Equal(t, before.RevokedBy, after.RevokedBy)
	assert.Equal(t, before.RevokedAt.Unix(), after.RevokedAt.Unix())

	// Revoke for unknown host → sql.ErrNoRows.
	err = s.Revoke(ctx, "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", "x", "y")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

// -------- handler tests --------

func newHandlerServer(t *testing.T) (*httptest.Server, *Store, *Handler) {
	t.Helper()
	s := newTestStore(t)
	h := NewHandler(s, Options{
		EnrollSecret:  testSecret,
		RatePerMinute: 30,
		Logger:        slog.Default(),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s, h
}

func postEnroll(t *testing.T, srv *httptest.Server, body any) *http.Response {
	t.Helper()
	buf := new(bytes.Buffer)
	require.NoError(t, json.NewEncoder(buf).Encode(body))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/enroll", buf)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestEnroll_HappyPath(t *testing.T) {
	srv, s, _ := newHandlerServer(t)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": testSecret,
		"hardware_uuid": testUUID,
		"hostname":      "qa-host",
		"os_version":    "macOS 15.3",
		"agent_version": "0.0.1-dev",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body enrollResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, testUUID, body.HostID)
	assert.Len(t, body.HostToken, 43)

	// Token verifies against the store.
	hostID, err := s.Verify(t.Context(), body.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testUUID, hostID)
}

func TestEnroll_SecretMismatch(t *testing.T) {
	srv, _, _ := newHandlerServer(t)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": "nope",
		"hardware_uuid": testUUID,
		"hostname":      "qa",
		"os_version":    "x",
		"agent_version": "y",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	var body enrollErrorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "secret_mismatch", body.Error)
}

func TestEnroll_BadBody(t *testing.T) {
	srv, _, _ := newHandlerServer(t)

	t.Run("malformed json", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/enroll",
			strings.NewReader("not json"))
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing fields", func(t *testing.T) {
		resp := postEnroll(t, srv, map[string]string{
			"enroll_secret": testSecret,
		})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		var body enrollErrorBody
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "bad_body", body.Error)
	})
}

func TestEnroll_InvalidUUID(t *testing.T) {
	srv, _, _ := newHandlerServer(t)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": testSecret,
		"hardware_uuid": "not-a-uuid",
		"hostname":      "qa",
		"os_version":    "x",
		"agent_version": "y",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body enrollErrorBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "hardware_uuid_invalid", body.Error)
}

func TestEnroll_RateLimit(t *testing.T) {
	s := newTestStore(t)
	h := NewHandler(s, Options{
		EnrollSecret:  testSecret,
		RatePerMinute: 3, // low cap for test speed
		Logger:        slog.Default(),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Five sequential attempts from the same source IP. First 3 may succeed auth-wise or 401
	// on secret-mismatch, depending on payload; regardless of auth outcome, attempts 4 and 5
	// must be rate-limited.
	var got429 bool
	for range 5 {
		resp := postEnroll(t, srv, map[string]string{
			"enroll_secret": "nope",
			"hardware_uuid": testUUID,
			"hostname":      "qa",
			"os_version":    "x",
			"agent_version": "y",
		})
		code := resp.StatusCode
		retryAfter := resp.Header.Get("Retry-After")
		resp.Body.Close()
		if code == http.StatusTooManyRequests {
			got429 = true
			assert.NotEmpty(t, retryAfter)
		}
	}
	assert.True(t, got429, "expected at least one 429 when exceeding rate limit")
}

func TestEnroll_SecretNeverLogged(t *testing.T) {
	// Capture the handler's slog output into a buffer and fail if the shared secret appears
	// anywhere in it — at any verbosity level.
	buf := new(bytes.Buffer)
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := newTestStore(t)
	h := NewHandler(s, Options{
		EnrollSecret: testSecret,
		Logger:       logger,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, payload := range []map[string]string{
		// success
		{"enroll_secret": testSecret, "hardware_uuid": testUUID, "hostname": "h", "os_version": "o", "agent_version": "v"},
		// fail
		{"enroll_secret": testSecret + "-wrong", "hardware_uuid": testUUID, "hostname": "h", "os_version": "o", "agent_version": "v"},
	} {
		resp := postEnroll(t, srv, payload)
		resp.Body.Close()
	}

	assert.NotContains(t, buf.String(), testSecret,
		"enroll secret must never appear in log output")
	// The obviously-bad variant must also not leak.
	assert.NotContains(t, buf.String(), testSecret+"-wrong",
		"presented secret must not leak even on failure")
}

// TestHandler_EnrollQueuesInitialPolicy is the Phase 2 regression bar: a successful
// enrollment must leave exactly one pending `set_blocklist` command for the new host,
// with a payload that mirrors the current default policy. Without this, a fresh host
// starts with no blocklist until the next admin edit.
func TestHandler_EnrollQueuesInitialPolicy(t *testing.T) {
	s := store.OpenTestStore(t)
	es := NewStore(s.DB())
	ps := policy.New(s.DB())

	// Advance the policy to a non-default version + non-empty blocklist so the test is
	// actually exercising payload population.
	_, err := ps.Update(t.Context(), policy.UpdateRequest{
		Name:  policy.DefaultName,
		Paths: []string{"/tmp/initial-block"},
		Actor: "seed",
	})
	require.NoError(t, err)

	h := NewHandler(es, Options{
		EnrollSecret:  testSecret,
		RatePerMinute: 30,
		Logger:        slog.Default(),
		PolicyStore:   ps,
		CommandStore:  s,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": testSecret,
		"hardware_uuid": testUUID,
		"hostname":      "qa-host",
		"os_version":    "macOS 15.3",
		"agent_version": "0.0.1-dev",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Exactly one pending set_blocklist command with the seeded policy.
	cmds, err := s.ListCommands(t.Context(), testUUID, "pending")
	require.NoError(t, err)
	var got []store.Command
	for _, c := range cmds {
		if c.CommandType == "set_blocklist" {
			got = append(got, c)
		}
	}
	require.Len(t, got, 1)

	var payload struct {
		Name    string   `json:"name"`
		Version int64    `json:"version"`
		Paths   []string `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(got[0].Payload, &payload))
	assert.Equal(t, "default", payload.Name)
	assert.Equal(t, int64(2), payload.Version)
	assert.Equal(t, []string{"/tmp/initial-block"}, payload.Paths)
}

func TestEnrollRequest_StringRedactsSecret(t *testing.T) {
	req := enrollRequest{
		EnrollSecret: "this-must-not-appear",
		HardwareUUID: testUUID,
	}
	s := req.String()
	assert.NotContains(t, s, "this-must-not-appear")
	assert.Contains(t, s, "REDACTED")
}
