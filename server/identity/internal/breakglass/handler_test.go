//go:build integration

package breakglass_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/breakglass"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// recAudit is the smoke-level audit recorder shared with tokens_test.
type recAudit struct{ events []api.AuditEvent }

func (r *recAudit) Record(_ context.Context, e api.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

// newHandler bundles the wired-up dependencies a handler test
// needs. The deep WebAuthn ceremony tests (registering + asserting
// against a virtual authenticator) require go-webauthn's test
// authenticator helper and live in the cross-context integration
// suite under test/integration; this file covers the no-WebAuthn
// failure paths (rate-limit, token-missing, challenge-missing,
// allowlist-404) where no signed assertion is needed.
func newHandler(t *testing.T) (*breakglass.Handler, *sqlx.DB, *recAudit) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))

	rec := &recAudit{}
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID:          "localhost",
		RPDisplayName: "EDR Test",
		RPOrigins:     []string{"http://localhost:8088"},
	})
	require.NoError(t, err)

	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB:          db,
		Users:       users.New(db),
		Identities:  identities.New(db),
		Tokens:      breakglass.NewTokenStore(db),
		Credentials: breakglass.NewCredentialStore(db),
		Sessions:    sessions.New(db, sessions.Options{}),
		WebAuthn:    wa,
		Audit:       rec,
		Logger:      slog.Default(),
	})

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service:    svc,
		SigningKey: signingKey,
		Logger:     slog.Default(),
	})
	return h, db, rec
}

// GET /admin/break-glass/setup with no token returns 410. Pinned
// because a regression that fell through to a free-form challenge
// would let an attacker farm setup challenges.
func TestHandleSetupGet_TokenMissing(t *testing.T) {
	h, _, _ := newHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/admin/break-glass/setup")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Equal(t, "token_missing", resp.Header.Get("X-Edr-Auth-Reason"))
}

// GET /admin/break-glass/setup with an invalid token returns 410
// with reason bootstrap.invalid in the audit row.
func TestHandleSetupGet_TokenInvalid(t *testing.T) {
	h, _, rec := newHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/admin/break-glass/setup?token=not-a-real-token")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Equal(t, "bootstrap.invalid", resp.Header.Get("X-Edr-Auth-Reason"))

	require.Len(t, rec.events, 1)
	assert.Equal(t, api.AuditAuthBreakglassFailure, rec.events[0].Action)
	assert.Equal(t, "bootstrap.invalid", rec.events[0].Payload["reason"])
}

// GET /admin/break-glass/setup with a VALID, freshly issued token
// returns 200 + a CredentialCreationOptions JSON body + the signed
// challenge cookie. Pinned to confirm the BeginSetup path round-trips.
func TestHandleSetupGet_ValidTokenIssuesChallenge(t *testing.T) {
	h, db, _ := newHandler(t)
	ctx := t.Context()

	// Seed admin row + token via the service helpers.
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (email, is_breakglass) VALUES (?, 1)`,
		"admin@fleet-edr.local")
	require.NoError(t, err)
	uid, err := res.LastInsertId()
	require.NoError(t, err)
	tokens := breakglass.NewTokenStore(db)
	plaintext, _, err := tokens.IssueSetup(ctx, uid, 0)
	require.NoError(t, err)

	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/admin/break-glass/setup?token=" + plaintext)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	pubKey, ok := body["publicKey"].(map[string]any)
	require.True(t, ok, "response must include publicKey object")
	assert.NotEmpty(t, pubKey["challenge"], "challenge field must be populated")

	// Challenge cookie present + on the right path.
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == breakglass.ChallengeStateCookieName {
			found = true
			assert.Equal(t, "/admin/break-glass/", c.Path)
			assert.True(t, c.HttpOnly)
		}
	}
	assert.True(t, found, "challenge cookie must be set")
}

// POST /admin/break-glass with no challenge cookie returns 400
// challenge_missing. The signed challenge cookie is the assertion's
// integrity gate; a missing cookie cannot be verified.
func TestHandleLogin_ChallengeMissing(t *testing.T) {
	h, _, _ := newHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := bytes.NewBufferString(`{"email":"x@y","password":"long-enough-password","assertion":{}}`)
	resp, err := srv.Client().Post(srv.URL+"/admin/break-glass", "application/json", body)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "challenge_missing", resp.Header.Get("X-Edr-Auth-Reason"))
}

// POST /admin/break-glass with a malformed challenge cookie returns
// 400 challenge_invalid (HMAC mismatch). The body never reaches the
// service.
func TestHandleLogin_ChallengeTampered(t *testing.T) {
	h, _, _ := newHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/admin/break-glass",
		bytes.NewBufferString(`{"email":"x@y","password":"long-enough-password","assertion":{}}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name: breakglass.ChallengeStateCookieName, Value: "garbage",
	})
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "challenge_invalid", resp.Header.Get("X-Edr-Auth-Reason"))
}

// POST /admin/break-glass/challenge with an unknown email returns
// 400 no_credentials. Same wire response as a known email with zero
// credentials, so an attacker cannot enumerate valid emails.
func TestHandleBeginLogin_UnknownEmail(t *testing.T) {
	h, _, _ := newHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := bytes.NewBufferString(`{"email":"unknown@example.com"}`)
	resp, err := srv.Client().Post(srv.URL+"/admin/break-glass/challenge", "application/json", body)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "no_credentials", resp.Header.Get("X-Edr-Auth-Reason"))
}

// IP allowlist 404 for off-list callers. Pinned because the spec
// requires the surface's existence to NOT be acknowledged.
func TestHandle_OffAllowlist404(t *testing.T) {
	rec := &recAudit{}
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID:          "localhost",
		RPDisplayName: "EDR Test",
		RPOrigins:     []string{"http://localhost:8088"},
	})
	require.NoError(t, err)
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB:          db,
		Users:       users.New(db),
		Identities:  identities.New(db),
		Tokens:      breakglass.NewTokenStore(db),
		Credentials: breakglass.NewCredentialStore(db),
		Sessions:    sessions.New(db, sessions.Options{}),
		WebAuthn:    wa,
		Audit:       rec,
	})
	allowlist, err := breakglass.NewAllowlist([]string{"203.0.113.0/24"})
	require.NoError(t, err)
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service:    svc,
		SigningKey: signingKey,
		Allowlist:  allowlist,
	})
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/admin/break-glass/setup?token=anything")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	// Off-list -> 404 (Go's stdlib body), no audit row.
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Truef(t, strings.Contains(string(body), "404") || strings.Contains(string(body), "not found"),
		"off-allowlist body must look like a generic 404; got %q", string(body))
}
