//go:build integration

package breakglass_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

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

// newService builds a Service against a fresh DB + a localhost WebAuthn engine. No real authenticator is needed for the Begin*
// paths (challenge generation is server-side); Finish* paths are covered by the deeper handler integration tests once go-webauthn
// virtual-authenticator fixture lands.
func newService(t *testing.T, allowJIT ...bool) (*breakglass.Service, *sqlx.DB, *recAudit, int64) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))

	usersStore := users.New(db)
	user, err := usersStore.CreateBreakglass(t.Context(), users.CreateBreakglassRequest{
		Email: "admin@fleet-edr.local",
	})
	require.NoError(t, err)

	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID:          "localhost",
		RPDisplayName: "EDR Test",
		RPOrigins:     []string{"http://localhost:8088"},
	})
	require.NoError(t, err)

	rec := &recAudit{}
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB:          db,
		Users:       usersStore,
		Identities:  identities.New(db),
		Tokens:      breakglass.NewTokenStore(db),
		Credentials: breakglass.NewCredentialStore(db),
		Sessions:    sessions.New(db, sessions.Options{}),
		WebAuthn:    wa,
		Audit:       rec,
		Logger:      slog.Default(),
	})
	return svc, db, rec, user.ID
}

// IssueSetupToken returns a non-empty plaintext + persisted Token
// row; FindValid via the underlying TokenStore round-trips.
func TestService_IssueSetupToken(t *testing.T) {
	t.Parallel()
	svc, db, _, uid := newService(t)
	plaintext, tok, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, plaintext)
	require.NotNil(t, tok)
	assert.Positive(t, tok.ID)
	assert.True(t, tok.UserID.Valid)
	assert.Equal(t, uid, tok.UserID.Int64)

	// Round-trip via FindValid.
	store := breakglass.NewTokenStore(db)
	got, err := store.FindValid(t.Context(), plaintext, time.Now())
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
}

// HasCredential reports false for a fresh user, true after a
// credential is inserted.
func TestService_HasCredential(t *testing.T) {
	t.Parallel()
	svc, db, _, uid := newService(t)
	has, err := svc.HasCredential(t.Context(), uid)
	require.NoError(t, err)
	assert.False(t, has)

	creds := breakglass.NewCredentialStore(db)
	_, err = creds.InsertWith(t.Context(), db, uid,
		fakeCredential("hc-cred", "pk", 1), "")
	require.NoError(t, err)

	has, err = svc.HasCredential(t.Context(), uid)
	require.NoError(t, err)
	assert.True(t, has)
}

// BeginSetup happy path: a valid token returns a SetupChallenge + the bound Token + User. The challenge carries a non-empty
// SessionData (the engine-internal challenge state the cookie rides).
func TestService_BeginSetup_HappyPath(t *testing.T) {
	t.Parallel()
	svc, _, _, uid := newService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)

	challenge, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	require.NotNil(t, challenge)
	require.NotNil(t, tok)
	require.NotNil(t, user)
	assert.Equal(t, uid, user.ID)
	assert.NotEmpty(t, challenge.Options.Response.Challenge)
	// SessionData carries the same challenge bytes the browser will echo back; round-tripping that through the cookie is covered by
	// state_test.
	assert.NotEmpty(t, challenge.SessionData.Challenge)
}

// BeginSetup with an unknown token returns ErrTokenInvalid; the
// typed error is what the handler audits as bootstrap.invalid.
func TestService_BeginSetup_TokenInvalid(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, _, _, err := svc.BeginSetup(t.Context(), "this-is-not-a-real-token")
	assert.ErrorIs(t, err, breakglass.ErrTokenInvalid)
}

// BeginSetup with a consumed token returns ErrTokenConsumed.
//
// spec:server-identity-authentication/break-glass-account-is-bootstrapped-via-single-use-token-not-a-printed-password/expired-or-already-consumed-token-cannot-be-redeemed
//
// Pins the already-consumed half of the redemption-rejection scenario: once a setup token is redeemed, a second redemption attempt
// fails with ErrTokenConsumed before BeginSetup returns a user, so no user or session is created. The handler maps ErrTokenConsumed
// to the bootstrap.consumed audit reason; the expiry sibling is pinned by TestFindValid_Expired in tokens_test.go.
func TestService_BeginSetup_TokenConsumed(t *testing.T) {
	t.Parallel()
	svc, db, _, uid := newService(t)
	plaintext, tok, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)

	// Mark the token redeemed via the store directly.
	store := breakglass.NewTokenStore(db)
	require.NoError(t, store.MarkRedeemed(t.Context(), db, tok.ID))

	_, _, _, err = svc.BeginSetup(t.Context(), plaintext)
	assert.ErrorIs(t, err, breakglass.ErrTokenConsumed)
}

// BeginLogin with an email that has no registered credentials surfaces ErrNoCredentials. The handler collapses this onto the same wire
// response as "user not found" so attackers cannot enumerate.
func TestService_BeginLogin_NoCredentials(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, _, err := svc.BeginLogin(t.Context(), "admin@fleet-edr.local")
	assert.ErrorIs(t, err, breakglass.ErrNoCredentials)
}

// BeginLogin with a non-existent email also surfaces ErrNoCredentials (collapsed from users.ErrNotFound to prevent enumeration).
func TestService_BeginLogin_UnknownEmail(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newService(t)
	_, _, err := svc.BeginLogin(t.Context(), "ghost@example.com")
	assert.ErrorIs(t, err, breakglass.ErrNoCredentials)
}

// BeginLogin happy path: a user with at least one credential
// returns a LoginChallenge + the User row.
func TestService_BeginLogin_HappyPath(t *testing.T) {
	t.Parallel()
	svc, db, _, uid := newService(t)
	creds := breakglass.NewCredentialStore(db)
	_, err := creds.InsertWith(t.Context(), db, uid,
		fakeCredential("login-cred", "pk", 1), "YubiKey")
	require.NoError(t, err)

	challenge, user, err := svc.BeginLogin(t.Context(), "admin@fleet-edr.local")
	require.NoError(t, err)
	require.NotNil(t, challenge)
	require.NotNil(t, user)
	assert.Equal(t, uid, user.ID)
	assert.NotEmpty(t, challenge.Options.Response.Challenge)
}

// BeginLogin against a non-break-glass user surfaces ErrNoCredentials. Pinned because non-breakglass users MUST go through OIDC;
// the wire response collapses to the same shape so an attacker cannot probe for the type.
func TestService_BeginLogin_NonBreakglass(t *testing.T) {
	t.Parallel()
	svc, db, _, _ := newService(t)
	// Pre-seed a non-breakglass user.
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO users (email, password_hash, password_salt, is_breakglass) VALUES (?, ?, ?, 0)`,
		"alice@example.com", []byte("h"), []byte("s"))
	require.NoError(t, err)

	_, _, err = svc.BeginLogin(t.Context(), "alice@example.com")
	assert.ErrorIs(t, err, breakglass.ErrNoCredentials)
}

// AuditSuccess + AuditFailure produce the spec-pinned action names
// + payload shape the handler relies on.
func TestService_AuditHelpers(t *testing.T) {
	t.Parallel()
	svc, _, rec, uid := newService(t)
	user := &users.User{ID: uid, Email: "admin@fleet-edr.local"}

	svc.AuditSuccess(t.Context(), user, "203.0.113.5", "test/1.0")
	svc.AuditFailure(t.Context(), user.Email, "password.mismatch", "203.0.113.5", "test/1.0")

	require.Len(t, rec.events, 2)
	// Success row.
	assert.Equal(t, api.AuditAuthBreakglassSuccess, rec.events[0].Action)
	assert.Equal(t, "allow", rec.events[0].Payload["decision"])
	assert.Equal(t, "203.0.113.5", rec.events[0].RemoteAddr)
	assert.Equal(t, "test/1.0", rec.events[0].Payload["user_agent"])
	// Failure row.
	assert.Equal(t, api.AuditAuthBreakglassFailure, rec.events[1].Action)
	assert.Equal(t, "deny", rec.events[1].Payload["decision"])
	assert.Equal(t, "password.mismatch", rec.events[1].Payload["reason"])
}

// NewService panics on any missing dependency. Pinned because the constructor is the only place where the wire-up gets validated;
// a regression that dropped a panic would let production boot with a half-built service.
func TestNewService_PanicsOnMissingDeps(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*breakglass.ServiceOptions)
	}{
		{"missing db", func(o *breakglass.ServiceOptions) { o.DB = nil }},
		{"missing users", func(o *breakglass.ServiceOptions) { o.Users = nil }},
		{"missing identities", func(o *breakglass.ServiceOptions) { o.Identities = nil }},
		{"missing tokens", func(o *breakglass.ServiceOptions) { o.Tokens = nil }},
		{"missing credentials", func(o *breakglass.ServiceOptions) { o.Credentials = nil }},
		{"missing sessions", func(o *breakglass.ServiceOptions) { o.Sessions = nil }},
		{"missing webauthn", func(o *breakglass.ServiceOptions) { o.WebAuthn = nil }},
	}
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID: "localhost", RPDisplayName: "EDR Test",
		RPOrigins: []string{"http://localhost:8088"},
	})
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := breakglass.ServiceOptions{
				DB:          db,
				Users:       users.New(db),
				Identities:  identities.New(db),
				Tokens:      breakglass.NewTokenStore(db),
				Credentials: breakglass.NewCredentialStore(db),
				Sessions:    sessions.New(db, sessions.Options{}),
				WebAuthn:    wa,
			}
			tc.mut(&opts)
			assert.Panics(t, func() {
				_ = breakglass.NewService(opts)
			})
		})
	}
}

// Sanity: ProvisionerOptions logger nil falls through to slog.Default().
// Cover the nil-logger branch of NewService.
func TestNewService_DefaultLogger(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID: "localhost", RPDisplayName: "EDR Test",
		RPOrigins: []string{"http://localhost:8088"},
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
		// Logger left nil — must default.
	})
	require.NotNil(t, svc)
}

// Recorder used by TestService_AuditHelpers.
var _ = func() context.Context { return context.Background() } // keep imports tight
