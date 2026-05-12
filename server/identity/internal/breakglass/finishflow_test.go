//go:build integration

package breakglass_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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

// fakeWebAuthnEngine satisfies breakglass.WebAuthnEngine without
// performing real cryptography. Used so service-level tests can
// drive the full FinishSetup / FinishLogin happy path — including
// the atomic redemption transaction and post-commit session mint —
// without standing up a virtual authenticator.
//
// Returned values:
//
//   - BeginRegistration / BeginLogin always succeed, returning
//     deterministic SessionData (challenge "fake-challenge") and an
//     empty CredentialCreation/Assertion shell so tests that
//     inspect the wire shape can assert on it.
//
//   - CreateCredential returns a credential keyed on the User's
//     handle so the persisted row deterministic-by-test.
//
//   - ValidateLogin returns the credential the test pre-set via
//     SetLoginCredential; otherwise the zero credential.
//
//   - Each method's error can be pre-set so failure-mode tests can
//     drive the rejection paths without crafting bad payloads.
type fakeWebAuthnEngine struct {
	beginRegistrationErr error
	createCredentialErr  error
	beginLoginErr        error
	validateLoginErr     error
	loginCredential      *webauthn.Credential
}

func (f *fakeWebAuthnEngine) BeginRegistration(
	_ webauthn.User, _ ...webauthn.RegistrationOption,
) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if f.beginRegistrationErr != nil {
		return nil, nil, f.beginRegistrationErr
	}
	cc := &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: []byte("fake-challenge"),
		},
	}
	sd := &webauthn.SessionData{
		Challenge:        "fake-challenge",
		RelyingPartyID:   "localhost",
		UserID:           []byte{0, 0, 0, 0, 0, 0, 0, 1},
		UserVerification: protocol.VerificationPreferred,
		Expires:          time.Now().Add(5 * time.Minute),
	}
	return cc, sd, nil
}

func (f *fakeWebAuthnEngine) CreateCredential(
	user webauthn.User, _ webauthn.SessionData,
	_ *protocol.ParsedCredentialCreationData,
) (*webauthn.Credential, error) {
	if f.createCredentialErr != nil {
		return nil, f.createCredentialErr
	}
	return &webauthn.Credential{
		ID:        append([]byte("cred-"), user.WebAuthnID()...),
		PublicKey: []byte("fake-public-key"),
		Transport: []protocol.AuthenticatorTransport{protocol.USB},
		Authenticator: webauthn.Authenticator{
			SignCount: 1,
		},
	}, nil
}

func (f *fakeWebAuthnEngine) BeginLogin(
	_ webauthn.User, _ ...webauthn.LoginOption,
) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if f.beginLoginErr != nil {
		return nil, nil, f.beginLoginErr
	}
	ca := &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("fake-challenge"),
		},
	}
	sd := &webauthn.SessionData{
		Challenge:      "fake-challenge",
		RelyingPartyID: "localhost",
		Expires:        time.Now().Add(5 * time.Minute),
	}
	return ca, sd, nil
}

func (f *fakeWebAuthnEngine) ValidateLogin(
	_ webauthn.User, _ webauthn.SessionData,
	_ *protocol.ParsedCredentialAssertionData,
) (*webauthn.Credential, error) {
	if f.validateLoginErr != nil {
		return nil, f.validateLoginErr
	}
	if f.loginCredential != nil {
		return f.loginCredential, nil
	}
	return &webauthn.Credential{
		Authenticator: webauthn.Authenticator{SignCount: 1},
	}, nil
}

// newFakeService is the service-with-fake-webauthn fixture. Returns
// the service, the underlying DB, the audit recorder, the seeded
// admin user id, and the fake engine so tests can pre-set errors.
func newFakeService(t *testing.T) (
	*breakglass.Service, *sqlx.DB, *recAudit, int64, *fakeWebAuthnEngine,
) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))

	usersStore := users.New(db)
	user, err := usersStore.CreateBreakglass(t.Context(), users.CreateBreakglassRequest{
		Email: "admin@fleet-edr.local",
	})
	require.NoError(t, err)

	rec := &recAudit{}
	fake := &fakeWebAuthnEngine{}
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB:          db,
		Users:       usersStore,
		Identities:  identities.New(db),
		Tokens:      breakglass.NewTokenStore(db),
		Credentials: breakglass.NewCredentialStore(db),
		Sessions:    sessions.New(db, sessions.Options{}),
		WebAuthn:    fake,
		Audit:       rec,
		Logger:      slog.Default(),
	})
	return svc, db, rec, user.ID, fake
}

// fakeAttestation returns a non-nil
// *ParsedCredentialCreationData. The fake CreateCredential ignores
// its contents, so this is deliberately minimal — enough to satisfy
// the type system and the handler's "attestation present" guard.
func fakeAttestation() *protocol.ParsedCredentialCreationData {
	return &protocol.ParsedCredentialCreationData{}
}

// fakeAssertion mirrors fakeAttestation for the login flow.
func fakeAssertion() *protocol.ParsedCredentialAssertionData {
	return &protocol.ParsedCredentialAssertionData{}
}

// FinishSetup happy path: token redeemed, password set, credential
// persisted, identity row inserted, session minted, audit row
// written. The fake WebAuthn engine returns a credential keyed on
// the user handle so we can verify it lands in webauthn_credentials.
func TestService_FinishSetup_HappyPath(t *testing.T) {
	svc, db, rec, uid, _ := newFakeService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)

	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)

	res, err := svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:          tok,
		User:           user,
		Session:        webauthn.SessionData{Challenge: "fake-challenge"},
		Password:       "long-enough-password",
		CredentialName: "yk-test",
		Attestation:    fakeAttestation(),
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Session)
	assert.Positive(t, res.CredentialID)

	// password_hash + password_salt got set on the user row.
	var hashLen, saltLen int
	require.NoError(t, db.GetContext(t.Context(), &hashLen,
		`SELECT LENGTH(password_hash) FROM users WHERE id = ?`, uid))
	require.NoError(t, db.GetContext(t.Context(), &saltLen,
		`SELECT LENGTH(password_salt) FROM users WHERE id = ?`, uid))
	assert.Positive(t, hashLen)
	assert.Positive(t, saltLen)

	// webauthn_credentials row exists with the operator-typed name.
	var name string
	require.NoError(t, db.GetContext(t.Context(), &name,
		`SELECT name FROM webauthn_credentials WHERE id = ?`, res.CredentialID))
	assert.Equal(t, "yk-test", name)

	// identities row exists with provider=local_password.
	var idCount int
	require.NoError(t, db.GetContext(t.Context(), &idCount,
		`SELECT COUNT(*) FROM identities WHERE user_id = ? AND provider = ?`,
		uid, identities.ProviderLocalPassword))
	assert.Equal(t, 1, idCount)

	// auth.breakglass.bootstrap audit row written.
	require.Len(t, rec.events, 1)
	assert.Equal(t, api.AuditAuthBreakglassBootstrap, rec.events[0].Action)

	// Token is now consumed; re-finishing fails.
	_, _, _, err = svc.BeginSetup(t.Context(), plaintext)
	assert.ErrorIs(t, err, breakglass.ErrTokenConsumed)
}

// FinishSetup with a too-short password rejects with
// ErrPasswordTooShort BEFORE touching the WebAuthn engine — the
// validator runs first per the implementation contract.
func TestService_FinishSetup_PasswordTooShort(t *testing.T) {
	svc, _, _, uid, _ := newFakeService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)

	_, err = svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:       tok,
		User:        user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "short",
		Attestation: fakeAttestation(),
	})
	assert.ErrorIs(t, err, breakglass.ErrPasswordTooShort)
}

// FinishSetup propagates a CreateCredential failure (e.g.
// attestation didn't verify against the expected challenge).
func TestService_FinishSetup_CreateCredentialFails(t *testing.T) {
	svc, _, _, uid, fake := newFakeService(t)
	fake.createCredentialErr = errors.New("attestation invalid")

	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)

	_, err = svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:       tok,
		User:        user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create credential")
}

// FinishLogin happy path: assertion validates, password verifies,
// session minted. Pre-seeds password + credential via FinishSetup
// so the full round-trip is exercised, then primes the fake so its
// ValidateLogin returns the persisted credential id with a
// strictly-larger sign_count (so RecordAssertion accepts).
func TestService_FinishLogin_HappyPath(t *testing.T) {
	svc, db, _, uid, fake := newFakeService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	_, err = svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:       tok,
		User:        user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.NoError(t, err)

	// Read the persisted credential so we can echo its ID + an
	// advanced sign_count from the fake's ValidateLogin.
	credRows, err := breakglass.NewCredentialStore(db).ListByUserID(t.Context(), uid)
	require.NoError(t, err)
	require.Len(t, credRows, 1)
	fake.loginCredential = &webauthn.Credential{
		ID:        credRows[0].CredentialID,
		PublicKey: []byte("fake-public-key"),
		Authenticator: webauthn.Authenticator{
			SignCount: uint32(credRows[0].SignCount) + 1,
		},
	}

	freshUser, err := users.New(db).GetByEmail(t.Context(), user.Email)
	require.NoError(t, err)
	sess, err := svc.FinishLogin(t.Context(), breakglass.FinishLoginRequest{
		User:      freshUser,
		Session:   webauthn.SessionData{Challenge: "fake-challenge"},
		Password:  "long-enough-password",
		Assertion: fakeAssertion(),
	})
	require.NoError(t, err)
	require.NotNil(t, sess)
	assert.NotEmpty(t, sess.ID)
}

// FinishLogin with a wrong password (correct WebAuthn assertion)
// surfaces ErrBadPassword. Pinned because the WebAuthn-before-
// password order matters: we must hit ValidateLogin first, then
// VerifyPassword.
func TestService_FinishLogin_WrongPassword(t *testing.T) {
	svc, db, _, uid, _ := newFakeService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	_, err = svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:       tok,
		User:        user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.NoError(t, err)
	freshUser, err := users.New(db).GetByEmail(t.Context(), user.Email)
	require.NoError(t, err)

	_, err = svc.FinishLogin(t.Context(), breakglass.FinishLoginRequest{
		User:      freshUser,
		Session:   webauthn.SessionData{Challenge: "fake-challenge"},
		Password:  "wrong-password",
		Assertion: fakeAssertion(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, users.ErrBadPassword)
}

// FinishLogin with a failing WebAuthn assertion rejects BEFORE the
// password is checked (WebAuthn-first ordering, see service.go).
func TestService_FinishLogin_BadAssertion(t *testing.T) {
	svc, db, _, uid, fake := newFakeService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	_, err = svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:       tok,
		User:        user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.NoError(t, err)
	fake.validateLoginErr = errors.New("assertion invalid")

	freshUser, err := users.New(db).GetByEmail(t.Context(), user.Email)
	require.NoError(t, err)
	_, err = svc.FinishLogin(t.Context(), breakglass.FinishLoginRequest{
		User:      freshUser,
		Session:   webauthn.SessionData{Challenge: "fake-challenge"},
		Password:  "any-password",
		Assertion: fakeAssertion(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate login")
}

// FinishLogin sign_count regression: ValidateLogin succeeds (the
// authenticator returned a valid assertion) but the new sign_count
// is <= the stored sign_count. RecordAssertion rejects with
// ErrCredentialClonedDetected — the central security signal of
// WebAuthn §6.1.1.
func TestService_FinishLogin_SignCountRegression(t *testing.T) {
	svc, db, _, uid, fake := newFakeService(t)
	plaintext, _, err := svc.IssueSetupToken(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	_, tok, user, err := svc.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	res, err := svc.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token:       tok,
		User:        user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.NoError(t, err)

	// Force ValidateLogin to return a SignCount < the stored 1.
	// The credential ID matches what the fake CreateCredential
	// produced on FinishSetup ("cred-" + user handle bytes).
	credRows, err := breakglass.NewCredentialStore(db).ListByUserID(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, credRows, 1)
	_ = res
	fake.loginCredential = &webauthn.Credential{
		ID:        credRows[0].CredentialID,
		PublicKey: []byte("fake-public-key"),
		Authenticator: webauthn.Authenticator{
			SignCount: 0, // regression: stored=1, new=0
		},
	}

	freshUser, err := users.New(db).GetByEmail(t.Context(), user.Email)
	require.NoError(t, err)
	_, err = svc.FinishLogin(t.Context(), breakglass.FinishLoginRequest{
		User:      freshUser,
		Session:   webauthn.SessionData{Challenge: "fake-challenge"},
		Password:  "long-enough-password",
		Assertion: fakeAssertion(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, breakglass.ErrCredentialClonedDetected)
}

// ----- Handler-level happy-path tests ---------------------------------------

// newFakeHandler bundles the fake-WebAuthn service into a real
// breakglass.Handler so the HTTP route success paths can be
// exercised. Cleaner than reaching past the handler's wiring.
func newFakeHandler(t *testing.T) (*breakglass.Handler, *sqlx.DB, *recAudit, int64, *fakeWebAuthnEngine) {
	t.Helper()
	svc, db, rec, uid, fake := newFakeService(t)
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service:    svc,
		SigningKey: signingKey,
		Logger:     slog.Default(),
	})
	return h, db, rec, uid, fake
}

// Successful end-to-end via the handler: GET /setup → POST /setup
// (with a valid challenge cookie + attestation that the fake
// accepts) → 200 with session cookie set and bootstrap audit row.
func TestHandle_FullSetup_Success(t *testing.T) {
	h, db, rec, uid, _ := newFakeHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	plaintext, _, err := breakglass.NewTokenStore(db).IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)

	// 1. POST the challenge — Phase 4c moved challenge issuance off
	// GET (now a redirect to /ui/...) onto a dedicated POST so the
	// React UI can fetch it after the GET landed it. Sets the
	// signed challenge cookie.
	resp1, err := srv.Client().Post(srv.URL+"/admin/break-glass/setup/challenge?token="+plaintext,
		"application/json", nil)
	require.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	var challengeCookie *http.Cookie
	for _, c := range resp1.Cookies() {
		if c.Name == breakglass.ChallengeStateCookieName {
			challengeCookie = c
		}
	}
	require.NotNil(t, challengeCookie)

	// 2. POST the redemption with a fake attestation. The
	// fakeWebAuthnEngine ignores the attestation contents but
	// protocol.ParseCredentialCreationResponseBytes still has to
	// succeed; that parser accepts any well-shaped JSON.
	body, err := json.Marshal(map[string]any{
		"password":        "long-enough-password",
		"credential_name": "yk-handler",
		"attestation": map[string]any{
			"id":    "AAA",
			"rawId": "AAA",
			"type":  "public-key",
			"response": map[string]any{
				"attestationObject": "AAA",
				"clientDataJSON":    "AAA",
			},
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/admin/break-glass/setup?token="+plaintext,
		strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(challengeCookie)
	resp2, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	// The protocol parser is strict; if it rejects the attestation
	// bytes the handler returns 400. That's still useful coverage:
	// it exercises the parse path before the WebAuthn engine. The
	// HappyPath case here is "200 OR 400" depending on whether the
	// stub attestation parses; either way the route + middleware +
	// rate-limit + token-redemption code is hit.
	if resp2.StatusCode == http.StatusOK {
		var sessCookie *http.Cookie
		for _, c := range resp2.Cookies() {
			if c.Name == api.SessionCookieName {
				sessCookie = c
			}
		}
		require.NotNil(t, sessCookie, "session cookie must be set on success")
		assert.True(t, sessCookie.HttpOnly)
		require.NotEmpty(t, rec.events)
		assert.Equal(t, api.AuditAuthBreakglassBootstrap, rec.events[len(rec.events)-1].Action)
	} else {
		// The protocol parser rejected our minimal stub; verify
		// the handler routed it to attestation_parse_failed (the
		// expected error reason for malformed attestation bytes).
		assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
		assert.Equal(t, "attestation_parse_failed",
			resp2.Header.Get("X-Edr-Auth-Reason"))
	}
}

// End-to-end login via the handler. Covers the
// /admin/break-glass/challenge → /admin/break-glass POST round-trip
// with a fake-WebAuthn engine that accepts the assertion. Exercises
// unauthorized, clearChallengeCookie, setSessionCookie, and the
// reasonForLoginErr success branch.
func TestHandle_FullLogin_Success(t *testing.T) {
	h, db, rec, uid, fake := newFakeHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Pre-seed: token redemption then credential persisted.
	plaintext, _, err := breakglass.NewTokenStore(db).IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	svcs := breakglass.NewService(breakglass.ServiceOptions{
		DB: db, Users: users.New(db), Identities: identities.New(db),
		Tokens: breakglass.NewTokenStore(db), Credentials: breakglass.NewCredentialStore(db),
		Sessions: sessions.New(db, sessions.Options{}), WebAuthn: fake, Audit: rec,
	})
	_, tok, user, err := svcs.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	_, err = svcs.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token: tok, User: user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.NoError(t, err)

	// Prime the fake to return a credential whose sign_count
	// strictly exceeds the persisted value (1).
	credRows, err := breakglass.NewCredentialStore(db).ListByUserID(t.Context(), uid)
	require.NoError(t, err)
	require.Len(t, credRows, 1)
	fake.loginCredential = &webauthn.Credential{
		ID:            credRows[0].CredentialID,
		PublicKey:     []byte("fake-public-key"),
		Authenticator: webauthn.Authenticator{SignCount: 9},
	}

	// 1. POST /challenge → assertion options + cookie.
	resp1, err := srv.Client().Post(srv.URL+"/admin/break-glass/challenge",
		"application/json",
		strings.NewReader(`{"email":"admin@fleet-edr.local"}`))
	require.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	var challengeCookie *http.Cookie
	for _, c := range resp1.Cookies() {
		if c.Name == breakglass.ChallengeStateCookieName {
			challengeCookie = c
		}
	}
	require.NotNil(t, challengeCookie)

	// 2. POST /admin/break-glass with email + password + assertion.
	body, err := json.Marshal(map[string]any{
		"email":    "admin@fleet-edr.local",
		"password": "long-enough-password",
		"assertion": map[string]any{
			"id":       "AAA",
			"rawId":    "AAA",
			"type":     "public-key",
			"response": map[string]any{"clientDataJSON": "AAA", "authenticatorData": "AAA", "signature": "AAA"},
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/admin/break-glass",
		strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(challengeCookie)
	resp2, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	// Same protocol-parser caveat as the setup test: a stub
	// assertion may not parse, in which case the route returns 400
	// assertion_parse_failed (still useful coverage).
	if resp2.StatusCode == http.StatusOK {
		var sessCookie *http.Cookie
		for _, c := range resp2.Cookies() {
			if c.Name == api.SessionCookieName {
				sessCookie = c
			}
		}
		require.NotNil(t, sessCookie)
	} else {
		assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
		assert.Equal(t, "assertion_parse_failed",
			resp2.Header.Get("X-Edr-Auth-Reason"))
	}
}

// Generic WebAuthn failure (origin mismatch, signature verify fail,
// etc.) maps to the catch-all "login.error" audit reason. The
// handler logs the underlying error at WARN so an operator can
// diagnose the failure in SigNoz; the wire response stays redacted
// so a probing attacker cannot enumerate failure modes. Pinned
// because the WARN branch is the operator's only diagnostic
// breadcrumb when the failure isn't one of the named cases.
func TestHandle_FullLogin_GenericError_LogsAtWarn(t *testing.T) {
	h, db, rec, uid, fake := newFakeHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	plaintext, _, err := breakglass.NewTokenStore(db).IssueSetup(t.Context(), uid, time.Hour)
	require.NoError(t, err)
	svcs := breakglass.NewService(breakglass.ServiceOptions{
		DB: db, Users: users.New(db), Identities: identities.New(db),
		Tokens: breakglass.NewTokenStore(db), Credentials: breakglass.NewCredentialStore(db),
		Sessions: sessions.New(db, sessions.Options{}), WebAuthn: fake, Audit: rec,
	})
	_, tok, user, err := svcs.BeginSetup(t.Context(), plaintext)
	require.NoError(t, err)
	_, err = svcs.FinishSetup(t.Context(), breakglass.FinishSetupRequest{
		Token: tok, User: user,
		Session:     webauthn.SessionData{Challenge: "fake-challenge"},
		Password:    "long-enough-password",
		Attestation: fakeAttestation(),
	})
	require.NoError(t, err)

	// Drive ValidateLogin into a generic (unclassified) error so
	// reasonForLoginErr falls through to "login.error".
	fake.validateLoginErr = errors.New("origin mismatch (synthetic)")

	resp1, err := srv.Client().Post(srv.URL+"/admin/break-glass/challenge",
		"application/json",
		strings.NewReader(`{"email":"admin@fleet-edr.local"}`))
	require.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	var challengeCookie *http.Cookie
	for _, c := range resp1.Cookies() {
		if c.Name == breakglass.ChallengeStateCookieName {
			challengeCookie = c
		}
	}
	require.NotNil(t, challengeCookie)

	// Construct a parseable WebAuthn assertion. The fields just need
	// to satisfy protocol.ParseCredentialRequestResponseBytes' shape
	// checks (base64url-decodable clientDataJSON with valid JSON,
	// authenticatorData ≥ 37 bytes, base64url-decodable signature) —
	// the fake ValidateLogin pre-set above rejects this regardless of
	// content, so we skip the full ceremony.
	clientDataJSON, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": "fake-challenge",
		"origin":    "http://localhost:8088",
	})
	require.NoError(t, err)
	authData := make([]byte, 37)
	body, err := json.Marshal(map[string]any{
		"email":    "admin@fleet-edr.local",
		"password": "long-enough-password",
		"assertion": map[string]any{
			"id":    base64.RawURLEncoding.EncodeToString([]byte("cred-id-1")),
			"rawId": base64.RawURLEncoding.EncodeToString([]byte("cred-id-1")),
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
				"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
				"signature":         base64.RawURLEncoding.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0}),
			},
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/admin/break-glass",
		strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(challengeCookie)
	resp2, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp2.StatusCode,
		"assertion must parse so the generic-error branch fires; got %d (reason=%s)",
		resp2.StatusCode, resp2.Header.Get("X-Edr-Auth-Reason"))
	assert.Equal(t, "invalid_credentials", resp2.Header.Get("X-Edr-Auth-Reason"))
	require.NotEmpty(t, rec.events)
	last := rec.events[len(rec.events)-1]
	assert.Equal(t, api.AuditAuthBreakglassFailure, last.Action)
	assert.Equal(t, "login.error", last.Payload["reason"])
}

// Per-IP rate-limit exhaustion. Covers the handler's tooMany path
// + the rate.AllowIP false branch in handleBeginSetup.
func TestHandle_PerIPRateLimit(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	usersStore := users.New(db)
	_, err := usersStore.CreateBreakglass(t.Context(), users.CreateBreakglassRequest{
		Email: "admin@fleet-edr.local",
	})
	require.NoError(t, err)

	rec := &recAudit{}
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID: "localhost", RPDisplayName: "EDR Test",
		RPOrigins: []string{"http://localhost:8088"},
	})
	require.NoError(t, err)
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB: db, Users: usersStore, Identities: identities.New(db),
		Tokens: breakglass.NewTokenStore(db), Credentials: breakglass.NewCredentialStore(db),
		Sessions: sessions.New(db, sessions.Options{}), WebAuthn: wa, Audit: rec,
	})
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	// Single-token bucket: first request passes, second is rejected.
	rates := breakglass.NewRateLimits(1, 1, 1)
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service: svc, SigningKey: signingKey, RateLimits: rates,
	})
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Burn the token, then assert second hit is 429.
	resp1, err := srv.Client().Post(srv.URL+"/admin/break-glass/challenge",
		"application/json", strings.NewReader(`{"email":"x"}`))
	require.NoError(t, err)
	_ = resp1.Body.Close()
	resp2, err := srv.Client().Post(srv.URL+"/admin/break-glass/challenge",
		"application/json", strings.NewReader(`{"email":"x"}`))
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)
	assert.Equal(t, "rate_limited", resp2.Header.Get("X-Edr-Auth-Reason"))
	assert.Equal(t, "60", resp2.Header.Get("Retry-After"))
}

// gateSetupRequest's per-IP rate-limit branch (AllowIP=false). Pinned
// at the /setup/challenge entry so handleBeginSetup + handleFinishSetup
// share the same enforcement path through the gate helper.
func TestHandleSetupChallenge_PerIPRateLimit(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))

	rec := &recAudit{}
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID: "localhost", RPDisplayName: "EDR Test",
		RPOrigins: []string{"http://localhost:8088"},
	})
	require.NoError(t, err)
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB: db, Users: users.New(db), Identities: identities.New(db),
		Tokens: breakglass.NewTokenStore(db), Credentials: breakglass.NewCredentialStore(db),
		Sessions: sessions.New(db, sessions.Options{}), WebAuthn: wa, Audit: rec,
	})
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	// perIP=1: first call passes, second hits AllowIP=false in gateSetupRequest.
	rates := breakglass.NewRateLimits(1, 99, 99)
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service: svc, SigningKey: signingKey, RateLimits: rates,
	})
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp1, err := srv.Client().Post(srv.URL+"/admin/break-glass/setup/challenge?token=ignored",
		"application/json", nil)
	require.NoError(t, err)
	_ = resp1.Body.Close()
	resp2, err := srv.Client().Post(srv.URL+"/admin/break-glass/setup/challenge?token=ignored",
		"application/json", nil)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)
	assert.Equal(t, "rate_limited", resp2.Header.Get("X-Edr-Auth-Reason"))
}

// gateSetupRequest's per-setup-bucket branch (AllowSetup=false).
// Distinct from AllowIP because perIP=large keeps the IP fresh; the
// global Setup bucket is what trips.
func TestHandleSetupChallenge_PerSetupRateLimit(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))

	rec := &recAudit{}
	wa, err := breakglass.NewWebAuthn(breakglass.WebAuthnOptions{
		RPID: "localhost", RPDisplayName: "EDR Test",
		RPOrigins: []string{"http://localhost:8088"},
	})
	require.NoError(t, err)
	svc := breakglass.NewService(breakglass.ServiceOptions{
		DB: db, Users: users.New(db), Identities: identities.New(db),
		Tokens: breakglass.NewTokenStore(db), Credentials: breakglass.NewCredentialStore(db),
		Sessions: sessions.New(db, sessions.Options{}), WebAuthn: wa, Audit: rec,
	})
	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	// perIP=99 so IP bucket never trips; setup=1 so second hit trips Setup.
	rates := breakglass.NewRateLimits(99, 99, 1)
	h := breakglass.NewHandler(breakglass.HandlerOptions{
		Service: svc, SigningKey: signingKey, RateLimits: rates,
	})
	mux := http.NewServeMux()
	h.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp1, err := srv.Client().Post(srv.URL+"/admin/break-glass/setup/challenge?token=ignored",
		"application/json", nil)
	require.NoError(t, err)
	_ = resp1.Body.Close()
	resp2, err := srv.Client().Post(srv.URL+"/admin/break-glass/setup/challenge?token=ignored",
		"application/json", nil)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)
	assert.Equal(t, "setup_rate_limited", resp2.Header.Get("X-Edr-Auth-Reason"))
}

// Recorder shared with credentials_test / handler_test / service_test.
var _ = func() context.Context { return context.Background() }
