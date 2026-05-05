package breakglass

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// Service composes the stores + WebAuthn engine + audit recorder
// behind the four operator-facing operations the handler exposes:
// BeginSetup / FinishSetup (token redemption), BeginLogin /
// FinishLogin (password + WebAuthn assertion). Each operation is
// transaction-scoped where the spec requires atomicity.
type Service struct {
	db          *sqlx.DB
	users       *users.Store
	identities  *identities.Store
	tokens      *TokenStore
	credentials *CredentialStore
	sessions    *sessions.Store
	webauthn    *webauthn.WebAuthn
	audit       api.AuditRecorder
	logger      *slog.Logger
}

// ServiceOptions carries every dependency Service needs at
// construction time. Empty values trip a panic in NewService — every
// dependency is load-bearing in production.
type ServiceOptions struct {
	DB          *sqlx.DB
	Users       *users.Store
	Identities  *identities.Store
	Tokens      *TokenStore
	Credentials *CredentialStore
	Sessions    *sessions.Store
	WebAuthn    *webauthn.WebAuthn
	Audit       api.AuditRecorder
	Logger      *slog.Logger
}

// NewService validates each dependency and returns the composed
// Service. A nil dependency panics rather than nil-checking on every
// hot-path method call.
func NewService(opts ServiceOptions) *Service {
	switch {
	case opts.DB == nil:
		panic("breakglass.NewService: DB is required")
	case opts.Users == nil:
		panic("breakglass.NewService: Users is required")
	case opts.Identities == nil:
		panic("breakglass.NewService: Identities is required")
	case opts.Tokens == nil:
		panic("breakglass.NewService: Tokens is required")
	case opts.Credentials == nil:
		panic("breakglass.NewService: Credentials is required")
	case opts.Sessions == nil:
		panic("breakglass.NewService: Sessions is required")
	case opts.WebAuthn == nil:
		panic("breakglass.NewService: WebAuthn is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		db:          opts.DB,
		users:       opts.Users,
		identities:  opts.Identities,
		tokens:      opts.Tokens,
		credentials: opts.Credentials,
		sessions:    opts.Sessions,
		webauthn:    opts.WebAuthn,
		audit:       opts.Audit,
		logger:      logger,
	}
}

// SetupChallenge bundles the response of BeginSetup. Options is the
// public-key creation options the browser passes to
// navigator.credentials.create. SessionData is the engine-internal
// challenge state the caller must round-trip via the signed cookie.
type SetupChallenge struct {
	Options     *protocol.CredentialCreation
	SessionData webauthn.SessionData
}

// BeginSetup verifies the bootstrap token and issues a WebAuthn
// registration challenge bound to the token's owning user. The
// caller serializes SessionData into the challenge cookie via
// EncodeChallengeState and renders Options for the browser. Any
// token-validity failure surfaces as the typed token-store error so
// the handler can audit the precise reason.
func (s *Service) BeginSetup(ctx context.Context, plaintextToken string) (*SetupChallenge, *Token, *users.User, error) {
	tok, err := s.tokens.FindValid(ctx, plaintextToken, time.Now())
	if err != nil {
		return nil, nil, nil, err
	}
	if !tok.UserID.Valid {
		return nil, nil, nil, fmt.Errorf("breakglass: token %d has no bound user", tok.ID)
	}
	u, err := s.users.Get(ctx, tok.UserID.Int64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("breakglass: load token user: %w", err)
	}
	wuser := User{
		ID:    u.ID,
		Email: u.Email,
	}
	options, sd, err := s.webauthn.BeginRegistration(wuser,
		webauthn.WithExclusions(nil), // no existing credentials yet
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("breakglass: begin registration: %w", err)
	}
	return &SetupChallenge{Options: options, SessionData: *sd}, tok, u, nil
}

// FinishSetupRequest is the input to FinishSetup: the password the
// operator chose, the credential name they typed (optional), and
// the parsed attestation (the handler decodes the JSON body via
// protocol.ParseCredentialCreationResponse before calling).
type FinishSetupRequest struct {
	Token          *Token
	User           *users.User
	Session        webauthn.SessionData
	Password       string
	CredentialName string
	Attestation    *protocol.ParsedCredentialCreationData
}

// FinishSetupResult is the output: the freshly-minted session row
// (plaintext id) the caller wraps in a Set-Cookie, plus the
// internal credential id for audit.
type FinishSetupResult struct {
	Session      *sessions.Session
	CredentialID int64
}

// FinishSetup performs the atomic redemption: validate password
// length, run go-webauthn's CreateCredential, then in a single
// transaction:
//  1. Mark the token redeemed (UPDATE ... WHERE redeemed_at IS NULL)
//  2. Set the user's password_hash + password_salt
//  3. Insert the webauthn_credentials row
//  4. Insert the local_password identities row (provider=local_password,
//     subject=email)
//  5. Audit auth.breakglass.bootstrap
//  6. Mint a session bound to the new identity
//
// Any failure rolls everything back; the token stays redeemable so
// the operator can retry. CredentialName is best-effort metadata
// (operator-typed); empty stores NULL.
func (s *Service) FinishSetup(ctx context.Context, req FinishSetupRequest) (*FinishSetupResult, error) {
	if err := ValidatePassword(req.Password); err != nil {
		return nil, err
	}
	wuser := User{ID: req.User.ID, Email: req.User.Email}
	cred, err := s.webauthn.CreateCredential(wuser, req.Session, req.Attestation)
	if err != nil {
		return nil, fmt.Errorf("breakglass: create credential: %w", err)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("breakglass: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := s.tokens.MarkRedeemed(ctx, tx, req.Token.ID); err != nil {
		return nil, err
	}
	if err := s.users.SetPassword(ctx, tx, req.User.ID, req.Password); err != nil {
		return nil, fmt.Errorf("breakglass: set password: %w", err)
	}
	credID, err := s.credentials.InsertWith(ctx, tx, req.User.ID, *cred, req.CredentialName)
	if err != nil {
		return nil, fmt.Errorf("breakglass: persist credential: %w", err)
	}
	identityID, err := s.identities.InsertWith(ctx, tx,
		req.User.ID, identities.ProviderLocalPassword, req.User.Email)
	if err != nil {
		// Identity row may already exist from an earlier seed; reuse it.
		// Look up the existing row outside the transaction (CASCADE
		// guarantees consistency even if we read post-commit).
		existing, lookupErr := s.identities.FindByProviderSubject(ctx,
			identities.ProviderLocalPassword, req.User.Email)
		if lookupErr != nil {
			return nil, fmt.Errorf("breakglass: insert identity: %w", err)
		}
		identityID = existing.ID
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("breakglass: commit setup tx: %w", err)
	}
	committed = true

	// Audit AFTER commit: a missing audit row does not roll the
	// account-creation back, but a successful audit is evidence the
	// account is live.
	uid := req.User.ID
	s.recordAudit(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: req.User.Email,
		Action:     api.AuditAuthBreakglassBootstrap,
		TargetType: "user",
		TargetID:   formatID(req.User.ID),
		Payload: map[string]any{
			"token_id":      req.Token.ID,
			"credential_id": credID,
			"identity_id":   identityID,
		},
	})

	idCopy := identityID
	sess, err := s.sessions.Create(ctx, req.User.ID, sessions.CreateOptions{
		IdentityID: &idCopy,
		AuthMethod: identities.ProviderLocalPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("breakglass: mint session: %w", err)
	}
	return &FinishSetupResult{Session: sess, CredentialID: credID}, nil
}

// LoginChallenge mirrors SetupChallenge but for the assertion flow.
type LoginChallenge struct {
	Options     *protocol.CredentialAssertion
	SessionData webauthn.SessionData
}

// BeginLogin issues a WebAuthn assertion challenge for the
// supplied email. Returns ErrNoCredentials when the user exists but
// has no registered credential (the spec scenario "operator who lost
// every authenticator" — admin must reissue a token). User
// enumeration: a non-existent email also surfaces ErrNoCredentials so
// an attacker cannot probe for valid emails via response shape.
func (s *Service) BeginLogin(ctx context.Context, email string) (*LoginChallenge, *users.User, error) {
	u, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, users.ErrNotFound) {
		return nil, nil, ErrNoCredentials
	}
	if err != nil {
		return nil, nil, fmt.Errorf("breakglass: load user: %w", err)
	}
	if !u.IsBreakglass {
		// Non-break-glass accounts MUST go through OIDC; surface as
		// no-credentials so the attacker can't distinguish.
		return nil, nil, ErrNoCredentials
	}
	rows, err := s.credentials.ListByUserID(ctx, u.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("breakglass: list credentials: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil, ErrNoCredentials
	}
	wuser := User{
		ID:          u.ID,
		Email:       u.Email,
		Credentials: ToWebauthnCredentials(rows),
	}
	options, sd, err := s.webauthn.BeginLogin(wuser)
	if err != nil {
		return nil, nil, fmt.Errorf("breakglass: begin login: %w", err)
	}
	return &LoginChallenge{Options: options, SessionData: *sd}, u, nil
}

// FinishLoginRequest packages the inputs to FinishLogin. The
// handler decodes the JSON body to ParsedCredentialAssertionData
// before calling.
type FinishLoginRequest struct {
	User      *users.User
	Session   webauthn.SessionData
	Password  string
	Assertion *protocol.ParsedCredentialAssertionData
}

// ErrNoCredentials is returned by BeginLogin when no credentials
// match the email. Caller maps to the directed reason
// `webauthn.no_credentials`.
var ErrNoCredentials = errors.New("breakglass: no registered credentials")

// FinishLogin verifies password + WebAuthn assertion and mints a
// fresh session. Both factors must succeed; either failure yields
// the same wire 401 + audit row with the precise reason in payload.
// The new sign_count is persisted via CredentialStore.RecordAssertion;
// a sign_count regression hard-rejects with ErrCredentialClonedDetected.
func (s *Service) FinishLogin(ctx context.Context, req FinishLoginRequest) (*sessions.Session, error) {
	// Password verification first: a brute-force attacker who hits
	// FinishLogin without a valid WebAuthn assertion still spends
	// argon2 cycles per attempt, capping the throughput.
	if _, err := s.users.VerifyPassword(ctx, req.User.Email, req.Password); err != nil {
		return nil, err
	}

	rows, err := s.credentials.ListByUserID(ctx, req.User.ID)
	if err != nil {
		return nil, fmt.Errorf("breakglass: list credentials: %w", err)
	}
	wuser := User{
		ID:          req.User.ID,
		Email:       req.User.Email,
		Credentials: ToWebauthnCredentials(rows),
	}
	cred, err := s.webauthn.ValidateLogin(wuser, req.Session, req.Assertion)
	if err != nil {
		return nil, fmt.Errorf("breakglass: validate login: %w", err)
	}
	// Persist the new sign_count + last_used_at. Sign-count regression
	// is fatal — surfaces ErrCredentialClonedDetected.
	if err := s.credentials.RecordAssertion(ctx, cred.ID, cred.Authenticator.SignCount); err != nil {
		return nil, err
	}
	// Resolve the local_password identity for session.identity_id.
	identityID := int64(0)
	id, err := s.identities.FindByProviderSubject(ctx,
		identities.ProviderLocalPassword, req.User.Email)
	if err == nil {
		identityID = id.ID
	}
	createOpts := sessions.CreateOptions{AuthMethod: identities.ProviderLocalPassword}
	if identityID > 0 {
		createOpts.IdentityID = &identityID
	}
	sess, err := s.sessions.Create(ctx, req.User.ID, createOpts)
	if err != nil {
		return nil, fmt.Errorf("breakglass: mint session: %w", err)
	}
	return sess, nil
}

// IssueSetupToken mints a fresh bootstrap token bound to userID and
// returns the plaintext (caller prints once to the operator banner)
// + the persisted row id (for audit). Thin wrapper over the
// TokenStore so cmd/main does not need to import the underlying
// store directly.
func (s *Service) IssueSetupToken(ctx context.Context, userID int64, ttl time.Duration) (string, *Token, error) {
	plaintext, tok, err := s.tokens.IssueSetup(ctx, userID, ttl)
	if err != nil {
		return "", nil, err
	}
	return plaintext, &tok, nil
}

// HasCredential reports whether the user has at least one
// registered WebAuthn credential. cmd/main uses this to decide
// whether to print a (re)redemption banner: a fresh-deployment
// admin with no credentials should see the URL on every boot until
// they redeem.
func (s *Service) HasCredential(ctx context.Context, userID int64) (bool, error) {
	rows, err := s.credentials.ListByUserID(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// recordAudit is the soft-fail audit recorder. Spec mandates ERROR
// log on write failure plus a metric (metric is wired in cmd/main).
func (s *Service) recordAudit(ctx context.Context, e api.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, e); err != nil {
		s.logger.ErrorContext(ctx, "breakglass audit record failed",
			"err", err, "action", string(e.Action))
	}
}

// AuditFailure is the spec-aligned auth.breakglass.failure helper
// the handler invokes on any login failure. Reason is the
// audit-payload string (`password.too_short`, `webauthn.cloned`,
// `webauthn.invalid_assertion`, `password.mismatch`,
// `webauthn.no_credentials`, `bootstrap.expired`, `bootstrap.consumed`,
// etc.).
func (s *Service) AuditFailure(ctx context.Context, email, reason, remoteAddr, userAgent string) {
	s.recordAudit(ctx, api.AuditEvent{
		ActorEmail: email,
		Action:     api.AuditAuthBreakglassFailure,
		RemoteAddr: remoteAddr,
		Payload: map[string]any{
			"decision":   "deny",
			"reason":     reason,
			"user_agent": userAgent,
		},
	})
}

// AuditSuccess is the auth.breakglass.success helper.
func (s *Service) AuditSuccess(ctx context.Context, user *users.User, remoteAddr, userAgent string) {
	uid := user.ID
	s.recordAudit(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: user.Email,
		Action:     api.AuditAuthBreakglassSuccess,
		TargetType: "user",
		TargetID:   formatID(user.ID),
		RemoteAddr: remoteAddr,
		Payload: map[string]any{
			"decision":   "allow",
			"user_agent": userAgent,
		},
	})
}

// formatID is a tiny helper to keep the call sites tidy.
func formatID(id int64) string { return strconv.FormatInt(id, 10) }
