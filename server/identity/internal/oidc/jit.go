package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// mysqlErrDupEntry is the duplicate-key error code we expect on the JIT race: a concurrent callback for the same OIDC subject (or the
// same email) wins the insert, and the loser sees this code.
const mysqlErrDupEntry = 1062

// DefaultJITRole is the role JIT-provisioned OIDC users are bound to. The lowest-privilege role available, so a freshly-provisioned
// operator can read but cannot mutate. An admin promotes them later via the wave-2 admin surface.
const DefaultJITRole = "analyst"

// ErrUnknownIdentity is returned by ProvisionOrFind when JIT is disabled (allowJIT=false) and the OIDC subject does not match an
// existing identity. The handler maps it to 403 + audit auth.oidc.failure with reason oidc.unknown_subject.
var ErrUnknownIdentity = errors.New("oidc: unknown identity and JIT disabled")

// ErrEmailConflict is returned when JIT cannot create the user because another row already owns the same email. This happens when
// an existing local-password user (or another OIDC user from a previous binding) has the same email but no identity row links them;
// promoting the binding is an admin task, not a silent JIT merge. The handler maps it to a 409 / 403 redirect with the reason surfaced
// to the operator.
var ErrEmailConflict = errors.New("oidc: email already bound to another account")

// Provisioner holds the per-deployment knobs JIT consults: the
// stores it writes to, the audit recorder it logs to, and the
// allow-JIT flag that gates whether unknown subjects auto-provision.
//
// A successful ProvisionOrFind call is one of two shapes:
//
//  1. Existing identity: lookup-by-(provider, subject) finds the row;
//     return the bound user. No DB writes; no audit emission (every
//     subsequent privileged request emits the standard
//     authz.<action> chokepoint row).
//  2. New identity (JIT): one transaction inserts users + identities
//     + role_bindings; emits one audit row (action="user.created",
//     payload.source="oidc.jit").
type Provisioner struct {
	db          *sqlx.DB
	users       *users.Store
	identities  *identities.Store
	rbac        *rbac.Store
	audit       api.AuditRecorder
	logger      *slog.Logger
	defaultRole string
	allowJIT    bool
}

// ProvisionerOptions bundles the per-deployment knobs. Zero values fall through to wave-1 defaults: defaultRole="analyst",
// allowJIT=false (spec wave-1 default: unknown subjects are denied unless the operator opts in). Logger defaults to slog.Default.
type ProvisionerOptions struct {
	AllowJIT    bool
	DefaultRole string
	Logger      *slog.Logger
}

// NewProvisioner constructs a Provisioner over an existing DB + already-constructed stores. db is the same handle the stores share so
// the JIT transaction wraps every insert atomically.
func NewProvisioner(
	db *sqlx.DB,
	usersStore *users.Store,
	identitiesStore *identities.Store,
	rbacStore *rbac.Store,
	audit api.AuditRecorder,
	opts ProvisionerOptions,
) *Provisioner {
	role := opts.DefaultRole
	if role == "" {
		role = DefaultJITRole
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{
		db:          db,
		users:       usersStore,
		identities:  identitiesStore,
		rbac:        rbacStore,
		audit:       audit,
		logger:      logger,
		defaultRole: role,
		allowJIT:    opts.AllowJIT,
	}
}

// ProvisionOrFind resolves the OIDC subject to a local user. Three
// outcomes:
//
//   - identity exists -> return its user_id + identity_id.
//   - identity missing + allowJIT -> atomic insert (user + identity +
//     role binding); return the new user_id + identity_id.
//   - identity missing + !allowJIT -> ErrUnknownIdentity.
//
// Race-safe: when two callbacks for the same fresh subject arrive at
// once, one wins the unique constraint on (provider, subject) and the
// other sees a duplicate-key error from the identity insert. The
// loser retries the lookup and proceeds with the winner's row.
//
// The returned identityID is the row id of the OIDC identity, used
// by the session-mint path to populate sessions.identity_id (FK).
func (p *Provisioner) ProvisionOrFind(ctx context.Context, c *Claims) (userID, identityID int64, err error) {
	if c == nil || c.Subject == "" {
		return 0, 0, errors.New("oidc: claims.Subject is required")
	}
	existing, err := p.identities.FindByProviderSubject(ctx, identities.ProviderOIDC, c.Subject)
	switch {
	case err == nil:
		return existing.UserID, existing.ID, nil
	case errors.Is(err, identities.ErrNotFound):
		// fall through to JIT path
	default:
		return 0, 0, fmt.Errorf("oidc: lookup identity: %w", err)
	}
	if !p.allowJIT {
		return 0, 0, ErrUnknownIdentity
	}
	userID, identityID, err = p.jitProvision(ctx, c)
	if err == nil {
		return userID, identityID, nil
	}
	// Duplicate-key on the identity insert means a concurrent callback for the same subject won. Re-resolve and let the loser ride the
	// winner's commit.
	if isDuplicateKey(err) {
		existing, lookupErr := p.identities.FindByProviderSubject(
			ctx, identities.ProviderOIDC, c.Subject)
		if lookupErr == nil {
			return existing.UserID, existing.ID, nil
		}
		return 0, 0, fmt.Errorf("oidc: race-resolve lookup: %w", lookupErr)
	}
	return 0, 0, err
}

// isDuplicateKey returns true when err wraps a MySQL 1062
// "Duplicate entry" error from any layer of the JIT transaction.
func isDuplicateKey(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDupEntry
}

// jitProvision creates the user + identity + role binding in a single transaction. Email comes from the ID-token claim, non-empty in
// every modern IdP, but if the IdP omits it we fall back to the subject as a stable display value (the audit row records it verbatim).
// When the email exists already on a different account we surface ErrEmailConflict so the operator path doesn't silently merge
// identities. That promotion is an admin action.
func (p *Provisioner) jitProvision(ctx context.Context, c *Claims) (userID, identityID int64, err error) {
	email := jitEmail(c)
	tx, err := p.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("oidc jit: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	user, err := p.users.CreateOIDC(ctx, tx, users.CreateOIDCRequest{Email: email})
	if err != nil {
		// Distinguish the email-collision branch: another row already owns this email (likely a local-password user). Caller maps to a
		// directed 403/conflict response rather than a 500.
		if isDuplicateKey(err) {
			return 0, 0, fmt.Errorf("%w: %s", ErrEmailConflict, email)
		}
		return 0, 0, fmt.Errorf("oidc jit: create user: %w", err)
	}
	idID, err := p.identities.InsertWith(ctx, tx, user.ID, identities.ProviderOIDC, c.Subject)
	if err != nil {
		// Bubble the duplicate up unwrapped so ProvisionOrFind's race
		// branch can detect it and re-resolve cleanly.
		return 0, 0, err
	}
	if err := p.rbac.BindRole(ctx, tx, rbac.BindRoleRequest{
		UserID:    user.ID,
		RoleID:    p.defaultRole,
		ScopeType: string(api.RoleBindingScopeGlobal),
		ScopeID:   api.RoleBindingScopeWildcard,
	}); err != nil {
		return 0, 0, fmt.Errorf("oidc jit: bind role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("oidc jit: commit: %w", err)
	}
	committed = true
	p.recordCreated(ctx, user, c.Subject)
	return user.ID, idID, nil
}

// jitEmail derives the email used for the JIT users row. Only trust the IdP-supplied email when email_verified=true (or absent, since the
// claim is optional in spec, and IdPs that don't emit it rarely allow unverified emails). When the IdP signals an unverified email,
// fall back to the synthetic subject-prefixed sentinel; an admin promotion path can attach the real email later.
func jitEmail(c *Claims) string {
	if c.Email != "" && c.EmailTrusted() {
		return c.Email
	}
	return "oidc:" + c.Subject
}

// recordCreated emits an audit row for a successful JIT provisioning. Soft-fail at the request level: a missing audit row does NOT
// roll the transaction back: the user is real and reachable. The chokepoint's standard authz rows still capture every subsequent
// action. Per spec, audit-write failures must log at ERROR so the operator pipeline notices the gap.
func (p *Provisioner) recordCreated(ctx context.Context, user *users.User, subject string) {
	if p.audit == nil {
		return
	}
	uid := user.ID
	if err := p.audit.Record(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: user.Email,
		Action:     api.AuditAction("user.created"),
		TargetType: "user",
		TargetID:   strconv.FormatInt(user.ID, 10),
		Payload: map[string]any{
			"subject": subject,
			"role":    p.defaultRole,
			"source":  "oidc.jit",
		},
	}); err != nil && p.logger != nil {
		p.logger.ErrorContext(ctx, "oidc jit audit record failed",
			"err", err, "action", "user.created", "user_id", uid)
	}
}
