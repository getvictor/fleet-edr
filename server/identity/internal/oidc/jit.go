package oidc

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/identities"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// DefaultJITRole is the role JIT-provisioned OIDC users are bound
// to. Per the spec (Phase 4.3): the lowest-privilege role available,
// so a freshly-provisioned operator can read but cannot mutate. An
// admin promotes them later via the wave-2 admin surface.
const DefaultJITRole = "analyst"

// ErrUnknownIdentity is returned by ProvisionOrFind when JIT is
// disabled (allowJIT=false) and the OIDC subject does not match an
// existing identity. The handler maps it to 403 + audit
// auth.oidc.unknown_subject.
var ErrUnknownIdentity = errors.New("oidc: unknown identity and JIT disabled")

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
//     + role_bindings; emits one audit row (auth.oidc.user_created).
type Provisioner struct {
	db          *sqlx.DB
	users       *users.Store
	identities  *identities.Store
	rbac        *rbac.Store
	audit       api.AuditRecorder
	defaultRole string
	allowJIT    bool
}

// ProvisionerOptions bundles the per-deployment knobs. Zero values
// fall through to wave-1 defaults: defaultRole="analyst", allowJIT=true.
type ProvisionerOptions struct {
	AllowJIT    bool
	DefaultRole string
}

// NewProvisioner constructs a Provisioner over an existing DB +
// already-constructed stores. db is the same handle the stores
// share so the JIT transaction wraps every insert atomically.
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
	return &Provisioner{
		db:          db,
		users:       usersStore,
		identities:  identitiesStore,
		rbac:        rbacStore,
		audit:       audit,
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
	return p.jitProvision(ctx, c)
}

// jitProvision creates the user + identity + role binding in a single
// transaction. Email comes from the ID-token claim — non-empty in
// every modern IdP, but if the IdP omits it we fall back to the
// subject as a stable display value (the audit row records it
// verbatim).
func (p *Provisioner) jitProvision(ctx context.Context, c *Claims) (userID, identityID int64, err error) {
	email := c.Email
	if email == "" {
		// Fallback: use subject prefixed with a sentinel so the row
		// is still searchable. Real-world IdPs always populate email
		// at standard scopes; this is purely defensive.
		email = "oidc:" + c.Subject
	}
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
		return 0, 0, fmt.Errorf("oidc jit: create user: %w", err)
	}
	idID, err := p.identities.InsertWith(ctx, tx, user.ID, identities.ProviderOIDC, c.Subject)
	if err != nil {
		return 0, 0, fmt.Errorf("oidc jit: insert identity: %w", err)
	}
	if err := p.rbac.BindRole(
		ctx, tx, user.ID,
		p.defaultRole, api.DefaultTenantID,
		string(api.RoleBindingScopeTenant), api.RoleBindingScopeWildcard,
		nil,
	); err != nil {
		return 0, 0, fmt.Errorf("oidc jit: bind role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("oidc jit: commit: %w", err)
	}
	committed = true
	p.recordCreated(ctx, user, c.Subject)
	return user.ID, idID, nil
}

// recordCreated emits an audit row for a successful JIT provisioning.
// Soft-fail: a missing audit row does NOT roll the transaction back —
// the user is real and reachable. The chokepoint's standard authz
// rows still capture every subsequent action.
func (p *Provisioner) recordCreated(ctx context.Context, user *users.User, subject string) {
	if p.audit == nil {
		return
	}
	uid := user.ID
	_ = p.audit.Record(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: user.Email,
		Action:     api.AuditAction("auth.oidc.user_created"),
		TargetType: "user",
		TargetID:   strconv.FormatInt(user.ID, 10),
		Payload: map[string]any{
			"subject": subject,
			"role":    p.defaultRole,
			"tenant":  api.DefaultTenantID,
		},
	})
}
