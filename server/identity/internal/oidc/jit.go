package oidc

import (
	"context"
	"database/sql"
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
// A successful ProvisionOrFind call is one of three shapes:
//
//  1. Existing identity: lookup-by-(provider, subject) finds the row;
//     return the bound user. No DB writes; no audit emission (every
//     subsequent privileged request emits the standard
//     authz.<action> chokepoint row).
//  2. Pre-provisioned adoption (#509): the verified email matches an
//     admin-staged stub (status 'provisioned'); one transaction links
//     the identity and activates the account, keeping the pre-assigned
//     role. Honored regardless of allowJIT; no new audit row (the
//     staging was already audited as user.provisioned, and the login
//     emits auth.login.success).
//  3. New identity (JIT): one transaction inserts users + identities
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
	// policyFn, when non-nil, supplies the JIT policy (allowJIT + defaultRole) per-call from the runtime OIDC configuration store,
	// overriding the static defaultRole/allowJIT above. Production wires this to ssoconfig so a UI edit of the JIT toggle / default
	// role takes effect on the next sign-in without a restart; tests omit it and exercise the static fields directly.
	policyFn func(ctx context.Context) (allowJIT bool, defaultRole string, err error)
}

// ProvisionerOptions bundles the per-deployment knobs. Zero values fall through to wave-1 defaults: defaultRole="analyst",
// allowJIT=false (spec wave-1 default: unknown subjects are denied unless the operator opts in). Logger defaults to slog.Default.
type ProvisionerOptions struct {
	AllowJIT    bool
	DefaultRole string
	Logger      *slog.Logger
	// PolicyFn, when non-nil, supplies the JIT policy (allowJIT + defaultRole) at provision time from the runtime OIDC config, taking
	// precedence over the static AllowJIT/DefaultRole above. Production wires this to the ssoconfig store; tests leave it nil.
	PolicyFn func(ctx context.Context) (allowJIT bool, defaultRole string, err error)
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
		policyFn:    opts.PolicyFn,
	}
}

// ProvisionOrFind resolves the OIDC subject to a local user. Four
// outcomes:
//
//   - identity exists -> return its user_id + identity_id.
//   - identity missing + verified email matches a pre-provisioned stub
//     -> adopt it (link identity, activate, keep pre-assigned role),
//     regardless of allowJIT (#509).
//   - identity missing + no stub + allowJIT -> atomic insert (user +
//     identity + role binding); return the new user_id + identity_id.
//   - identity missing + no stub + !allowJIT -> ErrUnknownIdentity.
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
	allowJIT, defaultRole, err := p.resolvePolicy(ctx)
	if err != nil {
		return 0, 0, err
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
	userID, identityID, err = p.provisionNew(ctx, c, allowJIT, defaultRole)
	if err == nil {
		return userID, identityID, nil
	}
	// Duplicate-key on the identity insert (from adopting a pre-provisioned stub or from a fresh JIT create) means a concurrent callback
	// for the same subject won. Re-resolve and let the loser ride the winner's commit.
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

// provisionNew handles the identity-missing case. It first tries to adopt a pre-provisioned stub (an admin-staged user matching the
// verified email, issue #509); that path is honored regardless of allowJIT because staging is an explicit admin decision. When there is
// no stub to adopt, allowJIT governs whether a brand-new account is JIT-created or the unknown subject is rejected.
func (p *Provisioner) provisionNew(ctx context.Context, c *Claims, allowJIT bool, defaultRole string) (userID, identityID int64, err error) {
	adopted, uid, idID, err := p.reconcilePreProvisioned(ctx, c)
	if err != nil {
		return 0, 0, err
	}
	if adopted {
		return uid, idID, nil
	}
	if !allowJIT {
		return 0, 0, ErrUnknownIdentity
	}
	return p.jitProvision(ctx, c, defaultRole)
}

// reconcilePreProvisioned adopts a pre-provisioned account (#509) when the OIDC claim carries a verified email matching a staged user.
// The discriminator is the explicit lifecycle status: a pre-provisioned stub is exactly a user with status 'provisioned' (a role binding
// but no credential and no identity, by construction). Returns adopted=false when there is nothing to adopt (no verified email, no user
// with that email, or a user in any other status, which includes a real local-password or already-active OIDC account), in which case
// the caller falls through to the normal JIT-create / unknown-subject path and a same-email real account still yields ErrEmailConflict.
// Gating on the explicit status (not "has no identity") is what keeps a real local-password user, which may also lack an identity row,
// from being silently adopted. Matching on the verified email only is what stops an attacker claiming a staged email the IdP has not
// verified.
func (p *Provisioner) reconcilePreProvisioned(ctx context.Context, c *Claims) (adopted bool, userID, identityID int64, err error) {
	// Adoption requires an EXPLICITLY verified email, stricter than EmailTrusted() (which trusts an absent email_verified claim) and
	// stricter than JIT creation: adoption binds an external subject to a pre-staged account that may carry an elevated role, so a missing
	// verification signal must not be treated as trusted here. An IdP that omits email_verified will not auto-adopt a staged account.
	if c.Email == "" || c.EmailVerified == nil || !*c.EmailVerified {
		return false, 0, 0, nil
	}
	u, err := p.users.GetByEmail(ctx, c.Email)
	if errors.Is(err, users.ErrNotFound) {
		return false, 0, 0, nil
	}
	if err != nil {
		return false, 0, 0, fmt.Errorf("oidc: reconcile lookup email: %w", err)
	}
	if u.Status != users.StatusProvisioned {
		return false, 0, 0, nil
	}
	idID, err := p.adoptPreProvisioned(ctx, c, u.ID)
	if errors.Is(err, errAdoptionLost) {
		// A concurrent sign-in flipped this staged account to active first. If it was our own subject (same email, same subject racing),
		// the winner's identity row resolves and we ride it; if it was a different subject, the email now belongs to an active account and
		// this login is an email conflict (never silently bind a second subject to one staged account).
		existing, lookupErr := p.identities.FindByProviderSubject(ctx, identities.ProviderOIDC, c.Subject)
		if lookupErr == nil {
			return true, existing.UserID, existing.ID, nil
		}
		if errors.Is(lookupErr, identities.ErrNotFound) {
			return false, 0, 0, fmt.Errorf("%w: %s", ErrEmailConflict, c.Email)
		}
		return false, 0, 0, fmt.Errorf("oidc: adoption-lost re-resolve: %w", lookupErr)
	}
	if err != nil {
		return false, 0, 0, err
	}
	return true, u.ID, idID, nil
}

// errAdoptionLost signals that a concurrent sign-in won the race to activate a staged account, so this transaction must abandon its
// adoption. reconcilePreProvisioned turns it into either the winner's resolved identity (same subject) or an email conflict (different
// subject); it never escapes the oidc package.
var errAdoptionLost = errors.New("oidc: pre-provisioned account adopted by a concurrent sign-in")

// adoptPreProvisioned links a new OIDC identity to an already-staged user and activates it, in one transaction, keeping the pre-assigned
// role (it deliberately does NOT bind defaultRole). The status flip is the serialization gate: Activate's `WHERE status = 'provisioned'`
// UPDATE takes a row lock, so two sign-ins racing the same staged email contend on it and exactly one sees the row flip. The loser gets
// flipped=false and returns errAdoptionLost without inserting its identity, so a single staged account can never bind two subjects.
// READ COMMITTED (matching the rbac guarded writes) ensures the loser's UPDATE re-reads the winner's committed status rather than a stale
// snapshot. A duplicate-key on the identity insert (a same-subject race that slipped past the gate) bubbles to ProvisionOrFind's
// re-resolve branch.
func (p *Provisioner) adoptPreProvisioned(ctx context.Context, c *Claims, userID int64) (identityID int64, err error) {
	tx, err := p.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("oidc adopt: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	// Flip first: this is the lock + gate. Only the winner proceeds to link an identity.
	flipped, err := p.users.Activate(ctx, tx, userID)
	if err != nil {
		return 0, fmt.Errorf("oidc adopt: activate user %d: %w", userID, err)
	}
	if !flipped {
		return 0, errAdoptionLost
	}
	idID, err := p.identities.InsertWith(ctx, tx, userID, identities.ProviderOIDC, c.Subject)
	if err != nil {
		// Bubble the duplicate up unwrapped so ProvisionOrFind's race branch detects it and re-resolves.
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("oidc adopt: commit: %w", err)
	}
	committed = true
	return idID, nil
}

// resolvePolicy returns the JIT policy (allowJIT + defaultRole) for this provision. When policyFn is wired (production), it reads the
// runtime OIDC config so a UI edit applies on the next sign-in; otherwise it falls back to the static fields (tests). An empty
// defaultRole from policyFn falls through to the static default so a misconfigured row never binds an empty role.
func (p *Provisioner) resolvePolicy(ctx context.Context) (allowJIT bool, defaultRole string, err error) {
	if p.policyFn == nil {
		return p.allowJIT, p.defaultRole, nil
	}
	aj, dr, err := p.policyFn(ctx)
	if err != nil {
		return false, "", fmt.Errorf("oidc: resolve jit policy: %w", err)
	}
	if dr == "" {
		dr = p.defaultRole
	}
	return aj, dr, nil
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
func (p *Provisioner) jitProvision(ctx context.Context, c *Claims, defaultRole string) (userID, identityID int64, err error) {
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
		RoleID:    defaultRole,
		ScopeType: string(api.RoleBindingScopeGlobal),
		ScopeID:   api.RoleBindingScopeWildcard,
	}); err != nil {
		return 0, 0, fmt.Errorf("oidc jit: bind role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("oidc jit: commit: %w", err)
	}
	committed = true
	p.recordCreated(ctx, user, c.Subject, defaultRole)
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
func (p *Provisioner) recordCreated(ctx context.Context, user *users.User, subject, defaultRole string) {
	if p.audit == nil {
		return
	}
	if err := p.audit.Record(ctx, api.AuditEvent{
		Actor:      api.UserPrincipal(user.ID, user.Email),
		Action:     api.AuditAction("user.created"),
		TargetType: "user",
		TargetID:   strconv.FormatInt(user.ID, 10),
		Payload: map[string]any{
			"subject": subject,
			"role":    defaultRole,
			"source":  "oidc.jit",
		},
	}); err != nil && p.logger != nil {
		p.logger.ErrorContext(ctx, "oidc jit audit record failed",
			"err", err, "action", "user.created", "user_id", user.ID)
	}
}
