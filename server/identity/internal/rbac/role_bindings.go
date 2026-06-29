// Package rbac owns the role_bindings + roles tables. Wave 1 ships
// this as a read-side store: the AuthZ chokepoint loads an actor's
// live bindings on every privileged request via ListLiveBindings.
// Wave 2's user-management write surface will land here.
//
// Internal to identity. Cross-context callers go through
// server/identity/api.AuthZ instead of touching this store.
package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// mysqlErrDupEntry is the MySQL "Duplicate entry" code. ProvisionUser maps a uk_users_email collision to api.ErrEmailExists. One local
// helper mirrors the same pattern in seed/admin.go, oidc/jit.go, and breakglass/service.go (the role set is dynamic, so there is no
// shared cross-package home for it).
const mysqlErrDupEntry = 1062

func isDuplicateKey(err error) bool {
	var mysqlErr *mysql.MySQLError
	// Early-return rather than `errors.As(...) && mysqlErr.Number == ...`: the one-liner trips nilaway (it cannot prove mysqlErr is
	// non-nil across the && short-circuit), and this shape matches the sibling helpers in oidc/jit.go and breakglass/service.go.
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDupEntry
}

// Store owns the role_bindings table.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store over an existing sqlx.DB handle.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// errNilDB is returned by every entry point when the Store was built without a DB handle, which happens only in minimal test wiring.
// One sentinel keeps the identical guard message in a single place (the S1192 dedup). It stays unexported because the nil-DB case is a
// construction-time misuse that no caller branches on; callers in other identity packages reach this Store through server/identity/api.
var errNilDB = errors.New("rbac: db must not be nil")

// DB returns the underlying executor for callers that need to invoke BindRole outside of a transaction (e.g. seed.Admin's idempotent
// bootstrap-time bind). JIT + admin-promotion paths thread their own transactional executor and don't need this accessor.
func (s *Store) DB() Executor {
	return s.db
}

// roleBindingRow is the storage shape; the public api.RoleBinding is the read shape callers see. Keeping them distinct means a wave-2
// schema add (e.g. created_by) can grow the storage row without pushing into the public boundary.
type roleBindingRow struct {
	ID        int64        `db:"id"`
	UserID    int64        `db:"user_id"`
	RoleID    string       `db:"role_id"`
	ScopeType string       `db:"scope_type"`
	ScopeID   string       `db:"scope_id"`
	ExpiresAt sql.NullTime `db:"expires_at"`
	CreatedAt time.Time    `db:"created_at"`
}

// Executor is the executor subset BindRole consumes; lets the JIT provisioner pass an *sqlx.Tx so the role binding lands in the same
// transaction as the user + identity insert. Named per the Go convention (single-method interface ends in -er).
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// BindRoleRequest is the input to BindRole. Pulled out of the function signature so the call site reads as named fields and stays
// under the linter's per-call parameter budget. Wave-1 defaults: ExpiresAt nil (non-expiring), ScopeType "global", ScopeID "*".
type BindRoleRequest struct {
	UserID    int64
	RoleID    string
	ScopeType string
	ScopeID   string
	ExpiresAt *time.Time
}

// BindRole inserts a role_bindings row. Used by Phase-4 JIT provisioning to bind a freshly-provisioned OIDC user to the default role
// for the deployment.
func (s *Store) BindRole(ctx context.Context, ec Executor, req BindRoleRequest) error {
	_, err := ec.ExecContext(ctx, `
		INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, req.UserID, req.RoleID, req.ScopeType, req.ScopeID, req.ExpiresAt)
	if err != nil {
		return fmt.Errorf("bind role %q to user %d: %w", req.RoleID, req.UserID, err)
	}
	return nil
}

// globalScope is the wave-2 binding scope: deployment-wide. The admin user-management surface (#135) reads and writes only global
// bindings; host_group / host scopes stay reserved for wave-3.
const globalScope = "global"

// adminTierRoles are the roles whose presence keeps the deployment self-manageable. The last-active-admin guard counts users holding
// any of these; demoting or disabling the last one is refused.
var adminTierRoles = []string{"admin", "super_admin"}

// AllLiveBindings returns the live global role ids for every user, keyed by user id. Used by the admin user-list endpoint to render
// each operator's effective role without an N+1 per-user query. Expired bindings and non-global scopes are excluded: the wave-2 surface
// is single-role, global-scope only. A user with no live global binding is simply absent from the map.
func (s *Store) AllLiveBindings(ctx context.Context) (map[int64][]string, error) {
	if s.db == nil {
		return nil, errNilDB
	}
	var rows []struct {
		UserID int64  `db:"user_id"`
		RoleID string `db:"role_id"`
	}
	err := s.db.SelectContext(ctx, &rows, `
		SELECT user_id, role_id
		FROM role_bindings
		WHERE scope_type = ?
		  AND (expires_at IS NULL OR expires_at > NOW(6))
		ORDER BY user_id, role_id
	`, globalScope)
	if err != nil {
		return nil, fmt.Errorf("list all live bindings: %w", err)
	}
	out := make(map[int64][]string, len(rows))
	for _, r := range rows {
		out[r.UserID] = append(out[r.UserID], r.RoleID)
	}
	return out, nil
}

// LiveGlobalRoles returns one user's live global role ids. Used by the user-management handler for the guardrail checks (is the target
// admin-tier? does it hold super_admin?), no-op detection, and the audit from-set. Non-global scopes and expired bindings are excluded.
func (s *Store) LiveGlobalRoles(ctx context.Context, userID int64) ([]string, error) {
	if s.db == nil {
		return nil, errNilDB
	}
	roles := []string{}
	err := s.db.SelectContext(ctx, &roles, `
		SELECT role_id FROM role_bindings
		WHERE user_id = ? AND scope_type = ?
		  AND (expires_at IS NULL OR expires_at > NOW(6))
		ORDER BY role_id
	`, userID, globalScope)
	if err != nil {
		return nil, fmt.Errorf("live global roles for user %d: %w", userID, err)
	}
	return roles, nil
}

// isAdminTier reports whether any of roles is an admin-tier role (admin or super_admin).
func isAdminTier(roles []string) bool {
	for _, r := range roles {
		if slices.Contains(adminTierRoles, r) {
			return true
		}
	}
	return false
}

// lockAdminSentinel takes an exclusive row lock on the admin-tier rows of the roles table, serializing every mutation that could reduce
// the active-admin count. All guarded mutations acquire it first, in the same (id-ordered) order, so concurrent demotes/disables run one
// at a time and the lock auto-releases when the surrounding transaction commits or rolls back. It is the serialization point that makes
// the last-admin invariant race-free: locking the *other* admins' binding rows would not work, because two demotes of different targets
// lock disjoint rows and never contend.
func lockAdminSentinel(ctx context.Context, tx *sqlx.Tx) error {
	query, args, err := sqlx.In(`SELECT id FROM roles WHERE id IN (?) ORDER BY id FOR UPDATE`, adminTierRoles)
	if err != nil {
		return fmt.Errorf("build admin-sentinel lock: %w", err)
	}
	var ids []string
	if err := tx.SelectContext(ctx, &ids, tx.Rebind(query), args...); err != nil {
		return fmt.Errorf("lock admin sentinel: %w", err)
	}
	return nil
}

// otherActiveAdmins counts active (non-disabled) users holding an admin-tier role via a live global binding, excluding excludeUserID.
// Runs on the caller's transaction so it reads the state established after lockAdminSentinel under READ COMMITTED.
func otherActiveAdmins(ctx context.Context, tx *sqlx.Tx, excludeUserID int64) (int, error) {
	query, args, err := sqlx.In(`
		SELECT COUNT(DISTINCT rb.user_id)
		FROM role_bindings rb
		JOIN users u ON u.id = rb.user_id
		WHERE rb.role_id IN (?)
		  AND rb.scope_type = ?
		  AND (rb.expires_at IS NULL OR rb.expires_at > NOW(6))
		  AND u.status = 'active'
		  AND rb.user_id <> ?
	`, adminTierRoles, globalScope, excludeUserID)
	if err != nil {
		return 0, fmt.Errorf("build other-active-admins query: %w", err)
	}
	var n int
	if err := tx.GetContext(ctx, &n, tx.Rebind(query), args...); err != nil {
		return 0, fmt.Errorf("count other active admins: %w", err)
	}
	return n, nil
}

// targetIsActiveAdmin reports whether userID is currently an active user holding an admin-tier global binding, read on the caller's tx.
func targetIsActiveAdmin(ctx context.Context, tx *sqlx.Tx, userID int64) (bool, error) {
	query, args, err := sqlx.In(`
		SELECT EXISTS(
			SELECT 1 FROM role_bindings rb JOIN users u ON u.id = rb.user_id
			WHERE rb.user_id = ?
			  AND rb.role_id IN (?)
			  AND rb.scope_type = ?
			  AND (rb.expires_at IS NULL OR rb.expires_at > NOW(6))
			  AND u.status = 'active'
		)
	`, userID, adminTierRoles, globalScope)
	if err != nil {
		return false, fmt.Errorf("build target-is-active-admin query: %w", err)
	}
	var ok bool
	if err := tx.GetContext(ctx, &ok, tx.Rebind(query), args...); err != nil {
		return false, fmt.Errorf("target is active admin: %w", err)
	}
	return ok, nil
}

// refuseIfLastActiveAdmin returns api.ErrLastAdmin when userID is the last active admin-tier user, so a demote or disable cannot strand
// the deployment without an administrator. It runs on the caller's locked transaction (after lockAdminSentinel) and reads the committed
// state under READ COMMITTED. A non-admin or already-inactive target can never be the last admin, so it returns nil.
func refuseIfLastActiveAdmin(ctx context.Context, tx *sqlx.Tx, userID int64) error {
	active, err := targetIsActiveAdmin(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !active {
		return nil
	}
	others, err := otherActiveAdmins(ctx, tx, userID)
	if err != nil {
		return err
	}
	if others == 0 {
		return api.ErrLastAdmin
	}
	return nil
}

// beginGuarded opens a READ COMMITTED transaction. READ COMMITTED (not InnoDB's default REPEATABLE READ) is required so that, after a
// guarded mutation blocks on lockAdminSentinel and the holder commits, the waiter's subsequent count reads the committed effect rather
// than a stale snapshot. The sentinel lock provides the serialization; READ COMMITTED provides the freshness.
func (s *Store) beginGuarded(ctx context.Context) (*sqlx.Tx, error) {
	return s.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
}

// SetUserRole replaces a user's global role bindings with exactly one binding for roleID and returns the user's previous live global
// role ids (for the audit payload). This is the wave-2 single-role model: a user holds exactly one global role afterward, collapsing any
// legacy multi-binding rows. The last-active-admin invariant is enforced atomically: demoting the last active admin away from an
// admin-tier role returns api.ErrLastAdmin and persists nothing. The caller (useradmin handler) validates roleID and runs the
// break-glass / self / super_admin guards before calling.
func (s *Store) SetUserRole(ctx context.Context, userID int64, roleID string) (previous []string, err error) {
	if s.db == nil {
		return nil, errNilDB
	}
	tx, err := s.beginGuarded(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin set-role tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err = lockAdminSentinel(ctx, tx); err != nil {
		return nil, err
	}
	if err = tx.SelectContext(ctx, &previous, `
		SELECT role_id FROM role_bindings
		WHERE user_id = ? AND scope_type = ?
		  AND (expires_at IS NULL OR expires_at > NOW(6))
		ORDER BY role_id
	`, userID, globalScope); err != nil {
		return nil, fmt.Errorf("read previous bindings for user %d: %w", userID, err)
	}
	// Guard: demoting an active admin-tier user to a non-admin role must leave at least one other active admin.
	if isAdminTier(previous) && !isAdminTier([]string{roleID}) {
		if err = refuseIfLastActiveAdmin(ctx, tx, userID); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `
		DELETE FROM role_bindings WHERE user_id = ? AND scope_type = ?
	`, userID, globalScope); err != nil {
		return nil, fmt.Errorf("clear bindings for user %d: %w", userID, err)
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id) VALUES (?, ?, ?, '*')
	`, userID, roleID, globalScope); err != nil {
		return nil, fmt.Errorf("bind role %q to user %d: %w", roleID, userID, err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit set-role tx: %w", err)
	}
	return previous, nil
}

// SetUserStatus sets a user's account status. Enabling never threatens the invariant and is a plain update. Disabling is guarded
// atomically (same sentinel + READ COMMITTED as SetUserRole): disabling the last active admin returns api.ErrLastAdmin and persists
// nothing. The caller validates the status value and runs the break-glass / self guards before calling.
func (s *Store) SetUserStatus(ctx context.Context, userID int64, status string) error {
	if s.db == nil {
		return errNilDB
	}
	if status != "disabled" {
		if _, err := s.db.ExecContext(ctx, `UPDATE users SET status = ? WHERE id = ?`, status, userID); err != nil {
			return fmt.Errorf("set status for user %d: %w", userID, err)
		}
		return nil
	}
	tx, err := s.beginGuarded(ctx)
	if err != nil {
		return fmt.Errorf("begin set-status tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err = lockAdminSentinel(ctx, tx); err != nil {
		return err
	}
	if err = refuseIfLastActiveAdmin(ctx, tx, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET status = 'disabled' WHERE id = ?`, userID); err != nil {
		return fmt.Errorf("disable user %d: %w", userID, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit set-status tx: %w", err)
	}
	return nil
}

// ProvisionUser stages a new operator before their first sign-in (issue #509): it inserts a users row in the 'provisioned' lifecycle
// state with no credential and binds it to exactly one global role, atomically, returning the new user id. A duplicate email returns
// api.ErrEmailExists (the uk_users_email unique key is the race-safe enforcement point). The last-active-admin guard does not apply: a
// brand-new row can only add an admin-tier binding, never remove the last one, and the account cannot authenticate until its first OIDC
// login adopts it (server/identity/internal/oidc reconciliation). Lives here because the rbac store already owns the user-plus-role
// write surface (SetUserRole, SetUserStatus). The caller (useradmin handler) normalizes the email and validates the role first.
func (s *Store) ProvisionUser(ctx context.Context, email, roleID string) (int64, error) {
	if s.db == nil {
		return 0, errNilDB
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin provision tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `INSERT INTO users (email, status) VALUES (?, ?)`, email, users.StatusProvisioned)
	if err != nil {
		if isDuplicateKey(err) {
			return 0, api.ErrEmailExists
		}
		// Do not log the email (PII) in the error; the user id isn't known yet, so keep it generic, matching CreateOIDC.
		return 0, fmt.Errorf("insert provisioned user: %w", err)
	}
	userID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id for provisioned user: %w", err)
	}
	// Attach the principals spine row in the same tx so the staged user is attributable per ADR-0017 (mirrors every other user-creation
	// path); reuses the centralized helper rather than cloning the principals insert.
	if err = users.EnsureUserPrincipal(ctx, tx, userID, email); err != nil {
		return 0, fmt.Errorf("ensure principal for provisioned user %d: %w", userID, err)
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id) VALUES (?, ?, ?, '*')
	`, userID, roleID, globalScope); err != nil {
		return 0, fmt.Errorf("bind role %q to provisioned user %d: %w", roleID, userID, err)
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit provision tx: %w", err)
	}
	return userID, nil
}

// ListLiveBindings returns every role binding for a user that is not
// expired. The (user_id, expires_at) index keeps the query indexed
// even on very large role_bindings tables.
//
// Used by the chokepoint's per-request actor build. Sub-millisecond
// on a populated DB; the AuthZ p99 budget allocates ~1 ms for the
// whole pipeline (this query + the OPA evaluation), so the index
// matters.
func (s *Store) ListLiveBindings(ctx context.Context, userID int64) ([]api.RoleBinding, error) {
	if s.db == nil {
		return nil, errNilDB
	}
	rows := []roleBindingRow{}
	err := s.db.SelectContext(ctx, &rows, `
		SELECT id, user_id, role_id, scope_type, scope_id, expires_at, created_at
		FROM role_bindings
		WHERE user_id = ?
		  AND (expires_at IS NULL OR expires_at > NOW(6))
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list live bindings for user %d: %w", userID, err)
	}
	out := make([]api.RoleBinding, len(rows))
	for i, r := range rows {
		out[i] = api.RoleBinding{
			ID:        r.ID,
			UserID:    r.UserID,
			RoleID:    r.RoleID,
			ScopeType: api.RoleBindingScopeType(r.ScopeType),
			ScopeID:   r.ScopeID,
			CreatedAt: r.CreatedAt,
		}
		if r.ExpiresAt.Valid {
			t := r.ExpiresAt.Time
			out[i].ExpiresAt = &t
		}
	}
	return out, nil
}
