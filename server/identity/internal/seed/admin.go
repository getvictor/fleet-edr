// Package seed bootstraps the first-boot state that is too opinionated for DDL: the
// single break-glass admin user that the recovery surface logs in as. Called from
// main.go right after the store is open but before the HTTP server starts accepting
// traffic.
//
// The seed creates the admin row with NULL password + is_breakglass=1, and
// cmd/main calls breakglass.IssueSetupToken to mint the redemption URL banner
// separately so the operator's first login is a WebAuthn registration ceremony
// rather than a printed-password handoff. The Admin function's second return
// value is always empty; it is preserved so service.SeedAdmin's signature does
// not break every caller in one PR.
package seed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/go-sql-driver/mysql"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// DefaultAdminEmail is the well-known first-admin email. Operators can create further
// accounts post-v1.1; for MVP this is the only one.
const DefaultAdminEmail = "admin@fleet-edr.local"

// DefaultAdminRole is the role bound to the seeded break-glass admin
// at first boot. `docs/authz.md` documents the contract: the
// break-glass account lands in `super_admin` so an operator who
// completes the redemption flow can do every operator action without
// a manual SQL promotion. Without this binding the user has zero
// grants and the chokepoint denies even host.read.
const DefaultAdminRole = "super_admin"

// mysqlErrDupEntry is the SQL state for "row already exists with the
// unique key you tried to insert." We rely on the role_bindings unique
// key (user_id, role_id, scope_type, scope_id) to make the seed
// idempotent across container restarts; a duplicate just means
// "already seeded, nothing to do."
const mysqlErrDupEntry = 1062

// Admin idempotently seeds the break-glass admin user AND its
// super_admin role binding. Returns the inserted (or pre-existing)
// row + an empty password string + nil on success. Surfaces a hard
// error if the canonical email is occupied by a non-break-glass row;
// pre-pilot there is no deployment in that state, and refusing to
// silently rewrite the row is the safer default.
//
// The role binding is inserted on every call so a deployment that
// somehow lost the binding (manual SQL surgery, partially-restored
// backup) self-heals on the next restart. The rbac unique key
// (user_id, role_id, scope_type, scope_id) makes the insert a no-op
// when the binding already exists.
//
// The stderr writer is no longer used: the redemption-token banner
// is emitted by cmd/main via breakglass.Service.IssueSetupToken so
// the banner can include the operator-friendly redemption URL.
func Admin(ctx context.Context, us *users.Store, rb *rbac.Store, logger *slog.Logger, _ io.Writer) (*users.User, string, error) {
	if us == nil {
		return nil, "", errors.New("seed.Admin: users store required")
	}
	if rb == nil {
		return nil, "", errors.New("seed.Admin: rbac store required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	u, err := resolveOrCreateAdmin(ctx, us, logger)
	if err != nil || u == nil {
		return u, "", err
	}
	if err := bindSuperAdmin(ctx, rb, u, logger); err != nil {
		return nil, "", err
	}
	return u, "", nil
}

// resolveOrCreateAdmin finds the canonical break-glass admin row,
// creating it if it doesn't exist yet. Idempotent: on a restart the
// existing row is returned unchanged so the caller can re-issue a
// fresh redemption token + re-bind super_admin without rewriting the
// user record. Returns a hard error on any inconsistency (e.g. a
// non-breakglass row at the canonical email) — there is no
// pre-release deployment to migrate from, so an unexpected state is
// always a bug, not a known migration path.
func resolveOrCreateAdmin(ctx context.Context, us *users.Store, logger *slog.Logger) (*users.User, error) {
	existing, err := us.GetByEmail(ctx, DefaultAdminEmail)
	if err == nil {
		if !existing.IsBreakglass {
			return nil, fmt.Errorf("seed.Admin: canonical email %q exists with is_breakglass=0; refusing to silently rewrite", DefaultAdminEmail)
		}
		return existing, nil
	}
	if !errors.Is(err, users.ErrNotFound) {
		return nil, fmt.Errorf("look up existing admin: %w", err)
	}

	u, err := us.CreateBreakglass(ctx, users.CreateBreakglassRequest{
		Email: DefaultAdminEmail,
	})
	if err != nil {
		return nil, fmt.Errorf("create breakglass admin: %w", err)
	}
	logger.InfoContext(ctx, "break-glass admin user seeded",
		attrkeys.UserID, u.ID,
		attrkeys.UserEmail, u.Email,
	)
	return u, nil
}

// bindSuperAdmin inserts the role_bindings row that gives the
// break-glass admin its wave-1 grants. Idempotent on the rbac unique
// key: a duplicate-entry error is swallowed (binding already exists,
// nothing to do); any other DB failure surfaces.
func bindSuperAdmin(ctx context.Context, rb *rbac.Store, u *users.User, logger *slog.Logger) error {
	err := rb.BindRole(ctx, rb.DB(), rbac.BindRoleRequest{
		UserID:    u.ID,
		RoleID:    DefaultAdminRole,
		ScopeType: string(api.RoleBindingScopeGlobal),
		ScopeID:   api.RoleBindingScopeWildcard,
	})
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == mysqlErrDupEntry {
		logger.DebugContext(ctx, "break-glass admin role binding already present",
			attrkeys.UserID, u.ID, "role", DefaultAdminRole)
		return nil
	}
	if err != nil {
		return fmt.Errorf("bind %s to %d: %w", DefaultAdminRole, u.ID, err)
	}
	logger.InfoContext(ctx, "break-glass admin role binding seeded",
		attrkeys.UserID, u.ID, "role", DefaultAdminRole)
	return nil
}
