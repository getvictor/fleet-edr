// Package seed bootstraps the first-boot state that is too opinionated for DDL: the
// single break-glass admin user that the recovery surface logs in as. Called from
// main.go right after the store is open but before the HTTP server starts accepting
// traffic.
//
// Phase 4b note: prior to phase 4 this seeded the admin row with a randomly
// generated password printed to stderr. That flow is replaced by the bootstrap
// token flow (server/identity/internal/breakglass): the seed only creates the
// admin row with NULL password + is_breakglass=1, and cmd/main calls
// breakglass.IssueSetupToken to mint the redemption URL banner separately. The
// second return value of Admin is now always empty; it is preserved so the
// service.SeedAdmin signature does not break every caller in one PR.
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
// key (user_id, role_id, tenant_id, scope_type, scope_id) to make the
// seed idempotent across container restarts; a duplicate just means
// "already seeded, nothing to do."
const mysqlErrDupEntry = 1062

// Admin idempotently seeds the break-glass admin user AND its
// super_admin role binding. Returns the inserted (or pre-existing)
// row + an empty password string + nil when the row was just created;
// (nil, "", nil) when the users table already had a non-break-glass
// row (a wave-0 deployment that the operator has not migrated yet -
// Admin does not destructively rewrite that row in case it carries
// operator data).
//
// The role binding is inserted on every call so a deployment that
// somehow lost the binding (manual SQL surgery, partially-restored
// backup) self-heals on the next restart. The rbac unique key
// (user_id, role_id, tenant_id, scope_type, scope_id) makes the
// insert a no-op when the binding already exists.
//
// The stderr writer is no longer used: the Phase 4b token banner is
// emitted by cmd/main via breakglass.Service.IssueSetupToken so the
// banner can include the operator-friendly redemption URL.
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
// creating it if the users table is empty. Returns (nil, nil) when
// the table has rows but none belong to the canonical admin OR when
// the canonical email exists but is_breakglass=0 (the wave-0
// migration path). The caller treats both nil-row outcomes as "seed
// skipped, no role binding to write."
func resolveOrCreateAdmin(ctx context.Context, us *users.Store, logger *slog.Logger) (*users.User, error) {
	n, err := us.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		// Existing row(s) present. Look up the canonical break-glass
		// admin specifically: if it already exists AND is_breakglass=1,
		// return it so the caller can decide whether to issue a fresh
		// redemption token + bind super_admin. If a wave-0 row exists
		// at the same email without is_breakglass=1, refuse to silently
		// flip the flag - the operator runbook covers that migration
		// path explicitly.
		existing, err := us.GetByEmail(ctx, DefaultAdminEmail)
		if errors.Is(err, users.ErrNotFound) {
			logger.DebugContext(ctx, "admin seed skipped - users table non-empty without canonical admin")
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("look up existing admin: %w", err)
		}
		if !existing.IsBreakglass {
			logger.WarnContext(ctx,
				"admin seed skipped - canonical email exists but is_breakglass=0; run wave-0 migration",
				attrkeys.UserID, existing.ID,
				attrkeys.UserEmail, existing.Email,
			)
			return nil, nil
		}
		return existing, nil
	}

	u, err := us.CreateBreakglass(ctx, users.CreateBreakglassRequest{
		Email: DefaultAdminEmail,
	})
	if errors.Is(err, users.ErrExistingNonBreakglass) {
		// Race: someone created a non-breakglass row at the email
		// between our Count and our Insert. Same handling as the
		// above branch.
		logger.WarnContext(ctx,
			"admin seed skipped - canonical email exists but is_breakglass=0; run wave-0 migration",
			attrkeys.UserEmail, DefaultAdminEmail,
		)
		return nil, nil
	}
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
		TenantID:  api.DefaultTenantID,
		ScopeType: string(api.RoleBindingScopeTenant),
		ScopeID:   "*",
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
