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

	"github.com/fleetdm/edr/server/identity/internal/users"
)

// DefaultAdminEmail is the well-known first-admin email. Operators can create further
// accounts post-v1.1; for MVP this is the only one.
const DefaultAdminEmail = "admin@fleet-edr.local"

// Admin idempotently seeds the break-glass admin user. Returns the
// inserted (or pre-existing) row + an empty password string + nil
// when the row was just created; (nil, "", nil) when the users
// table already had a non-break-glass row (a wave-0 deployment that
// the operator has not migrated yet — Admin does not destructively
// rewrite that row in case it carries operator data).
//
// The stderr writer is no longer used: the Phase 4b token banner is
// emitted by cmd/main via breakglass.Service.IssueSetupToken so the
// banner can include the operator-friendly redemption URL.
func Admin(ctx context.Context, us *users.Store, logger *slog.Logger, _ io.Writer) (*users.User, string, error) {
	if us == nil {
		return nil, "", errors.New("seed.Admin: users store required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	n, err := us.Count(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		// Existing row(s) present. Look up the canonical break-glass
		// admin specifically: if it already exists AND is_breakglass=1,
		// return it so the caller can decide whether to issue a fresh
		// redemption token. If a wave-0 row exists at the same email
		// without is_breakglass=1, refuse to silently flip the flag —
		// the operator runbook covers that migration path explicitly.
		existing, err := us.GetByEmail(ctx, DefaultAdminEmail)
		if errors.Is(err, users.ErrNotFound) {
			logger.DebugContext(ctx, "admin seed skipped — users table non-empty without canonical admin")
			return nil, "", nil
		}
		if err != nil {
			return nil, "", fmt.Errorf("look up existing admin: %w", err)
		}
		if !existing.IsBreakglass {
			// Wave-0 admin row at the canonical email: the operator
			// must run the migration runbook (DELETE FROM users WHERE
			// email='admin@fleet-edr.local' followed by a restart, or
			// a future admin endpoint). Returning (nil, "", nil) skips
			// the redemption-token banner so the operator does not see
			// an invalid URL pointing at a row that still has the old
			// password.
			logger.WarnContext(ctx,
				"admin seed skipped — canonical email exists but is_breakglass=0; run wave-0 migration",
				"edr.user.id", existing.ID,
				"edr.user.email", existing.Email,
			)
			return nil, "", nil
		}
		return existing, "", nil
	}

	u, err := us.CreateBreakglass(ctx, users.CreateBreakglassRequest{
		Email: DefaultAdminEmail,
	})
	if errors.Is(err, users.ErrExistingNonBreakglass) {
		// Race: someone created a non-breakglass row at the email
		// between our Count and our Insert. Same handling as the
		// above branch.
		logger.WarnContext(ctx,
			"admin seed skipped — canonical email exists but is_breakglass=0; run wave-0 migration",
			"edr.user.email", DefaultAdminEmail,
		)
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("create breakglass admin: %w", err)
	}
	logger.InfoContext(ctx, "break-glass admin user seeded",
		"edr.user.id", u.ID,
		"edr.user.email", u.Email,
	)
	return u, "", nil
}
