package seed

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// DefaultTenantID is the wave-1 scaffolding tenant. Every existing row
// across every context defaults its tenant_id to this string; wave-1
// reads do not filter on tenant_id, so the literal lives only in the
// schema defaults and this seed. Wave 2 introduces additional rows;
// the constant becomes the "fallback when no tenant header is set"
// rather than the only tenant.
const DefaultTenantID = "default"

// DefaultTenantName is the human-facing name used in the seeded row
// and in any UI that resolves the default tenant. Operators may
// rename it post-seed; the seed is INSERT IGNORE so re-runs do not
// clobber an edited row.
const DefaultTenantName = "Default Tenant"

// Tenants seeds the `tenants` table with the default tenant. Idempotent
// via INSERT IGNORE: a populated DB is a no-op, an empty DB inserts the
// single row. Returns an error only on a real DB failure; "row already
// exists" is the success case.
//
// The seed is always called from identity bootstrap.ApplySchema after
// the CREATE TABLE + ALTER passes complete; the function is deliberately
// db-driver-shaped (no Identity handle, no test-only hooks) so it
// composes with the package-level ApplySchema that testkit consumes.
func Tenants(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("seed.Tenants: db must not be nil")
	}
	_, err := db.ExecContext(ctx, `
		INSERT IGNORE INTO tenants (id, name, status)
		VALUES (?, ?, 'active')
	`, DefaultTenantID, DefaultTenantName)
	if err != nil {
		return fmt.Errorf("seed default tenant: %w", err)
	}
	return nil
}
