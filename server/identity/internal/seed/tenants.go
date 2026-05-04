package seed

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
)

// DefaultTenantName is the human-facing name used in the seeded row
// and in any UI that resolves the default tenant. Operators may
// rename it post-seed; the seed is INSERT IGNORE so re-runs do not
// clobber an edited row.
//
// The id sentinel lives at api.DefaultTenantID so the public
// boundary owns the canonical value; the seed reads from there to
// avoid drift if the constant is ever renamed.
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
	`, api.DefaultTenantID, DefaultTenantName)
	if err != nil {
		return fmt.Errorf("seed default tenant: %w", err)
	}
	return nil
}
