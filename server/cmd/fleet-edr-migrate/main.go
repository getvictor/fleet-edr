// Command fleet-edr-migrate applies every bounded context's database migrations against EDR_DSN and exits, without booting the
// server. It is the ops entry point for "apply the schema, then sanity-check before letting the server start" (issue #115,
// ADR-0009).
//
// Each context's package-level ApplySchema runs its goose corpus (identity additionally seeds the built-in roles); goose's
// per-context tracking tables make a re-run a no-op. Service-dependent seeds (the Default app-control policy, the admin account)
// are deliberately NOT run here: those stay the server's responsibility at boot, where the service layer that owns them is wired.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/bootstrap"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

// migration pairs a context name with its package-level schema applier. Ordering is not load-bearing (there are no cross-context
// FKs), but identity leads because it is the most foundational and this mirrors server/testdb/full's order.
type migration struct {
	context string
	apply   func(context.Context, *sqlx.DB) error
}

func migrations() []migration {
	return []migration{
		{"identity", identitybootstrap.ApplySchema},
		{"endpoint", endpointbootstrap.ApplySchema},
		{"rules", rulesbootstrap.ApplySchema},
		{"response", responsebootstrap.ApplySchema},
		{"detection", detectionbootstrap.ApplySchema},
	}
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "fleet-edr-migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	dsn := os.Getenv("EDR_DSN") //nolint:forbidigo // EDR_DSN is read at the cmd wiring boundary (the migrate entrypoint); see issue #172
	if dsn == "" {
		return errors.New("EDR_DSN must be set")
	}
	db, err := bootstrap.OpenDB(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()
	return applyAll(ctx, db, os.Stdout)
}

// applyAll runs every context's migrations against db, reporting progress to out. Separated from run so a test can drive it with
// an isolated test database instead of EDR_DSN.
func applyAll(ctx context.Context, db *sqlx.DB, out io.Writer) error {
	for _, m := range migrations() {
		if err := m.apply(ctx, db); err != nil {
			return fmt.Errorf("apply %s migrations: %w", m.context, err)
		}
		fmt.Fprintf(out, "fleet-edr-migrate: %s migrations applied\n", m.context)
	}
	fmt.Fprintln(out, "fleet-edr-migrate: all migrations applied")
	return nil
}
