// Package runner applies a bounded context's embedded SQL migration corpus at boot, wrapping pressly/goose.
//
// Each bounded context (ADR-0004) owns its own migration directory under server/<context>/migrations/ and its own goose tracking
// table, so contexts migrate independently and the per-context ownership boundary is preserved. A context's bootstrap calls Up
// once at boot from its package-level ApplySchema; the same path runs in tests via that context's testkit, so the goose corpus is
// exercised on every fresh test database.
//
// See docs/adr/0009-migrations-via-goose.md for the decision and the forward-only + tiered (expand-contract for Tier 2) policy
// that governs the migration files this runner applies.
package runner

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
)

// Options configures a single context's migration run.
type Options struct {
	// Context is the bounded-context name (e.g. "identity"). Used only to prefix errors so a boot failure names the context that
	// owns the offending migration.
	Context string

	// TableName is the per-context goose tracking table (e.g. "identity_goose_db_version"). Each context records its own applied
	// versions here so the corpora stay independent. It MUST be stable for the life of a deployment: renaming it strands the
	// applied-version history and goose would re-run every migration against an already-migrated database.
	TableName string
}

// Up applies every not-yet-applied migration in fsys against db, recording applied versions in opts.TableName. It is idempotent:
// a call with no new migration files is a no-op that returns nil, which is what makes it safe to run on every boot and what keeps
// the existing "second ApplySchema re-apply succeeds" integration tests green.
//
// fsys must contain goose SQL files named NNNNN_name.sql at its root, which is exactly what a context's `//go:embed *.sql`
// produces. Applying the frozen CREATE TABLE IF NOT EXISTS baseline (00001_initial.sql) against a database that already carries
// those tables from the pre-goose in-process ApplySchema is safe: the CREATE statements no-op and goose simply records version 1,
// which is the migration path for a deployment upgrading off the legacy schema.
//
// Up does NOT take a distributed lock. Under a single-replica boot that is sufficient. The multi-replica rolling-upgrade path
// wraps the whole boot migration sequence in a single MySQL advisory lock at the cmd layer (see the HA arc) so exactly one replica
// applies migrations during a cutover; goose's tracking table then makes every other replica's apply a no-op.
func Up(ctx context.Context, db *sqlx.DB, fsys fs.FS, opts Options) error {
	if db == nil {
		return fmt.Errorf("%s migrations: db must not be nil", opts.Context)
	}
	if opts.TableName == "" {
		return fmt.Errorf("%s migrations: table name must not be empty", opts.Context)
	}

	provider, err := goose.NewProvider(goose.DialectMySQL, db.DB, fsys,
		goose.WithTableName(opts.TableName),
		goose.WithVerbose(false),
	)
	if err != nil {
		return fmt.Errorf("%s migrations: build provider: %w", opts.Context, err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("%s migrations: apply: %w", opts.Context, err)
	}
	return nil
}
