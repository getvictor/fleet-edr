package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/visibility/api"
	"github.com/fleetdm/edr/server/visibility/internal/eventlog"
	visibilitymigrations "github.com/fleetdm/edr/server/visibility/migrations"
)

// Deps bundles what New needs to wire the visibility context.
type Deps struct {
	DB     *sqlx.DB
	Logger *slog.Logger
}

// Visibility is the handle cmd/main holds for the visibility context.
type Visibility struct {
	eventLog *eventlog.Store
	db       *sqlx.DB
	logger   *slog.Logger
}

// New wires the visibility context. It does NOT apply the schema (call ApplySchema).
func New(deps Deps) (*Visibility, error) {
	if deps.DB == nil {
		return nil, errors.New("visibility bootstrap: DB is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	el, err := eventlog.New(deps.DB)
	if err != nil {
		return nil, fmt.Errorf("visibility bootstrap: %w", err)
	}
	return &Visibility{eventLog: el, db: deps.DB, logger: logger}, nil
}

// EventLog returns the durable work queue that decouples ingestion from detection processing.
func (v *Visibility) EventLog() api.EventLog { return v.eventLog }

// ApplySchema runs visibility's migrations against the context's DB. Idempotent.
func (v *Visibility) ApplySchema(ctx context.Context) error { return ApplySchema(ctx, v.db) }

// ApplySchema is the package-level form: applies visibility's goose migration corpus against db without a fully constructed
// *Visibility. Used by the test fixture composer. Idempotent (goose skips already-applied versions).
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("visibility ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, visibilitymigrations.FS, runner.Options{
		Context:   "visibility",
		TableName: "visibility_goose_db_version",
	})
}
