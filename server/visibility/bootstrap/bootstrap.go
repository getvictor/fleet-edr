package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/migrations/runner"
	"github.com/fleetdm/edr/server/visibility/api"
	"github.com/fleetdm/edr/server/visibility/internal/clickhouse"
	"github.com/fleetdm/edr/server/visibility/internal/eventlog"
	visibilitymigrations "github.com/fleetdm/edr/server/visibility/migrations"
	migrationsclickhouse "github.com/fleetdm/edr/server/visibility/migrations-clickhouse"
)

// Deps bundles what New needs to wire the visibility context.
type Deps struct {
	// DB is the MySQL pool backing the EventLog work queue and the control plane. Required.
	DB *sqlx.DB
	// ClickHouseDB is the ClickHouse pool backing the EventArchive (opened via clickhouse.Open). Optional: when nil, the context runs
	// without an archive (queue only) and EventArchive returns nil. The cutover wires it in cmd/main.
	ClickHouseDB *sqlx.DB
	Logger       *slog.Logger
}

// Visibility is the handle cmd/main holds for the visibility context.
type Visibility struct {
	eventLog     *eventlog.Store
	eventArchive *clickhouse.Store
	db           *sqlx.DB
	chDB         *sqlx.DB
	logger       *slog.Logger
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
	v := &Visibility{eventLog: el, db: deps.DB, chDB: deps.ClickHouseDB, logger: logger}
	if deps.ClickHouseDB != nil {
		archive, err := clickhouse.New(deps.ClickHouseDB)
		if err != nil {
			return nil, fmt.Errorf("visibility bootstrap: %w", err)
		}
		v.eventArchive = archive
	}
	return v, nil
}

// EventLog returns the durable work queue that decouples ingestion from detection processing.
func (v *Visibility) EventLog() api.EventLog { return v.eventLog }

// EventArchive returns the durable event lake, or nil when no ClickHouse connection was provided.
func (v *Visibility) EventArchive() api.EventArchive {
	if v.eventArchive == nil {
		return nil
	}
	return v.eventArchive
}

// ApplySchema runs visibility's migrations: the MySQL queue always, and the ClickHouse event archive when a ClickHouse connection was
// provided. Idempotent.
func (v *Visibility) ApplySchema(ctx context.Context) error {
	if err := ApplySchema(ctx, v.db); err != nil {
		return err
	}
	if v.chDB != nil {
		return ApplyClickHouseSchema(ctx, v.chDB)
	}
	return nil
}

// ApplySchema is the package-level form: applies visibility's MySQL goose migration corpus (the event_queue) against db. Used by the
// test fixture composer. Idempotent (goose skips already-applied versions).
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("visibility ApplySchema: db must not be nil")
	}
	return runner.Up(ctx, db, visibilitymigrations.FS, runner.Options{
		Context:   "visibility",
		TableName: "visibility_goose_db_version",
	})
}

// ApplyClickHouseSchema applies the event-archive ClickHouse migration corpus against chDB. Idempotent.
func ApplyClickHouseSchema(ctx context.Context, chDB *sqlx.DB) error {
	if chDB == nil {
		return errors.New("visibility ApplyClickHouseSchema: db must not be nil")
	}
	return runner.Up(ctx, chDB, migrationsclickhouse.FS, runner.Options{
		Context:   "visibility",
		TableName: "visibility_clickhouse_goose_db_version",
		Dialect:   runner.DialectClickHouse,
	})
}
