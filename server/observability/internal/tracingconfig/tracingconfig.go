// Package tracingconfig owns the trace_sampler_settings singleton row: the deployment's runtime OTel trace head-sampling
// configuration (issue #374). It is the persistence + read accessor behind the super-admin settings API and the per-replica sampler
// poller. The domain type (tracing.Settings) lives in internal/observability/tracing so the sampler, the poller, and this store all
// agree on one shape; this package only reads and writes it.
package tracingconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/internal/observability/tracing"
)

// ErrVersionConflict is returned by Update when the row's version no longer matches the expected version (a concurrent write landed
// between the caller's Get and Update). The handler maps it to 409 so the operator re-reads and retries. This is the guard the version
// column exists for (optimistic concurrency), mirroring appconfig.
var ErrVersionConflict = errors.New("tracingconfig: version conflict")

// Store owns the singleton trace_sampler_settings row.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store. Panics if db is nil.
func New(db *sqlx.DB) *Store {
	if db == nil {
		panic("tracingconfig.New: db must not be nil")
	}
	return &Store{db: db}
}

// Get returns the singleton settings and the row version for an optimistic-concurrency Update. The row is seeded by migration, so it
// normally always exists; if it is somehow absent the built-in defaults are returned with version 0 (not an error) so both the poller
// and the admin API stay functional on a fresh or partially-migrated deployment.
func (s *Store) Get(ctx context.Context) (*tracing.Settings, int64, error) {
	var row struct {
		tracing.Settings
		Version int64 `db:"version"`
	}
	err := s.db.GetContext(ctx, &row,
		`SELECT high_volume_ratio, standard_ratio, force_full, updated_at, version FROM trace_sampler_settings WHERE id = 1`)
	if errors.Is(err, sql.ErrNoRows) {
		return &tracing.Settings{
			HighVolumeRatio: tracing.DefaultHighVolumeRatio,
			StandardRatio:   tracing.DefaultStandardRatio,
		}, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("tracingconfig: get: %w", err)
	}
	out := row.Settings
	return &out, row.Version, nil
}

// GetTraceSamplerSettings returns just the settings, dropping the version. It satisfies tracing.SettingsReader for the per-replica
// poller, which needs the values but not the concurrency token.
func (s *Store) GetTraceSamplerSettings(ctx context.Context) (*tracing.Settings, error) {
	settings, _, err := s.Get(ctx)
	return settings, err
}

// Update writes the singleton row with optimistic concurrency: it succeeds only when the stored version still matches expectedVersion,
// returning ErrVersionConflict otherwise so a concurrent PATCH cannot silently clobber a peer's write. expectedVersion 0 means "no row
// yet" and inserts the singleton (idempotent under a concurrent first write). The caller validates the ratios are in [0,1]; the DB
// CHECK constraints are the backstop. updatedBy records the operator user id as a breadcrumb (nil for a non-operator write).
func (s *Store) Update(ctx context.Context, settings tracing.Settings, expectedVersion int64, updatedBy *int64) error {
	var by sql.NullInt64
	if updatedBy != nil {
		by = sql.NullInt64{Int64: *updatedBy, Valid: true}
	}
	if expectedVersion <= 0 {
		// First write: insert the singleton. ON DUPLICATE KEY UPDATE keeps a concurrent first write idempotent.
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO trace_sampler_settings (id, high_volume_ratio, standard_ratio, force_full, version, updated_by)
			VALUES (1, ?, ?, ?, 1, ?)
			ON DUPLICATE KEY UPDATE
				high_volume_ratio = VALUES(high_volume_ratio),
				standard_ratio = VALUES(standard_ratio),
				force_full = VALUES(force_full),
				version = version + 1,
				updated_by = VALUES(updated_by)`,
			settings.HighVolumeRatio, settings.StandardRatio, settings.ForceFull, by)
		if err != nil {
			return fmt.Errorf("tracingconfig: update insert: %w", err)
		}
		return nil
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE trace_sampler_settings
		SET high_volume_ratio = ?, standard_ratio = ?, force_full = ?, version = version + 1, updated_by = ?
		WHERE id = 1 AND version = ?`,
		settings.HighVolumeRatio, settings.StandardRatio, settings.ForceFull, by, expectedVersion)
	if err != nil {
		return fmt.Errorf("tracingconfig: update: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("tracingconfig: update rows-affected: %w", err)
	}
	if rows == 0 {
		return ErrVersionConflict
	}
	return nil
}
