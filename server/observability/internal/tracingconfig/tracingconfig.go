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

// GetTraceSamplerSettings returns the singleton settings. The row is seeded by migration, so it normally always exists; if it is
// somehow absent the built-in defaults are returned (not an error) so both the poller and the admin API stay functional on a fresh or
// partially-migrated deployment. Satisfies tracing.SettingsReader.
func (s *Store) GetTraceSamplerSettings(ctx context.Context) (*tracing.Settings, error) {
	var out tracing.Settings
	err := s.db.GetContext(ctx, &out,
		`SELECT high_volume_ratio, standard_ratio, force_full, updated_at FROM trace_sampler_settings WHERE id = 1`)
	if errors.Is(err, sql.ErrNoRows) {
		return &tracing.Settings{
			HighVolumeRatio: tracing.DefaultHighVolumeRatio,
			StandardRatio:   tracing.DefaultStandardRatio,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tracingconfig: get: %w", err)
	}
	return &out, nil
}

// Update writes the singleton row (upsert so a missing row self-heals). The caller validates the ratios are in [0,1]; the DB CHECK
// constraints are the backstop. updatedBy records the operator user id as a breadcrumb (nil for a non-operator write).
func (s *Store) Update(ctx context.Context, settings tracing.Settings, updatedBy *int64) error {
	var by sql.NullInt64
	if updatedBy != nil {
		by = sql.NullInt64{Int64: *updatedBy, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO trace_sampler_settings (id, high_volume_ratio, standard_ratio, force_full, updated_by)
		VALUES (1, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			high_volume_ratio = VALUES(high_volume_ratio),
			standard_ratio = VALUES(standard_ratio),
			force_full = VALUES(force_full),
			updated_by = VALUES(updated_by)`,
		settings.HighVolumeRatio, settings.StandardRatio, settings.ForceFull, by)
	if err != nil {
		return fmt.Errorf("tracingconfig: update: %w", err)
	}
	return nil
}
