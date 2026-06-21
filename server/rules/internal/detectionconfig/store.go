package detectionconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
)

// ErrInvalidRequest is returned when a mutation carries an invalid match type, mode, or a missing required field. REST handlers map
// it to HTTP 400.
var ErrInvalidRequest = errors.New("detectionconfig: invalid request")

// Store persists and reads the detection-config tables (detection_rule_settings, detection_exclusions) plus the detection_config_meta
// version counter. Every mutation bumps the version in the same transaction so a reader can detect a change and reload the in-memory
// Snapshot. The rules bootstrap constructs it and shares it with the REST handler + the snapshot-reload path.
type Store struct {
	db *sqlx.DB
}

// NewStore builds a Store. Panics on a nil db: cmd/main is the only production caller and a nil handle is a wiring bug, not a
// recoverable state.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("detectionconfig.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

// CreateExclusionInput is the create-exclusion contract. HostGroupID is api.GlobalScope for a global entry. Actor is recorded as
// created_by.
type CreateExclusionInput struct {
	RuleID      string
	MatchType   api.ExclusionMatchType
	Value       string
	HostGroupID int64
	Reason      string
	ExpiresAt   *time.Time
	Actor       string
}

// UpsertSettingInput is the upsert-per-(rule, scope)-setting contract.
type UpsertSettingInput struct {
	RuleID           string
	HostGroupID      int64
	Mode             api.DetectionRuleMode
	SeverityOverride string
	Settings         api.NullRawJSON
	Actor            string
}

// Version returns the current detection-config version. A reader compares it against the version its cached Snapshot was loaded at to
// decide whether to reload.
func (s *Store) Version(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.GetContext(ctx, &v, `SELECT version FROM detection_config_meta WHERE id = 1`); err != nil {
		return 0, fmt.Errorf("detectionconfig version: %w", err)
	}
	return v, nil
}

// LoadSnapshot reads the enabled exclusions + all rule settings at the current version and returns an immutable Snapshot. membership
// and clock are passed through to the snapshot (nil clock defaults to time.Now).
func (s *Store) LoadSnapshot(ctx context.Context, membership Membership, clock func() time.Time) (*Snapshot, error) {
	version, err := s.Version(ctx)
	if err != nil {
		return nil, err
	}
	exclusions, err := s.listExclusions(ctx, true)
	if err != nil {
		return nil, err
	}
	settings, err := s.ListRuleSettings(ctx)
	if err != nil {
		return nil, err
	}
	return NewSnapshot(version, exclusions, settings, membership, clock), nil
}

// ListExclusions returns every exclusion row (enabled and disabled) for the operator surface, newest first.
func (s *Store) ListExclusions(ctx context.Context) ([]api.DetectionExclusion, error) {
	return s.listExclusions(ctx, false)
}

func (s *Store) listExclusions(ctx context.Context, enabledOnly bool) ([]api.DetectionExclusion, error) {
	q := `SELECT id, rule_id, match_type, value, host_group_id,
		reason, enabled, expires_at, created_by, created_at
		FROM detection_exclusions`
	if enabledOnly {
		q += ` WHERE enabled = 1`
	}
	q += ` ORDER BY id DESC`
	var out []api.DetectionExclusion
	if err := s.db.SelectContext(ctx, &out, q); err != nil {
		return nil, fmt.Errorf("detectionconfig list exclusions: %w", err)
	}
	return out, nil
}

// ListRuleSettings returns every per-rule setting row.
func (s *Store) ListRuleSettings(ctx context.Context) ([]api.DetectionRuleSetting, error) {
	const q = `SELECT id, rule_id, host_group_id, mode,
		COALESCE(severity_override, '') AS severity_override, settings, updated_by, updated_at
		FROM detection_rule_settings ORDER BY rule_id, host_group_id`
	var out []api.DetectionRuleSetting
	if err := s.db.SelectContext(ctx, &out, q); err != nil {
		return nil, fmt.Errorf("detectionconfig list settings: %w", err)
	}
	return out, nil
}

// CreateExclusion inserts an exclusion and bumps the config version atomically.
func (s *Store) CreateExclusion(ctx context.Context, in CreateExclusionInput) (api.DetectionExclusion, error) {
	if !api.IsValidExclusionMatchType(in.MatchType) {
		return api.DetectionExclusion{}, fmt.Errorf("%w: match_type %q", ErrInvalidRequest, in.MatchType)
	}
	if in.Value == "" {
		return api.DetectionExclusion{}, fmt.Errorf("%w: value is required", ErrInvalidRequest)
	}
	if in.Actor == "" {
		return api.DetectionExclusion{}, fmt.Errorf("%w: actor is required", ErrInvalidRequest)
	}
	var id int64
	err := s.inTx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO detection_exclusions (rule_id, match_type, value, host_group_id, reason, expires_at, created_by)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			in.RuleID, in.MatchType, in.Value, in.HostGroupID, in.Reason, in.ExpiresAt, in.Actor)
		if err != nil {
			return fmt.Errorf("insert exclusion: %w", err)
		}
		id, err = res.LastInsertId()
		if err != nil {
			return fmt.Errorf("exclusion last insert id: %w", err)
		}
		return bumpVersion(ctx, tx)
	})
	if err != nil {
		return api.DetectionExclusion{}, err
	}
	return s.getExclusion(ctx, id)
}

// DeleteExclusion removes an exclusion and bumps the version. Returns sql.ErrNoRows when the id does not exist.
func (s *Store) DeleteExclusion(ctx context.Context, id int64) error {
	return s.inTx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM detection_exclusions WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("delete exclusion: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("delete exclusion rows: %w", err)
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		return bumpVersion(ctx, tx)
	})
}

// UpsertRuleSetting inserts or updates the setting for (rule, scope) and bumps the version. The unique key (rule_id, host_group_id)
// drives the upsert, so re-setting the same scope flips the row in place rather than creating a duplicate.
func (s *Store) UpsertRuleSetting(ctx context.Context, in UpsertSettingInput) (api.DetectionRuleSetting, error) {
	if !api.IsValidDetectionRuleMode(in.Mode) {
		return api.DetectionRuleSetting{}, fmt.Errorf("%w: mode %q", ErrInvalidRequest, in.Mode)
	}
	if in.RuleID == "" {
		return api.DetectionRuleSetting{}, fmt.Errorf("%w: rule_id is required", ErrInvalidRequest)
	}
	if in.Actor == "" {
		return api.DetectionRuleSetting{}, fmt.Errorf("%w: actor is required", ErrInvalidRequest)
	}
	var severity any
	if in.SeverityOverride != "" {
		severity = in.SeverityOverride
	}
	err := s.inTx(ctx, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, severity_override, settings, updated_by)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE mode = VALUES(mode), severity_override = VALUES(severity_override),
			 settings = VALUES(settings), updated_by = VALUES(updated_by)`,
			in.RuleID, in.HostGroupID, in.Mode, severity, in.Settings, in.Actor)
		if err != nil {
			return fmt.Errorf("upsert rule setting: %w", err)
		}
		return bumpVersion(ctx, tx)
	})
	if err != nil {
		return api.DetectionRuleSetting{}, err
	}
	return s.getRuleSetting(ctx, in.RuleID, in.HostGroupID)
}

func (s *Store) getExclusion(ctx context.Context, id int64) (api.DetectionExclusion, error) {
	var e api.DetectionExclusion
	err := s.db.GetContext(ctx, &e,
		`SELECT id, rule_id, match_type, value, host_group_id,
		 reason, enabled, expires_at, created_by, created_at FROM detection_exclusions WHERE id = ?`, id)
	if err != nil {
		return api.DetectionExclusion{}, fmt.Errorf("detectionconfig get exclusion: %w", err)
	}
	return e, nil
}

func (s *Store) getRuleSetting(ctx context.Context, ruleID string, hostGroupID int64) (api.DetectionRuleSetting, error) {
	var st api.DetectionRuleSetting
	err := s.db.GetContext(ctx, &st,
		`SELECT id, rule_id, host_group_id, mode,
		 COALESCE(severity_override, '') AS severity_override, settings, updated_by, updated_at
		 FROM detection_rule_settings WHERE rule_id = ? AND host_group_id = ?`, ruleID, hostGroupID)
	if err != nil {
		return api.DetectionRuleSetting{}, fmt.Errorf("detectionconfig get setting: %w", err)
	}
	return st, nil
}

// inTx runs fn in a transaction, committing on success and rolling back on error.
func (s *Store) inTx(ctx context.Context, fn func(tx *sqlx.Tx) error) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("detectionconfig begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("detectionconfig commit tx: %w", err)
	}
	return nil
}

// bumpVersion increments the single-row version counter inside the caller's tx.
func bumpVersion(ctx context.Context, tx *sqlx.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE detection_config_meta SET version = version + 1 WHERE id = 1`); err != nil {
		return fmt.Errorf("bump detection-config version: %w", err)
	}
	return nil
}
