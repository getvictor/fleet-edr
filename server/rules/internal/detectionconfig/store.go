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

// SQL shared by the *Store (whole-DB) read methods and the read transaction LoadSnapshot uses, so a query change lands once and the
// duplicate-literal linter stays quiet. The exclusion select takes an optional `WHERE enabled = 1` suffix.
const (
	sqlSelectVersion    = `SELECT version FROM detection_config_meta WHERE id = 1`
	sqlSelectExclusions = `SELECT id, rule_id, match_type, value, host_group_id, reason, enabled, expires_at, created_by, created_at
		FROM detection_exclusions`
	sqlSelectSettings = `SELECT id, rule_id, host_group_id, mode, COALESCE(severity_override, '') AS severity_override,
		settings, updated_by, updated_at FROM detection_rule_settings ORDER BY rule_id, host_group_id`
)

// readVersion / readExclusions / readSettings run against any sqlx querier (the whole *Store DB or a read transaction), so a
// consistent snapshot can read all three under one transaction.
func readVersion(ctx context.Context, q sqlx.QueryerContext) (int64, error) {
	var v int64
	if err := sqlx.GetContext(ctx, q, &v, sqlSelectVersion); err != nil {
		return 0, fmt.Errorf("detectionconfig version: %w", err)
	}
	return v, nil
}

func readExclusions(ctx context.Context, q sqlx.QueryerContext, enabledOnly bool) ([]api.DetectionExclusion, error) {
	query := sqlSelectExclusions
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY id DESC`
	var out []api.DetectionExclusion
	if err := sqlx.SelectContext(ctx, q, &out, query); err != nil {
		return nil, fmt.Errorf("detectionconfig list exclusions: %w", err)
	}
	return out, nil
}

func readSettings(ctx context.Context, q sqlx.QueryerContext) ([]api.DetectionRuleSetting, error) {
	var out []api.DetectionRuleSetting
	if err := sqlx.SelectContext(ctx, q, &out, sqlSelectSettings); err != nil {
		return nil, fmt.Errorf("detectionconfig list settings: %w", err)
	}
	return out, nil
}

// Version returns the current detection-config version. A reader compares it against the version its cached Snapshot was loaded at to
// decide whether to reload.
func (s *Store) Version(ctx context.Context) (int64, error) { return readVersion(ctx, s.db) }

// LoadSnapshot reads the enabled exclusions + all rule settings + the version under a single read transaction so the snapshot is a
// consistent point-in-time view: a concurrent mutation that bumps the version cannot interleave between the three reads and yield a
// version that disagrees with the rows. membership and clock are passed through to the snapshot (nil clock defaults to time.Now).
func (s *Store) LoadSnapshot(ctx context.Context, membership Membership, clock func() time.Time) (*Snapshot, error) {
	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("detectionconfig begin read tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	version, err := readVersion(ctx, tx)
	if err != nil {
		return nil, err
	}
	exclusions, err := readExclusions(ctx, tx, true)
	if err != nil {
		return nil, err
	}
	settings, err := readSettings(ctx, tx)
	if err != nil {
		return nil, err
	}
	return NewSnapshot(version, exclusions, settings, membership, clock), nil
}

// ListExclusions returns every exclusion row (enabled and disabled) for the operator surface, newest first.
func (s *Store) ListExclusions(ctx context.Context) ([]api.DetectionExclusion, error) {
	return readExclusions(ctx, s.db, false)
}

// ListRuleSettings returns every per-rule setting row.
func (s *Store) ListRuleSettings(ctx context.Context) ([]api.DetectionRuleSetting, error) {
	return readSettings(ctx, s.db)
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
	// Validate the optional severity override in Go: the column is an ENUM, so an unrecognised value would otherwise surface as an
	// opaque SQL error (HTTP 500) rather than a clean ErrInvalidRequest (HTTP 400).
	var severity any
	if in.SeverityOverride != "" {
		if !api.IsValidSeverity(api.Severity(in.SeverityOverride)) {
			return api.DetectionRuleSetting{}, fmt.Errorf("%w: severity_override %q", ErrInvalidRequest, in.SeverityOverride)
		}
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

// inTx runs fn in a transaction, committing on success and rolling back otherwise. The deferred rollback guarantees cleanup even if
// fn panics or returns early; after a successful Commit the rollback is a no-op (ErrTxDone), which is ignored.
func (s *Store) inTx(ctx context.Context, fn func(tx *sqlx.Tx) error) (err error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("detectionconfig begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("detectionconfig commit tx: %w", err)
	}
	return nil
}

// bumpVersion increments the single-row version counter inside the caller's tx. A zero-rows-affected update means the seeded
// detection_config_meta row (id=1) is missing, which would silently break the cache-invalidation contract (readers would never see a
// version change), so it is treated as an error that rolls the mutation back rather than committing an un-versioned write.
func bumpVersion(ctx context.Context, tx *sqlx.Tx) error {
	res, err := tx.ExecContext(ctx, `UPDATE detection_config_meta SET version = version + 1 WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("bump detection-config version: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("bump detection-config version rows: %w", err)
	}
	if n == 0 {
		return errors.New("detectionconfig: meta version row (id=1) missing; cannot bump version")
	}
	return nil
}
