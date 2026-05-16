package appcontrol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
)

// Store wraps the *sqlx.DB handle for the app_control_policies + app_control_rules tables. Constructed once by the rules bootstrap and
// shared across the REST handler, the fan-out path, and tests. Satisfies api.ApplicationControlStore.
type Store struct {
	db *sqlx.DB
}

// NewStore builds a Store. Panics if db is nil; cmd/main is the only caller and a nil db would mean a wiring bug, not a recoverable
// state.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("appcontrol.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

// EnsureDefaultPolicy idempotently seeds the Default policy. Safe to call on every server boot (Bootstrap does so). Uses INSERT IGNORE
// so a manual edit of the row's description or version is not clobbered on subsequent restarts.
func (s *Store) EnsureDefaultPolicy(ctx context.Context) error {
	const query = `INSERT IGNORE INTO app_control_policies
		(name, description, version, default_action, created_by, updated_by)
		VALUES (?, ?, 1, 'NONE', 'system', 'system')`
	if _, err := s.db.ExecContext(ctx, query,
		api.DefaultPolicyName,
		"Default application control policy. Add rules to block executables by SHA-256 hash.",
	); err != nil {
		return fmt.Errorf("appcontrol seed default policy: %w", err)
	}
	return nil
}

// GetPolicyByName loads the policy row by name. Rules are NOT populated; callers that need rules call ListRulesByPolicy explicitly.
// A future GetPolicyWithRules helper can join the two queries when an endpoint shows up that needs both in one round trip; today's
// REST surface fetches them separately.
func (s *Store) GetPolicyByName(ctx context.Context, name string) (api.ApplicationControlPolicy, error) {
	const query = `SELECT id, name, description, version, default_action,
		created_at, updated_at, created_by, updated_by
		FROM app_control_policies WHERE name = ?`
	row := s.db.QueryRowxContext(ctx, query, name)
	var p api.ApplicationControlPolicy
	if err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.Version, &p.DefaultAction,
		&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
		}
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol get policy: %w", err)
	}
	return p, nil
}

// ListPolicies returns every policy in name order. Rules are NOT populated; the list view shows the rule count only, which the REST
// handler computes via a separate aggregate query when it needs it.
func (s *Store) ListPolicies(ctx context.Context) ([]api.ApplicationControlPolicy, error) {
	const query = `SELECT id, name, description, version, default_action,
		created_at, updated_at, created_by, updated_by
		FROM app_control_policies ORDER BY name ASC`
	rows, err := s.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("appcontrol list policies: %w", err)
	}
	defer rows.Close()
	out := []api.ApplicationControlPolicy{}
	for rows.Next() {
		var p api.ApplicationControlPolicy
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Version, &p.DefaultAction,
			&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("appcontrol list policies scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appcontrol list policies rows: %w", err)
	}
	return out, nil
}

// ListRulesByPolicy returns every rule belonging to the policy in (rule_type, identifier) order so the response is deterministic and
// snapshot-testable.
func (s *Store) ListRulesByPolicy(ctx context.Context, policyID int64) ([]api.ApplicationControlRule, error) {
	const query = `SELECT id, policy_id, rule_type, identifier, action, enforcement, enabled,
		severity, source, source_ref, custom_msg, custom_url, comment, expires_at,
		created_at, updated_at, created_by
		FROM app_control_rules WHERE policy_id = ? ORDER BY rule_type, identifier`
	rows, err := s.db.QueryxContext(ctx, query, policyID)
	if err != nil {
		return nil, fmt.Errorf("appcontrol list rules: %w", err)
	}
	defer rows.Close()
	out := []api.ApplicationControlRule{}
	for rows.Next() {
		var r api.ApplicationControlRule
		var enabled int
		if err := rows.Scan(
			&r.ID, &r.PolicyID, &r.RuleType, &r.Identifier, &r.Action, &r.Enforcement, &enabled,
			&r.Severity, &r.Source, &r.SourceRef, &r.CustomMsg, &r.CustomURL, &r.Comment, &r.ExpiresAt,
			&r.CreatedAt, &r.UpdatedAt, &r.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("appcontrol list rules scan: %w", err)
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appcontrol list rules rows: %w", err)
	}
	return out, nil
}

// CreateRule inserts a new rule under the policy and bumps the
// owning policy's version inside a single transaction so the
// "version changes imply snapshot changes" contract cannot be broken
// by a partial failure between the insert and the bump.
//
// Validates rule_type, identifier, and severity before the INSERT.
// Validates that Actor and Reason are non-empty: every state-changing
// call has to be auditable, so the store rejects unattributed rules
// rather than papering over them with "system". Returns
// ErrAppControlDuplicateRule when a rule with the same
// (policy_id, rule_type, identifier) already exists, and
// ErrAppControlPolicyNotFound when policy_id does not exist (so the
// REST layer can map cleanly to HTTP 404 instead of 500).
func (s *Store) CreateRule(ctx context.Context, req api.CreateRuleRequest) (api.ApplicationControlRule, error) {
	if strings.TrimSpace(req.Actor) == "" {
		return api.ApplicationControlRule{}, fmt.Errorf("%w: actor is required", api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return api.ApplicationControlRule{}, fmt.Errorf("%w: reason is required", api.ErrAppControlInvalidRequest)
	}
	if err := ValidateRuleType(req.RuleType); err != nil {
		return api.ApplicationControlRule{}, err
	}
	if err := ValidateIdentifier(req.RuleType, req.Identifier); err != nil {
		return api.ApplicationControlRule{}, err
	}
	if err := ValidateSeverity(req.Severity); err != nil {
		return api.ApplicationControlRule{}, err
	}
	severity := req.Severity
	if severity == "" {
		severity = api.SeverityRuleMedium
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol begin tx: %w", err)
	}
	// Deferred rollback is a no-op once Commit has run; the early
	// returns below leave the transaction to roll back here.
	defer func() { _ = tx.Rollback() }()

	const insert = `INSERT INTO app_control_rules
		(policy_id, rule_type, identifier, action, enforcement, enabled, severity, source, custom_msg, custom_url, comment, created_by)
		VALUES (?, ?, ?, 'BLOCK', 'PROTECT', 1, ?, 'admin', ?, ?, ?, ?)`
	res, err := tx.ExecContext(ctx, insert,
		req.PolicyID, req.RuleType, req.Identifier, severity,
		req.CustomMsg, req.CustomURL, req.Comment, req.Actor,
	)
	if err != nil {
		switch {
		case isDuplicateKey(err):
			return api.ApplicationControlRule{}, api.ErrAppControlDuplicateRule
		case isForeignKeyViolation(err):
			return api.ApplicationControlRule{}, api.ErrAppControlPolicyNotFound
		default:
			return api.ApplicationControlRule{}, fmt.Errorf("appcontrol create rule: %w", err)
		}
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol create rule lastid: %w", err)
	}
	// Bump the policy version so the agent sees a fresh value on its next snapshot apply. The application-control fan-out also keys on
	// this for at-most-once dispatch in the follow-on REST handler task; lifting it into the same transaction as the insert keeps the
	// "version changes imply snapshot changes" contract atomic.
	if _, err := tx.ExecContext(ctx, `UPDATE app_control_policies
		SET version = version + 1, updated_by = ?
		WHERE id = ?`, req.Actor, req.PolicyID); err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol bump policy version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol commit tx: %w", err)
	}
	return s.getRuleByID(ctx, ruleID)
}

func (s *Store) getRuleByID(ctx context.Context, id int64) (api.ApplicationControlRule, error) {
	const query = `SELECT id, policy_id, rule_type, identifier, action, enforcement, enabled,
		severity, source, source_ref, custom_msg, custom_url, comment, expires_at,
		created_at, updated_at, created_by
		FROM app_control_rules WHERE id = ?`
	row := s.db.QueryRowxContext(ctx, query, id)
	var r api.ApplicationControlRule
	var enabled int
	if err := row.Scan(
		&r.ID, &r.PolicyID, &r.RuleType, &r.Identifier, &r.Action, &r.Enforcement, &enabled,
		&r.Severity, &r.Source, &r.SourceRef, &r.CustomMsg, &r.CustomURL, &r.Comment, &r.ExpiresAt,
		&r.CreatedAt, &r.UpdatedAt, &r.CreatedBy,
	); err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol get rule: %w", err)
	}
	r.Enabled = enabled != 0
	return r, nil
}

// MySQL error numbers we care about. Documented at
// https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
const (
	mysqlDuplicateEntry      = 1062
	mysqlForeignKeyViolation = 1452
)

// isDuplicateKey is the MySQL-driver-agnostic check for the duplicate-entry error. Stays as a small helper so a future driver swap
// only touches this one site.
func isDuplicateKey(err error) bool {
	return isMySQLErrorNumber(err, mysqlDuplicateEntry) || errStringContains(err, "Duplicate entry")
}

// isForeignKeyViolation detects the MySQL "cannot add or update a child row: a foreign key constraint fails" error (1452). The only FK
// on app_control_rules is policy_id → app_control_policies(id), so a 1452 unambiguously means the caller's PolicyID is missing.
func isForeignKeyViolation(err error) bool {
	return isMySQLErrorNumber(err, mysqlForeignKeyViolation) ||
		errStringContains(err, "foreign key constraint fails")
}

func isMySQLErrorNumber(err error, num uint16) bool {
	if err == nil {
		return false
	}
	type mysqlError interface{ Number() uint16 }
	var mErr mysqlError
	if errors.As(err, &mErr) && mErr.Number() == num {
		return true
	}
	return false
}

func errStringContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), substr)
}
