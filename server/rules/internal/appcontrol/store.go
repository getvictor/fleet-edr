package appcontrol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
)

// Store wraps the *sqlx.DB handle for the app_control_policies +
// app_control_rules tables. Constructed once by the rules bootstrap
// and shared across the REST handler, the fan-out path, and tests.
type Store struct {
	db *sqlx.DB
}

// NewStore builds a Store. Panics if db is nil; cmd/main is the only
// caller and a nil db would mean a wiring bug, not a recoverable
// state.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("appcontrol.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

// EnsureDefaultPolicy idempotently seeds the per-tenant Default
// policy. Safe to call on every server boot (Bootstrap does so). Uses
// INSERT IGNORE so a manual edit of the row's description or version
// is not clobbered on subsequent restarts.
func (s *Store) EnsureDefaultPolicy(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		tenantID = "default"
	}
	const query = `INSERT IGNORE INTO app_control_policies
		(tenant_id, name, description, version, default_action, created_by, updated_by)
		VALUES (?, ?, ?, 1, 'NONE', 'system', 'system')`
	if _, err := s.db.ExecContext(ctx, query,
		tenantID, api.DefaultPolicyName,
		"Per-tenant default application control policy. Add rules to block executables by SHA-256 hash.",
	); err != nil {
		return fmt.Errorf("appcontrol seed default policy: %w", err)
	}
	return nil
}

// GetPolicyByName loads the policy row by (tenant_id, name). Rules
// are NOT populated; callers that need rules either call
// ListRulesByPolicy explicitly or use GetPolicyWithRules.
func (s *Store) GetPolicyByName(ctx context.Context, tenantID, name string) (api.ApplicationControlPolicy, error) {
	const query = `SELECT id, tenant_id, name, description, version, default_action,
		created_at, updated_at, created_by, updated_by
		FROM app_control_policies WHERE tenant_id = ? AND name = ?`
	row := s.db.QueryRowxContext(ctx, query, tenantID, name)
	var p api.ApplicationControlPolicy
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Version, &p.DefaultAction,
		&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
		}
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol get policy: %w", err)
	}
	return p, nil
}

// ListPolicies returns every policy for the tenant in name order.
// Rules are NOT populated; the list view shows the rule count only,
// which the REST handler computes via a separate aggregate query
// when it needs it.
func (s *Store) ListPolicies(ctx context.Context, tenantID string) ([]api.ApplicationControlPolicy, error) {
	const query = `SELECT id, tenant_id, name, description, version, default_action,
		created_at, updated_at, created_by, updated_by
		FROM app_control_policies WHERE tenant_id = ? ORDER BY name ASC`
	rows, err := s.db.QueryxContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("appcontrol list policies: %w", err)
	}
	defer rows.Close()
	out := []api.ApplicationControlPolicy{}
	for rows.Next() {
		var p api.ApplicationControlPolicy
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Version, &p.DefaultAction,
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

// ListRulesByPolicy returns every rule belonging to the policy in
// (rule_type, identifier) order so the response is deterministic and
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

// CreateRule inserts a new rule under the named policy. Validates
// rule_type, identifier, and severity before the INSERT. Returns
// ErrAppControlDuplicateRule when a rule with the same
// (policy_id, rule_type, identifier) already exists.
func (s *Store) CreateRule(ctx context.Context, req api.CreateRuleRequest) (api.ApplicationControlRule, error) {
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
	createdBy := req.Actor
	if createdBy == "" {
		createdBy = "system"
	}
	const insert = `INSERT INTO app_control_rules
		(policy_id, rule_type, identifier, action, enforcement, enabled, severity, source, custom_msg, custom_url, comment, created_by)
		VALUES (?, ?, ?, 'BLOCK', 'PROTECT', 1, ?, 'admin', ?, ?, ?, ?)`
	res, err := s.db.ExecContext(ctx, insert,
		req.PolicyID, req.RuleType, req.Identifier, severity,
		req.CustomMsg, req.CustomURL, req.Comment, createdBy,
	)
	if err != nil {
		if isDuplicateKey(err) {
			return api.ApplicationControlRule{}, api.ErrAppControlDuplicateRule
		}
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol create rule: %w", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol create rule lastid: %w", err)
	}
	// Bump the policy version so the agent sees a fresh value on its
	// next snapshot apply. The application-control fan-out also keys
	// on this for at-most-once dispatch in the follow-on REST handler
	// task; lifting it into the store keeps every code path
	// consistent.
	if _, err := s.db.ExecContext(ctx, `UPDATE app_control_policies
		SET version = version + 1, updated_by = ?
		WHERE id = ?`, createdBy, req.PolicyID); err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol bump policy version: %w", err)
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

// isDuplicateKey is the MySQL-driver-agnostic check for the
// duplicate-entry error. Stays as a small helper so a future driver
// swap only touches this one site.
func isDuplicateKey(err error) bool {
	if err == nil {
		return false
	}
	const mysqlDuplicateEntry = 1062
	type mysqlError interface{ Number() uint16 }
	var mErr mysqlError
	if errors.As(err, &mErr) && mErr.Number() == mysqlDuplicateEntry {
		return true
	}
	// Fallback for drivers that don't expose Number(): the canonical
	// error message contains "Duplicate entry".
	return errStringContains(err, "Duplicate entry")
}

func errStringContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), substr)
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
