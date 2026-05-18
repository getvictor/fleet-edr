package appcontrol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
)

// Error-message format strings shared by every state-changing store method. Extracted to constants so Sonar's duplicate-literal rule
// (go:S1192) stays quiet AND so a wording change here propagates uniformly across CreateRule / UpdateRule / DeleteRule / CreatePolicy
// / UpdatePolicy / DeletePolicy. Each is a fmt.Errorf format string for wrapping api.ErrAppControlInvalidRequest.
const (
	errActorRequiredFmt  = "%w: actor is required"
	errReasonRequiredFmt = "%w: reason is required"
	errBeginTxFmt        = "appcontrol begin tx: %w"
	errCommitTxFmt       = "appcontrol commit tx: %w"
	// errBulkItemFmt wraps a per-item validator error with the batch index. Sonar S1192 flagged this string as duplicated across
	// three call sites in BulkUpsertRules' validation pass; extracting keeps the wire format stable.
	errBulkItemFmt = "bulk item %d: %w"
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

// EnsureDefaultPolicy idempotently seeds the Phase A built-ins: the `Default` policy, the `all-hosts` host group, and the single
// assignment row connecting them. Safe to call on every server boot (Bootstrap does so). Uses INSERT IGNORE for all three so a manual
// edit of any row's description or criteria is not clobbered on subsequent restarts. The three statements run in a transaction so a
// partial bootstrap (policy without assignment) is impossible after the first successful boot.
func (s *Store) EnsureDefaultPolicy(ctx context.Context) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("appcontrol seed: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT IGNORE INTO app_control_policies (name, description, version, default_action, created_by, updated_by)
		 VALUES (?, ?, 1, 'NONE', 'system', 'system')`,
		api.DefaultPolicyName,
		"Default application control policy. Add rules to block executables by SHA-256 hash or signing identity.",
	); err != nil {
		return fmt.Errorf("appcontrol seed default policy: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT IGNORE INTO host_groups (name, description, criteria) VALUES (?, ?, ?)`,
		api.DefaultHostGroupName,
		"Built-in host group that matches every enrolled host. Phase A's only host group; editable groups arrive in Phase B.",
		fmt.Sprintf(`{"type":"%s"}`, api.HostGroupCriteriaTypeAll),
	); err != nil {
		return fmt.Errorf("appcontrol seed all-hosts group: %w", err)
	}

	// Resolve the rows we just (idempotently) inserted so we can wire the assignment. SELECT BY NAME because LAST_INSERT_ID() returns
	// 0 on the IGNORE-suppressed path; that's the second-boot case where the rows already exist.
	var policyID, groupID int64
	if err := tx.QueryRowxContext(ctx,
		`SELECT id FROM app_control_policies WHERE name = ?`, api.DefaultPolicyName,
	).Scan(&policyID); err != nil {
		return fmt.Errorf("appcontrol seed: resolve default policy id: %w", err)
	}
	if err := tx.QueryRowxContext(ctx,
		`SELECT id FROM host_groups WHERE name = ?`, api.DefaultHostGroupName,
	).Scan(&groupID); err != nil {
		return fmt.Errorf("appcontrol seed: resolve all-hosts group id: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT IGNORE INTO app_control_assignments (policy_id, host_group_id, priority) VALUES (?, ?, 0)`,
		policyID, groupID,
	); err != nil {
		return fmt.Errorf("appcontrol seed default assignment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("appcontrol seed: commit: %w", err)
	}
	return nil
}

// ListHostGroupsForPolicy returns the host groups assigned to a policy, ordered by priority (highest first) then by group name. The
// fan-out path walks the result and unions the member hosts of each group to build the set of unique hosts a rule update should
// reach. Phase A always returns the single built-in `all-hosts` group; Phase B grows the result when editable assignments land.
func (s *Store) ListHostGroupsForPolicy(ctx context.Context, policyID int64) ([]api.HostGroup, error) {
	const query = `SELECT g.id, g.name, g.description, g.criteria, g.created_at, g.updated_at
		FROM host_groups g
		INNER JOIN app_control_assignments a ON a.host_group_id = g.id
		WHERE a.policy_id = ?
		ORDER BY a.priority DESC, g.name ASC`
	rows, err := s.db.QueryxContext(ctx, query, policyID)
	if err != nil {
		return nil, fmt.Errorf("appcontrol list host groups: %w", err)
	}
	defer rows.Close()
	out := []api.HostGroup{}
	for rows.Next() {
		var g api.HostGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Criteria, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("appcontrol scan host group: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appcontrol iterate host groups: %w", err)
	}
	return out, nil
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

// GetPolicyByID loads the policy row by primary key. Rules are NOT populated; callers that need rules call ListRulesByPolicy
// explicitly. Used by the service-layer snapshot composer and the policy-delete audit path which both need a single policy by
// id without paying for a full ListPolicies scan. Delegates to the existing private getPolicyByID helper (mirroring the
// GetRuleByID / getRuleByID delegation pattern) so the SELECT + scan + ErrNoRows mapping lives in one place.
func (s *Store) GetPolicyByID(ctx context.Context, policyID int64) (api.ApplicationControlPolicy, error) {
	return s.getPolicyByID(ctx, policyID)
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

// ListRulesAcrossPolicies returns rules matching the filter across every policy (or one, when req.PolicyID is set). Powers the
// cross-policy GET /rules endpoint that integration callers + audit exports need. Two queries: one count, one page. The page
// is ordered by (policy_id, rule_type, identifier, id) so pagination is deterministic across sibling rows with identical
// (rule_type, identifier) keys in different policies.
func (s *Store) ListRulesAcrossPolicies(
	ctx context.Context, req api.ListRulesAcrossPoliciesRequest,
) (api.ListRulesAcrossPoliciesResult, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = api.DefaultListRulesAcrossPoliciesLimit
	}
	if limit > api.MaxListRulesAcrossPoliciesLimit {
		limit = api.MaxListRulesAcrossPoliciesLimit
	}
	offset := max(req.Offset, 0)

	// Build the dynamic WHERE clause from the set dimensions. Each branch appends its placeholder + arg in lockstep so the
	// SQL stays parameterised end-to-end (no string concatenation of operator input). Empty filter -> WHERE 1=1, full scan.
	clauses := []string{"1=1"}
	args := []any{}
	if req.PolicyID != nil {
		clauses = append(clauses, "policy_id = ?")
		args = append(args, *req.PolicyID)
	}
	if req.RuleType != "" {
		clauses = append(clauses, "rule_type = ?")
		args = append(args, req.RuleType)
	}
	if req.Enabled != nil {
		clauses = append(clauses, "enabled = ?")
		if *req.Enabled {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	if req.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, req.Severity)
	}
	if req.Source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, req.Source)
	}
	where := strings.Join(clauses, " AND ")

	// Count first so the wire response can render "Showing N of M" without a second client-side round trip.
	var total int
	if err := s.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM app_control_rules WHERE `+where, args...); err != nil {
		return api.ListRulesAcrossPoliciesResult{}, fmt.Errorf("appcontrol list rules count: %w", err)
	}

	pageArgs := append(append([]any{}, args...), limit, offset)
	const pageSelect = `SELECT id, policy_id, rule_type, identifier, action, enforcement, enabled,
		severity, source, source_ref, custom_msg, custom_url, comment, expires_at,
		created_at, updated_at, created_by
		FROM app_control_rules WHERE `
	const pageTail = ` ORDER BY policy_id, rule_type, identifier, id LIMIT ? OFFSET ?`
	rows, err := s.db.QueryxContext(ctx, pageSelect+where+pageTail, pageArgs...)
	if err != nil {
		return api.ListRulesAcrossPoliciesResult{}, fmt.Errorf("appcontrol list rules page: %w", err)
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
			return api.ListRulesAcrossPoliciesResult{}, fmt.Errorf("appcontrol list rules scan: %w", err)
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return api.ListRulesAcrossPoliciesResult{}, fmt.Errorf("appcontrol list rules rows: %w", err)
	}
	return api.ListRulesAcrossPoliciesResult{Rules: out, Total: total}, nil
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
		return api.ApplicationControlRule{}, fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return api.ApplicationControlRule{}, fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
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
		return api.ApplicationControlRule{}, fmt.Errorf(errBeginTxFmt, err)
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
		return api.ApplicationControlRule{}, fmt.Errorf(errCommitTxFmt, err)
	}
	return s.getRuleByID(ctx, ruleID)
}

// GetRuleByID returns one rule row keyed by id, mapping a missing row to ErrAppControlRuleNotFound so the REST PATCH / DELETE
// handlers can respond 404 cleanly. Public wrapper around getRuleByID (which historically only the post-INSERT path called); the
// underlying query is the same.
func (s *Store) GetRuleByID(ctx context.Context, id int64) (api.ApplicationControlRule, error) {
	rule, err := s.getRuleByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ApplicationControlRule{}, api.ErrAppControlRuleNotFound
		}
		return api.ApplicationControlRule{}, err
	}
	return rule, nil
}

// buildRuleUpdateSetClause renders the SET-clause fragment + args slice for the partial-update fields the caller set in req.
// Extracted from UpdateRule so the orchestrator's cognitive complexity stays under Sonar's 15-statement threshold (S3776).
// Returns (clauseFragment, args, ok); ok is false when the caller sent zero mutable fields — the caller maps that to
// ErrAppControlInvalidRequest at the top level.
func buildRuleUpdateSetClause(req api.UpdateRuleRequest) (string, []any, bool) {
	setClauses := make([]string, 0, 6)
	args := make([]any, 0, 7)
	if req.Enabled != nil {
		setClauses = append(setClauses, "enabled = ?")
		enabledInt := 0
		if *req.Enabled {
			enabledInt = 1
		}
		args = append(args, enabledInt)
	}
	if req.Severity != nil {
		setClauses = append(setClauses, "severity = ?")
		args = append(args, *req.Severity)
	}
	if req.CustomMsg != nil {
		setClauses = append(setClauses, "custom_msg = ?")
		args = append(args, *req.CustomMsg)
	}
	if req.CustomURL != nil {
		setClauses = append(setClauses, "custom_url = ?")
		args = append(args, *req.CustomURL)
	}
	if req.Comment != nil {
		setClauses = append(setClauses, "comment = ?")
		args = append(args, *req.Comment)
	}
	if req.ExpiresAt != nil {
		setClauses = append(setClauses, "expires_at = ?")
		args = append(args, *req.ExpiresAt)
	}
	if len(setClauses) == 0 {
		return "", nil, false
	}
	return strings.Join(setClauses, ", "), args, true
}

// validateUpdateRuleRequest covers the up-front guards: actor + reason required, severity (if present) must be a non-empty
// enum value. Extracted so UpdateRule's body stays linear and Sonar's cognitive-complexity rule (S3776) does not fire.
func validateUpdateRuleRequest(req api.UpdateRuleRequest) error {
	if strings.TrimSpace(req.Actor) == "" {
		return fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if req.Severity != nil {
		if err := ValidateSeverity(*req.Severity); err != nil {
			return err
		}
		// ValidateSeverity accepts "" as "use default"; on UPDATE the operator must send a concrete value or omit the field.
		if strings.TrimSpace(string(*req.Severity)) == "" {
			return fmt.Errorf("%w: severity must be a non-empty enum value when present on a PATCH", api.ErrAppControlInvalidSeverity)
		}
	}
	return nil
}

// UpdateRule applies a partial update to one rule row and bumps the parent policy's version atomically. PolicyID is read from the
// existing row rather than carried on the request so a PATCH cannot inadvertently move a rule between policies; the auth-gated
// REST handler runs separately. ErrAppControlRuleNotFound when the row is missing, ErrAppControlInvalidRequest on empty
// actor/reason or a body with no mutable field, ErrAppControlInvalidSeverity when Severity is set to a bogus value.
//
// Concurrency: the UPDATE result's RowsAffected is gated to 1 so a concurrent DELETE between the SELECT and the UPDATE returns
// ErrAppControlRuleNotFound rather than silently bumping the policy version (which would trigger a spurious snapshot fan-out).
func (s *Store) UpdateRule(ctx context.Context, req api.UpdateRuleRequest) (api.ApplicationControlRule, error) {
	if err := validateUpdateRuleRequest(req); err != nil {
		return api.ApplicationControlRule{}, err
	}
	setFragment, args, ok := buildRuleUpdateSetClause(req)
	if !ok {
		return api.ApplicationControlRule{}, fmt.Errorf("%w: at least one mutable field must be set on a PATCH", api.ErrAppControlInvalidRequest)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf(errBeginTxFmt, err)
	}
	defer func() { _ = tx.Rollback() }()

	// Look up the existing row so we know which policy to bump and so we can return a 404 instead of silently updating zero rows.
	var policyID int64
	if err := tx.QueryRowxContext(ctx, `SELECT policy_id FROM app_control_rules WHERE id = ?`, req.RuleID).Scan(&policyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ApplicationControlRule{}, api.ErrAppControlRuleNotFound
		}
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol lookup rule for update: %w", err)
	}

	args = append(args, req.RuleID)
	updateSQL := "UPDATE app_control_rules SET " + setFragment + " WHERE id = ?"
	res, err := tx.ExecContext(ctx, updateSQL, args...)
	if err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol update rule: %w", err)
	}
	// Concurrent delete race: the SELECT above passed but the UPDATE hit zero rows because another transaction removed the row
	// between the two statements. Fail with ErrAppControlRuleNotFound so the caller sees a stable 404 — without this, the policy
	// version bump below would still fire, triggering a spurious snapshot push to every agent.
	affected, err := res.RowsAffected()
	if err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol update rule rows affected: %w", err)
	}
	if affected == 0 {
		return api.ApplicationControlRule{}, api.ErrAppControlRuleNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE app_control_policies SET version = version + 1, updated_by = ? WHERE id = ?`,
		req.Actor, policyID); err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf("appcontrol bump policy version on update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return api.ApplicationControlRule{}, fmt.Errorf(errCommitTxFmt, err)
	}
	return s.GetRuleByID(ctx, req.RuleID)
}

// DeleteRule removes a rule row + bumps the parent policy's version atomically. Returns the parent policy_id so the service's
// downstream snapshot fan-out targets the right policy. ErrAppControlRuleNotFound when the row is missing.
func (s *Store) DeleteRule(ctx context.Context, req api.DeleteRuleRequest) (int64, error) {
	if strings.TrimSpace(req.Actor) == "" {
		return 0, fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return 0, fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf(errBeginTxFmt, err)
	}
	defer func() { _ = tx.Rollback() }()

	var policyID int64
	if err := tx.QueryRowxContext(ctx, `SELECT policy_id FROM app_control_rules WHERE id = ?`, req.RuleID).Scan(&policyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, api.ErrAppControlRuleNotFound
		}
		return 0, fmt.Errorf("appcontrol lookup rule for delete: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM app_control_rules WHERE id = ?`, req.RuleID)
	if err != nil {
		return 0, fmt.Errorf("appcontrol delete rule: %w", err)
	}
	// Concurrent delete race: same shape as UpdateRule. If another transaction removed the row between the SELECT and the DELETE,
	// affected will be 0 — fail with ErrAppControlRuleNotFound so the policy version bump below does not fire and trigger a
	// no-op snapshot push.
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("appcontrol delete rule rows affected: %w", err)
	}
	if affected == 0 {
		return 0, api.ErrAppControlRuleNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE app_control_policies SET version = version + 1, updated_by = ? WHERE id = ?`,
		req.Actor, policyID); err != nil {
		return 0, fmt.Errorf("appcontrol bump policy version on delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf(errCommitTxFmt, err)
	}
	return policyID, nil
}

// CreatePolicy inserts a new policy row with version=1, default_action='NONE', and the supplied actor on created_by + updated_by.
// Phase A has no assignments wired in to a fresh policy; the operator attaches host groups via the assignments endpoint (Phase B).
func (s *Store) CreatePolicy(ctx context.Context, req api.CreatePolicyRequest) (api.ApplicationControlPolicy, error) {
	if strings.TrimSpace(req.Actor) == "" {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Name) == "" {
		return api.ApplicationControlPolicy{}, fmt.Errorf("%w: policy name is required", api.ErrAppControlInvalidRequest)
	}

	res, err := s.db.ExecContext(ctx, `INSERT INTO app_control_policies (name, description, version, default_action, created_by, updated_by) VALUES (?, ?, 1, 'NONE', ?, ?)`,
		req.Name, req.Description, req.Actor, req.Actor)
	if err != nil {
		if isDuplicateKey(err) {
			return api.ApplicationControlPolicy{}, api.ErrAppControlDuplicatePolicy
		}
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol create policy: %w", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol create policy lastid: %w", err)
	}
	return s.getPolicyByID(ctx, policyID)
}

// UpdatePolicy applies a partial update (name and/or description) to a policy row, bumps version, and sets updated_by. Returns
// ErrAppControlPolicyNotFound when the id is missing; ErrAppControlDuplicatePolicy if the new name collides with another row;
// ErrAppControlInvalidRequest when no mutable field is provided; ErrAppControlPolicyImmutable if the caller tries to rename the
// seed Default policy (closing the Copilot-flagged bypass where a rename-then-delete would defeat the immutability guard).
func (s *Store) UpdatePolicy(ctx context.Context, req api.UpdatePolicyRequest) (api.ApplicationControlPolicy, error) {
	if strings.TrimSpace(req.Actor) == "" {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errBeginTxFmt, err)
	}
	defer func() { _ = tx.Rollback() }()

	// Look up the existing name inside the txn so the rename guard sees a consistent view: a concurrent rename cannot squeeze
	// between the SELECT and the UPDATE because both run under the same transaction's repeatable-read snapshot.
	var existingName string
	if err := tx.QueryRowxContext(ctx, `SELECT name FROM app_control_policies WHERE id = ?`, req.PolicyID).Scan(&existingName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
		}
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol lookup policy for update: %w", err)
	}
	// Failsafe: refuse to rename the seed Default policy. Without this, an admin could rename Default to "x" and then DELETE it,
	// since DeletePolicy's immutability check fires on the current name. The seed policy's name is the stable anchor for the
	// `all-hosts` assignment that every deployment inherits at boot.
	if req.Name != nil && existingName == api.DefaultPolicyName && *req.Name != api.DefaultPolicyName {
		return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyImmutable
	}

	setClauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			return api.ApplicationControlPolicy{}, fmt.Errorf("%w: policy name cannot be empty when present", api.ErrAppControlInvalidRequest)
		}
		setClauses = append(setClauses, "name = ?")
		args = append(args, *req.Name)
	}
	if req.Description != nil {
		setClauses = append(setClauses, "description = ?")
		args = append(args, *req.Description)
	}
	if len(setClauses) == 0 {
		return api.ApplicationControlPolicy{}, fmt.Errorf("%w: at least one mutable field must be set on a PATCH", api.ErrAppControlInvalidRequest)
	}
	setClauses = append(setClauses, "version = version + 1", "updated_by = ?")
	args = append(args, req.Actor, req.PolicyID)
	updateSQL := "UPDATE app_control_policies SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	res, err := tx.ExecContext(ctx, updateSQL, args...)
	if err != nil {
		if isDuplicateKey(err) {
			return api.ApplicationControlPolicy{}, api.ErrAppControlDuplicatePolicy
		}
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol update policy: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol update policy rows affected: %w", err)
	}
	if affected == 0 {
		return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
	}
	if err := tx.Commit(); err != nil {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errCommitTxFmt, err)
	}
	return s.getPolicyByID(ctx, req.PolicyID)
}

// DeletePolicy removes a policy row. Refuses the seed Default policy by name (ErrAppControlPolicyImmutable) so the failsafe
// assignment that ships with every deployment stays intact. ON DELETE CASCADE on app_control_rules + app_control_assignments cleans
// up child rows; agents that already cached this policy's rules will not see the deletion until the next snapshot push, but Phase A
// only ever has the Default policy assigned to hosts so a non-Default delete affects zero hosts in practice.
func (s *Store) DeletePolicy(ctx context.Context, req api.DeletePolicyRequest) error {
	if strings.TrimSpace(req.Actor) == "" {
		return fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf(errBeginTxFmt, err)
	}
	defer func() { _ = tx.Rollback() }()

	var name string
	if err := tx.QueryRowxContext(ctx, `SELECT name FROM app_control_policies WHERE id = ?`, req.PolicyID).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ErrAppControlPolicyNotFound
		}
		return fmt.Errorf("appcontrol lookup policy for delete: %w", err)
	}
	if name == api.DefaultPolicyName {
		return api.ErrAppControlPolicyImmutable
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_control_policies WHERE id = ?`, req.PolicyID); err != nil {
		return fmt.Errorf("appcontrol delete policy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf(errCommitTxFmt, err)
	}
	return nil
}

// getPolicyByID is the internal lookup the create/update paths use to return the post-mutation row. The missing-row case is
// translated to api.ErrAppControlPolicyNotFound inside this helper (mirroring GetRuleByID's contract); callers can errors.Is
// directly without unwrapping a driver-level sql.ErrNoRows.
func (s *Store) getPolicyByID(ctx context.Context, id int64) (api.ApplicationControlPolicy, error) {
	const query = `SELECT id, name, description, version, default_action, created_at, updated_at, created_by, updated_by
		FROM app_control_policies WHERE id = ?`
	row := s.db.QueryRowxContext(ctx, query, id)
	var p api.ApplicationControlPolicy
	if err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.Version, &p.DefaultAction,
		&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy, &p.UpdatedBy,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
		}
		return api.ApplicationControlPolicy{}, fmt.Errorf("appcontrol get policy by id: %w", err)
	}
	return p, nil
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

// bulkItemKey is the canonical (rule_type, identifier) key the bulk-upsert preflight + post-state maps index on. \x1f is the
// ASCII unit-separator; using it as the join token avoids any collision with valid rule_type / identifier characters.
func bulkItemKey(ruleType api.RuleType, identifier string) string {
	return string(ruleType) + "\x1f" + identifier
}

// validateBulkUpsertRequest covers the envelope-level guards (actor, reason, item count). Extracted so BulkUpsertRules' body
// stays under Sonar's cognitive-complexity threshold (S3776) AND so the duplicate-batch + per-item validators below stay
// focused on item-shape concerns.
func validateBulkUpsertRequest(req api.BulkUpsertRulesRequest) error {
	if strings.TrimSpace(req.Actor) == "" {
		return fmt.Errorf(errActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return fmt.Errorf(errReasonRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	if len(req.Items) == 0 {
		return fmt.Errorf("%w: bulk upsert requires at least one rule", api.ErrAppControlInvalidRequest)
	}
	if len(req.Items) > api.MaxBulkUpsertItems {
		return fmt.Errorf("%w: batch size %d exceeds limit %d",
			api.ErrAppControlInvalidRequest, len(req.Items), api.MaxBulkUpsertItems)
	}
	return nil
}

// validateBulkUpsertItems runs the per-item shape checks AND the in-batch duplicate-key guard. CodeRabbit on PR #190 flagged a
// duplicate key in the same batch as a count-correctness bug: without this guard, the second occurrence of the same
// (rule_type, identifier) tuple would be classified as Insert because the preflight only sees pre-batch state.
func validateBulkUpsertItems(items []api.BulkUpsertRuleItem) error {
	seen := make(map[string]int, len(items))
	for i, item := range items {
		if err := ValidateRuleType(item.RuleType); err != nil {
			return fmt.Errorf(errBulkItemFmt, i, err)
		}
		if err := ValidateIdentifier(item.RuleType, item.Identifier); err != nil {
			return fmt.Errorf(errBulkItemFmt, i, err)
		}
		if err := ValidateSeverity(item.Severity); err != nil {
			return fmt.Errorf(errBulkItemFmt, i, err)
		}
		key := bulkItemKey(item.RuleType, item.Identifier)
		if prev, dup := seen[key]; dup {
			return fmt.Errorf("%w: bulk item %d duplicates the (rule_type, identifier) of item %d",
				api.ErrAppControlInvalidRequest, i, prev)
		}
		seen[key] = i
	}
	return nil
}

// lockPolicyForBulkUpsert serialises concurrent bulk-upserts against the same policy by taking a row lock on the parent
// app_control_policies row inside the txn. Two concurrent bulk-upserts on the same policy would otherwise have a TOCTOU race
// between preflight (SELECT existing keys) and upsert (INSERT ... ON DUPLICATE KEY UPDATE) — both could classify the same key
// as Insert and over-report inserted counts. Returns ErrAppControlPolicyNotFound when the policy doesn't exist (the row lock
// surfaces missing rows as sql.ErrNoRows).
func lockPolicyForBulkUpsert(ctx context.Context, tx *sqlx.Tx, policyID int64) error {
	var id int64
	err := tx.QueryRowxContext(ctx, `SELECT id FROM app_control_policies WHERE id = ? FOR UPDATE`, policyID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return api.ErrAppControlPolicyNotFound
	}
	if err != nil {
		return fmt.Errorf("appcontrol bulk upsert: lock policy: %w", err)
	}
	return nil
}

// collectExistingBulkKeys returns the set of (rule_type, identifier) tuples that already exist for the policy among the items
// in the batch. One SELECT replaces the previous N×SELECT preflight loop (Gemini HIGH on PR #190). Items are passed in so the
// IN clause only spans the batch keys, not the whole policy's rules.
func (s *Store) collectExistingBulkKeys(ctx context.Context, tx *sqlx.Tx, policyID int64, items []api.BulkUpsertRuleItem) (map[string]struct{}, error) {
	if len(items) == 0 {
		return map[string]struct{}{}, nil
	}
	// Compose `(?, ?), (?, ?), ...` placeholder list for the row-constructor IN clause.
	placeholders := make([]string, len(items))
	args := make([]any, 0, 1+2*len(items))
	args = append(args, policyID)
	for i, item := range items {
		placeholders[i] = "(?, ?)"
		args = append(args, item.RuleType, item.Identifier)
	}
	query := "SELECT rule_type, identifier FROM app_control_rules WHERE policy_id = ? AND (rule_type, identifier) IN (" +
		strings.Join(placeholders, ", ") + ")"
	rows, err := tx.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("appcontrol bulk preflight: %w", err)
	}
	defer rows.Close()
	out := make(map[string]struct{}, len(items))
	for rows.Next() {
		var rt api.RuleType
		var ident string
		if err := rows.Scan(&rt, &ident); err != nil {
			return nil, fmt.Errorf("appcontrol bulk preflight scan: %w", err)
		}
		out[bulkItemKey(rt, ident)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appcontrol bulk preflight rows: %w", err)
	}
	return out, nil
}

// fetchBulkUpsertRows is the single-SELECT post-state fetch that replaces the previous N×SELECT refetch loop (Gemini HIGH on
// PR #190). Returns the rules indexed by (rule_type, identifier) key so the caller can re-order them to the request's order.
func (s *Store) fetchBulkUpsertRows(ctx context.Context, policyID int64, items []api.BulkUpsertRuleItem) (map[string]api.ApplicationControlRule, error) {
	if len(items) == 0 {
		return map[string]api.ApplicationControlRule{}, nil
	}
	placeholders := make([]string, len(items))
	args := make([]any, 0, 1+2*len(items))
	args = append(args, policyID)
	for i, item := range items {
		placeholders[i] = "(?, ?)"
		args = append(args, item.RuleType, item.Identifier)
	}
	query := `SELECT id, policy_id, rule_type, identifier, action, enforcement, enabled,
		severity, source, source_ref, custom_msg, custom_url, comment, expires_at,
		created_at, updated_at, created_by
		FROM app_control_rules
		WHERE policy_id = ? AND (rule_type, identifier) IN (` + strings.Join(placeholders, ", ") + ")"
	rows, err := s.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("appcontrol bulk upsert: refetch: %w", err)
	}
	defer rows.Close()
	out := make(map[string]api.ApplicationControlRule, len(items))
	for rows.Next() {
		var rule api.ApplicationControlRule
		var enabled int
		if err := rows.Scan(
			&rule.ID, &rule.PolicyID, &rule.RuleType, &rule.Identifier, &rule.Action, &rule.Enforcement, &enabled,
			&rule.Severity, &rule.Source, &rule.SourceRef, &rule.CustomMsg, &rule.CustomURL, &rule.Comment, &rule.ExpiresAt,
			&rule.CreatedAt, &rule.UpdatedAt, &rule.CreatedBy,
		); err != nil {
			return nil, fmt.Errorf("appcontrol bulk upsert refetch scan: %w", err)
		}
		rule.Enabled = enabled != 0
		out[bulkItemKey(rule.RuleType, rule.Identifier)] = rule
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("appcontrol bulk upsert refetch rows: %w", err)
	}
	return out, nil
}

// BulkUpsertRules inserts or overwrites each row in req.Items inside one transaction, bumps the parent policy version once, and
// returns the post-upsert rows + insert/update counts. Idempotency key is (policy_id, rule_type, identifier) per the openspec;
// severity / custom_msg / custom_url / comment overwrite when the key collides. All-or-nothing: a per-item validator error
// (rule_type, identifier shape, severity) OR an in-batch duplicate-key violation rejects the whole batch before any UPDATE
// fires. Returns ErrAppControlPolicyNotFound when the policy_id is missing.
//
// Concurrency: the batch takes a row-level lock on the parent app_control_policies row (SELECT ... FOR UPDATE) so two
// concurrent bulk-upserts on the same policy cannot interleave their preflight + write phases. Items are also sorted by
// (rule_type, identifier) so lock acquisition order on the underlying rule rows is deterministic — defense-in-depth that
// stays sound if Phase B relaxes the parent-policy row lock.
//
// Insert/update classification snapshots the existing (policy_id, rule_type, identifier) keys with one SELECT inside the
// same txn (no N×SELECT preflight), then classifies each item by checking the snapshot. The post-state row set is fetched
// with one SELECT after commit (no N×SELECT refetch); rows are returned in the original request order.
func (s *Store) BulkUpsertRules(ctx context.Context, req api.BulkUpsertRulesRequest) (api.BulkUpsertResult, error) {
	if err := validateBulkUpsertRequest(req); err != nil {
		return api.BulkUpsertResult{}, err
	}
	if err := validateBulkUpsertItems(req.Items); err != nil {
		return api.BulkUpsertResult{}, err
	}

	// Sort a copy so the caller's slice stays intact + lock ordering on rule rows is deterministic across concurrent batches.
	sortedItems := make([]api.BulkUpsertRuleItem, len(req.Items))
	copy(sortedItems, req.Items)
	sort.Slice(sortedItems, func(i, j int) bool {
		if sortedItems[i].RuleType != sortedItems[j].RuleType {
			return sortedItems[i].RuleType < sortedItems[j].RuleType
		}
		return sortedItems[i].Identifier < sortedItems[j].Identifier
	})

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.BulkUpsertResult{}, fmt.Errorf(errBeginTxFmt, err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockPolicyForBulkUpsert(ctx, tx, req.PolicyID); err != nil {
		return api.BulkUpsertResult{}, err
	}
	existing, err := s.collectExistingBulkKeys(ctx, tx, req.PolicyID, sortedItems)
	if err != nil {
		return api.BulkUpsertResult{}, err
	}

	const upsert = `INSERT INTO app_control_rules
		(policy_id, rule_type, identifier, action, enforcement, enabled, severity, source, custom_msg, custom_url, comment, created_by)
		VALUES (?, ?, ?, 'BLOCK', 'PROTECT', 1, ?, 'admin', ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			severity = VALUES(severity),
			custom_msg = VALUES(custom_msg),
			custom_url = VALUES(custom_url),
			comment = VALUES(comment)`
	inserted := 0
	updated := 0
	for _, item := range sortedItems {
		severity := item.Severity
		if severity == "" {
			severity = api.SeverityRuleMedium
		}
		if _, err := tx.ExecContext(ctx, upsert,
			req.PolicyID, item.RuleType, item.Identifier, severity,
			item.CustomMsg, item.CustomURL, item.Comment, req.Actor,
		); err != nil {
			if isForeignKeyViolation(err) {
				return api.BulkUpsertResult{}, api.ErrAppControlPolicyNotFound
			}
			return api.BulkUpsertResult{}, fmt.Errorf("appcontrol bulk upsert item: %w", err)
		}
		if _, existedBefore := existing[bulkItemKey(item.RuleType, item.Identifier)]; existedBefore {
			updated++
		} else {
			inserted++
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE app_control_policies SET version = version + 1, updated_by = ? WHERE id = ?`,
		req.Actor, req.PolicyID); err != nil {
		return api.BulkUpsertResult{}, fmt.Errorf("appcontrol bulk upsert: bump policy version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return api.BulkUpsertResult{}, fmt.Errorf(errCommitTxFmt, err)
	}

	// Post-upsert state: one SELECT replaces the N×SELECT refetch. Build the response in the original request order so
	// indexable consumers (paste-many UI showing line-by-line) line up with the operator's input.
	postMap, err := s.fetchBulkUpsertRows(ctx, req.PolicyID, req.Items)
	if err != nil {
		return api.BulkUpsertResult{}, err
	}
	rules := make([]api.ApplicationControlRule, 0, len(req.Items))
	for _, item := range req.Items {
		rule, ok := postMap[bulkItemKey(item.RuleType, item.Identifier)]
		if !ok {
			return api.BulkUpsertResult{}, fmt.Errorf("appcontrol bulk upsert: refetch missed key %s/%s", item.RuleType, item.Identifier)
		}
		rules = append(rules, rule)
	}
	return api.BulkUpsertResult{Inserted: inserted, Updated: updated, Rules: rules}, nil
}
