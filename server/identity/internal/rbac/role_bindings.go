// Package rbac owns the role_bindings + roles tables. Wave 1 ships
// this as a read-side store: the AuthZ chokepoint loads an actor's
// live bindings on every privileged request via ListLiveBindings.
// Wave 2's user-management write surface will land here.
//
// Internal to identity. Cross-context callers go through
// server/identity/api.AuthZ instead of touching this store.
package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
)

// Store owns the role_bindings table.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store over an existing sqlx.DB handle.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// roleBindingRow is the storage shape; the public api.RoleBinding is
// the read shape callers see. Keeping them distinct means a wave-2
// schema add (e.g. created_by) can grow the storage row without
// pushing into the public boundary.
type roleBindingRow struct {
	ID        int64        `db:"id"`
	UserID    int64        `db:"user_id"`
	RoleID    string       `db:"role_id"`
	TenantID  string       `db:"tenant_id"`
	ScopeType string       `db:"scope_type"`
	ScopeID   string       `db:"scope_id"`
	ExpiresAt sql.NullTime `db:"expires_at"`
	CreatedAt time.Time    `db:"created_at"`
}

// Executor is the executor subset BindRole consumes; lets the JIT
// provisioner pass an *sqlx.Tx so the role binding lands in the same
// transaction as the user + identity insert. Named per the Go
// convention (single-method interface ends in -er).
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// BindRoleRequest is the input to BindRole. Pulled out of the
// function signature so the call site reads as named fields and stays
// under the linter's per-call parameter budget. Wave-1 defaults:
// ExpiresAt nil (non-expiring), ScopeType "tenant", ScopeID "*".
type BindRoleRequest struct {
	UserID    int64
	RoleID    string
	TenantID  string
	ScopeType string
	ScopeID   string
	ExpiresAt *time.Time
}

// BindRole inserts a role_bindings row. Used by Phase-4 JIT
// provisioning to bind a freshly-provisioned OIDC user to the
// default role at the seeded tenant.
func (s *Store) BindRole(ctx context.Context, ec Executor, req BindRoleRequest) error {
	_, err := ec.ExecContext(ctx, `
		INSERT INTO role_bindings (user_id, role_id, tenant_id, scope_type, scope_id, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, req.UserID, req.RoleID, req.TenantID, req.ScopeType, req.ScopeID, req.ExpiresAt)
	if err != nil {
		return fmt.Errorf("bind role %q to user %d: %w", req.RoleID, req.UserID, err)
	}
	return nil
}

// ListLiveBindings returns every role binding for a user that is not
// expired. The (user_id, expires_at) index keeps the query indexed
// even on very large role_bindings tables.
//
// Used by the chokepoint's per-request actor build. Sub-millisecond
// on a populated DB; the AuthZ p99 budget allocates ~1 ms for the
// whole pipeline (this query + the OPA evaluation), so the index
// matters.
func (s *Store) ListLiveBindings(ctx context.Context, userID int64) ([]api.RoleBinding, error) {
	if s.db == nil {
		return nil, errors.New("rbac: db must not be nil")
	}
	rows := []roleBindingRow{}
	err := s.db.SelectContext(ctx, &rows, `
		SELECT id, user_id, role_id, tenant_id, scope_type, scope_id, expires_at, created_at
		FROM role_bindings
		WHERE user_id = ?
		  AND (expires_at IS NULL OR expires_at > NOW(6))
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list live bindings for user %d: %w", userID, err)
	}
	out := make([]api.RoleBinding, len(rows))
	for i, r := range rows {
		out[i] = api.RoleBinding{
			ID:        r.ID,
			UserID:    r.UserID,
			RoleID:    r.RoleID,
			TenantID:  r.TenantID,
			ScopeType: api.RoleBindingScopeType(r.ScopeType),
			ScopeID:   r.ScopeID,
			CreatedAt: r.CreatedAt,
		}
		if r.ExpiresAt.Valid {
			t := r.ExpiresAt.Time
			out[i].ExpiresAt = &t
		}
	}
	return out, nil
}
