package main

import (
	"context"
	"database/sql"
	"fmt"
)

// dbExecQuerier is the subset of database/sql the seeder's DB-facing helpers use. Both *sql.DB (production) and *sqlx.DB (the
// testdb/full handle the tests open) satisfy it, so the same code is exercised against a real schema in tests.
type dbExecQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	// BeginTx lets refreshTimestamps slide every replayed column atomically: a partial shift would desync the
	// device-vs-ingest and event-vs-alert ordering the detail/correlation views depend on.
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// seedDemoUser idempotently provisions the SSO demo user so first login lands at a full-capability role instead of the OIDC JIT
// default (analyst, hardcoded in server/identity/internal/oidc/jit.go). It inserts the users row, an oidc identity bound to the
// dex-issued subject, and a global role binding. On login ProvisionOrFind matches the existing (provider, subject) identity and
// reuses it rather than JIT-provisioning, so the higher role sticks.
//
// roleID must already exist in the roles table: the server seeds the five built-in roles at boot, which happens before this seeder
// runs against it. Every statement is idempotent on its unique key so a container restart re-runs the seeder harmlessly.
func seedDemoUser(ctx context.Context, db dbExecQuerier, email, subject, roleID string) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (email, display_name, status)
		VALUES (?, 'Demo User', 'active')
		ON DUPLICATE KEY UPDATE display_name = VALUES(display_name)`, email); err != nil {
		return fmt.Errorf("seed demo user row: %w", err)
	}

	var userID int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID); err != nil {
		return fmt.Errorf("look up demo user id: %w", err)
	}

	// Insert the identity, leaving any pre-existing (provider, subject) mapping untouched (ON DUPLICATE ... user_id = user_id is a
	// no-op). Then confirm the mapping points at the demo user: refuse to silently re-bind a subject already owned by another user
	// rather than hijacking it.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO identities (user_id, provider, subject)
		VALUES (?, 'oidc', ?)
		ON DUPLICATE KEY UPDATE user_id = user_id`, userID, subject); err != nil {
		return fmt.Errorf("seed demo identity: %w", err)
	}
	var boundUserID int64
	if err := db.QueryRowContext(ctx,
		`SELECT user_id FROM identities WHERE provider = 'oidc' AND subject = ?`, subject).Scan(&boundUserID); err != nil {
		return fmt.Errorf("verify demo identity binding: %w", err)
	}
	if boundUserID != userID {
		return fmt.Errorf("oidc subject %q is already bound to user %d, not demo user %d; refusing to re-bind", subject, boundUserID, userID)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id)
		VALUES (?, ?, 'global', '*')
		ON DUPLICATE KEY UPDATE role_id = VALUES(role_id)`, userID, roleID); err != nil {
		return fmt.Errorf("seed demo role binding: %w", err)
	}
	return nil
}
