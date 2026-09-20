// Package appconfig owns the app_config table: the deployment's general settings as a single versioned JSON document deserialized into
// a typed AppConfig struct. This is the scalable home for admin-editable, non-secret settings (issue #375): add a field to AppConfig
// and it is persisted with no migration. Secrets do NOT live here (they go in dedicated sealed stores, e.g. ssoconfig's encrypted
// client-secret column); strongly-relational config gets its own typed table. The document is the "Fleet-style" app-config pattern with
// two refinements: secrets stay out, and a version counter provides optimistic-concurrency / cache invalidation.
package appconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
)

// ErrVersionConflict is returned by Put when the row's version no longer matches the expected version (a concurrent write landed
// between the caller's Get and Put). The caller should re-read and retry. This is the optimistic-concurrency guard the version column
// exists for.
var ErrVersionConflict = errors.New("appconfig: version conflict")

// AppConfig is the typed deployment-wide settings document. ADD A FIELD HERE to add a setting; no migration is needed. Every field
// MUST be omitempty-friendly and have a sensible zero value, because a fresh deployment reads a zero-value AppConfig until the first
// write. Do NOT put secrets here.
type AppConfig struct {
	// ExternalURL is the deployment's externally-reachable base URL (e.g. https://edr.acme.com). The OIDC redirect URI is derived from
	// it; other absolute-URL needs can read it later via the identity api surface.
	ExternalURL string `json:"external_url,omitempty"`
}

// Store owns the singleton app_config row.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store. Panics if db is nil.
func New(db *sqlx.DB) *Store {
	if db == nil {
		panic("appconfig.New: db must not be nil")
	}
	return &Store{db: db}
}

// Get returns the parsed config and its version. A deployment with no row yet returns a zero-value AppConfig and version 0 (not an
// error), so callers always get a usable document.
func (s *Store) Get(ctx context.Context) (AppConfig, int64, error) {
	return s.GetTx(ctx, s.db)
}

// GetTx is Get against a caller-supplied executor, so a caller can take the read inside a transaction alongside another table's and
// get one snapshot. Two separate reads can be landed between, which pairs one table's new version with the other's old value; a
// client that sends such a version back then passes the concurrency check holding stale data (issue #1046).
func (s *Store) GetTx(ctx context.Context, ext sqlx.ExtContext) (AppConfig, int64, error) {
	var rawConfig []byte
	var version int64
	err := ext.QueryRowxContext(ctx, `SELECT config, version FROM app_config WHERE id = 1`).Scan(&rawConfig, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return AppConfig{}, 0, nil
	}
	if err != nil {
		return AppConfig{}, 0, fmt.Errorf("appconfig: get: %w", err)
	}
	var cfg AppConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return AppConfig{}, 0, fmt.Errorf("appconfig: unmarshal: %w", err)
	}
	return cfg, version, nil
}

// Put writes the whole document with optimistic concurrency. Callers Get (which returns the current version), mutate, then Put with
// that version (read-modify-write) so unrelated fields are preserved and a concurrent write is detected. expectedVersion <= 0 means
// "first write" (no row yet) and inserts the singleton; expectedVersion > 0 updates only when the stored version still matches,
// returning ErrVersionConflict otherwise. updatedBy is the acting principal id (api.SystemPrincipal().ID for a non-operator env seed).
func (s *Store) Put(ctx context.Context, cfg AppConfig, expectedVersion int64, updatedBy string) error {
	return s.PutTx(ctx, s.db, cfg, expectedVersion, updatedBy)
}

// PutTx is Put against a caller-supplied executor (*sqlx.Tx or the Store's *sqlx.DB), so a write can join a transaction that also
// updates other tables atomically (e.g. the SSO admin update that writes oidc_config and app_config together).
func (s *Store) PutTx(ctx context.Context, ext sqlx.ExtContext, cfg AppConfig, expectedVersion int64, updatedBy string) error {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("appconfig: marshal: %w", err)
	}
	// An unset updater records the system principal, matching the column's NOT NULL DEFAULT 'sys' and its FK to principals(id).
	by := updatedBy
	if by == "" {
		by = api.PrincipalSystemID
	}
	if expectedVersion <= 0 {
		// First write: insert the singleton. ON DUPLICATE KEY UPDATE keeps the env-seed path idempotent across a concurrent first boot.
		if _, err := ext.ExecContext(ctx, `
			INSERT INTO app_config (id, config, version, updated_by)
			VALUES (1, ?, 1, ?)
			ON DUPLICATE KEY UPDATE
				config = VALUES(config), version = version + 1, updated_by = VALUES(updated_by)`,
			encoded, by); err != nil {
			return fmt.Errorf("appconfig: put insert: %w", err)
		}
		return nil
	}
	res, err := ext.ExecContext(ctx, `
		UPDATE app_config SET config = ?, version = version + 1, updated_by = ?
		WHERE id = 1 AND version = ?`,
		encoded, by, expectedVersion)
	if err != nil {
		return fmt.Errorf("appconfig: put update: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("appconfig: put rows-affected: %w", err)
	}
	if rows == 0 {
		return ErrVersionConflict
	}
	return nil
}

// PutAtVersionTx is PutTx for a caller who named the version it read, rather than one recovering a version the server itself read a
// moment earlier. The difference is the first write: PutTx inserts with ON DUPLICATE KEY UPDATE, which keeps the env seed idempotent
// but makes two racing first writes both succeed with the second silently replacing the first. Here a first write is a plain INSERT,
// so the race has a defined winner and the loser is told (issue #1046).
//
// Locking the row first is not the alternative it looks like: there is no row yet to lock, and what a SELECT ... FOR UPDATE would
// take in its place is a gap lock whose behaviour depends on the isolation level. An insert needs no such reasoning, because the
// primary key is the thing being contended for.
func (s *Store) PutAtVersionTx(ctx context.Context, ext sqlx.ExtContext, cfg AppConfig, expectedVersion int64, updatedBy string) error {
	if expectedVersion > 0 {
		return s.PutTx(ctx, ext, cfg, expectedVersion, updatedBy)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("appconfig: marshal: %w", err)
	}
	by := updatedBy
	if by == "" {
		by = api.PrincipalSystemID
	}
	_, err = ext.ExecContext(ctx, `INSERT INTO app_config (id, config, version, updated_by) VALUES (1, ?, 1, ?)`, encoded, by)
	if isDuplicateKey(err) {
		return ErrVersionConflict
	}
	if err != nil {
		return fmt.Errorf("appconfig: put insert at version: %w", err)
	}
	return nil
}

// mysqlErrDupEntry is the MySQL "Duplicate entry" code. A collision on the singleton primary key means another writer created the
// row first, which for a write conditioned on "there was nothing here" is a conflict to report rather than a failure.
//
// Local rather than shared, as in identity's rbac, seed, oidc and breakglass packages: arch-go confines this context's internal
// packages to identity's own tree plus a short allowlist, and server/sqlhelpers (where IsDeadlockErr lives) is not on it.
const mysqlErrDupEntry = 1062

func isDuplicateKey(err error) bool {
	var mysqlErr *mysql.MySQLError
	// Early-return rather than `errors.As(...) && mysqlErr.Number == ...`: the one-liner trips nilaway, which cannot prove mysqlErr
	// is non-nil across the && short-circuit.
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDupEntry
}
