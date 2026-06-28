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
	var rawConfig []byte
	var version int64
	err := s.db.QueryRowxContext(ctx, `SELECT config, version FROM app_config WHERE id = 1`).Scan(&rawConfig, &version)
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
