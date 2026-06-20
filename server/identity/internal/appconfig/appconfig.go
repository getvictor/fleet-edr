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
)

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

// Put writes the whole document, inserting the singleton row on first write (version 1) and bumping version on update. Callers that
// change one field should Get, mutate, then Put (read-modify-write) so unrelated fields are preserved. updatedBy nil records a
// non-operator write (env seed).
func (s *Store) Put(ctx context.Context, cfg AppConfig, updatedBy *int64) error {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("appconfig: marshal: %w", err)
	}
	var by sql.NullInt64
	if updatedBy != nil {
		by = sql.NullInt64{Int64: *updatedBy, Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO app_config (id, config, version, updated_by)
		VALUES (1, ?, 1, ?)
		ON DUPLICATE KEY UPDATE
			config = VALUES(config), version = version + 1, updated_by = VALUES(updated_by)`,
		encoded, by)
	if err != nil {
		return fmt.Errorf("appconfig: put: %w", err)
	}
	return nil
}
