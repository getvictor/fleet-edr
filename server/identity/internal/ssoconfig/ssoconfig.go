package ssoconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// ErrNotFound is returned by the Get methods when no oidc_config row exists (OIDC has not been configured for the deployment).
var ErrNotFound = errors.New("ssoconfig: not configured")

// Config is the resolved OIDC configuration callers see. ClientSecret is populated ONLY by GetDecrypted (the login/resolver path);
// Get leaves it empty and reports presence via HasSecret so the admin read API can never serialize the secret. Scopes is the parsed
// list. Version is config_version, bumped on every Upsert, used by the per-replica provider cache to detect a change.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	HasSecret    bool
	RedirectURL  string
	Scopes       []string
	JITEnabled   bool
	DefaultRole  string
	Version      int64
	UpdatedAt    time.Time
	UpdatedBy    sql.NullInt64
}

// row is the raw DB shape; client_secret_enc stays sealed until GetDecrypted opens it.
type row struct {
	Issuer          string        `db:"issuer"`
	ClientID        string        `db:"client_id"`
	ClientSecretEnc []byte        `db:"client_secret_enc"`
	RedirectURL     string        `db:"redirect_url"`
	Scopes          string        `db:"scopes"`
	JITEnabled      bool          `db:"jit_enabled"`
	DefaultRole     string        `db:"default_role"`
	Version         int64         `db:"config_version"`
	UpdatedAt       time.Time     `db:"updated_at"`
	UpdatedBy       sql.NullInt64 `db:"updated_by"`
}

// UpsertInput is the write shape. NewSecret nil leaves the stored secret unchanged (rotate-only semantics); a non-nil pointer (even to
// "") rotates it to the sealed new value. UpdatedBy nil records an env-seed (no operator); non-nil records the acting user id.
type UpsertInput struct {
	Issuer      string
	ClientID    string
	NewSecret   *string
	RedirectURL string
	Scopes      []string
	JITEnabled  bool
	DefaultRole string
	UpdatedBy   *int64
}

// Store owns the oidc_config table. It holds the Sealer so secret sealing/opening stays co-located with persistence.
type Store struct {
	db     *sqlx.DB
	sealer *Sealer
}

// New constructs a Store. Panics if db or sealer is nil: a Store that cannot read the DB or seal the secret has no useful behavior.
func New(db *sqlx.DB, sealer *Sealer) *Store {
	if db == nil {
		panic("ssoconfig.New: db must not be nil")
	}
	if sealer == nil {
		panic("ssoconfig.New: sealer must not be nil")
	}
	return &Store{db: db, sealer: sealer}
}

const selectConfig = `
	SELECT issuer, client_id, client_secret_enc, redirect_url, scopes, jit_enabled, default_role,
	       config_version, updated_at, updated_by
	FROM oidc_config
	WHERE id = 1`

func (s *Store) fetch(ctx context.Context) (*row, error) {
	var r row
	err := s.db.GetContext(ctx, &r, selectConfig)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("ssoconfig: fetch: %w", err)
	}
	return &r, nil
}

func toConfig(r *row) *Config {
	return &Config{
		Issuer:      r.Issuer,
		ClientID:    r.ClientID,
		HasSecret:   len(r.ClientSecretEnc) > 0,
		RedirectURL: r.RedirectURL,
		Scopes:      splitScopes(r.Scopes),
		JITEnabled:  r.JITEnabled,
		DefaultRole: r.DefaultRole,
		Version:     r.Version,
		UpdatedAt:   r.UpdatedAt,
		UpdatedBy:   r.UpdatedBy,
	}
}

// Get returns the configuration WITHOUT the client secret. HasSecret reports whether one is set. This is the read used by the admin
// API so the plaintext secret is never loaded into a response path.
func (s *Store) Get(ctx context.Context) (*Config, error) {
	r, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	return toConfig(r), nil
}

// GetDecrypted returns the configuration WITH the plaintext client secret opened. Used only by the OIDC login/resolver path that needs
// the secret to perform the token exchange. A sealed-but-unopenable secret (e.g. after a root-key rotation) surfaces as an error.
func (s *Store) GetDecrypted(ctx context.Context) (*Config, error) {
	r, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c := toConfig(r)
	if len(r.ClientSecretEnc) > 0 {
		pt, err := s.sealer.Open(r.ClientSecretEnc)
		if err != nil {
			return nil, fmt.Errorf("ssoconfig: decrypt client secret: %w", err)
		}
		c.ClientSecret = string(pt)
	}
	return c, nil
}

// Upsert writes the singleton row. On first write it inserts id=1 with config_version=1; on a subsequent write it updates the row and
// increments config_version. When NewSecret is nil the existing sealed secret is preserved (the UPDATE clause omits the secret
// column); when non-nil it seals and stores the new value.
func (s *Store) Upsert(ctx context.Context, in UpsertInput) error {
	scopes := strings.Join(in.Scopes, ",")
	var updatedBy sql.NullInt64
	if in.UpdatedBy != nil {
		updatedBy = sql.NullInt64{Int64: *in.UpdatedBy, Valid: true}
	}

	if in.NewSecret != nil {
		sealed, err := s.sealer.Seal([]byte(*in.NewSecret))
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO oidc_config
				(id, issuer, client_id, client_secret_enc, redirect_url, scopes, jit_enabled, default_role, config_version, updated_by)
			VALUES (1, ?, ?, ?, ?, ?, ?, ?, 1, ?)
			ON DUPLICATE KEY UPDATE
				issuer = VALUES(issuer), client_id = VALUES(client_id), client_secret_enc = VALUES(client_secret_enc),
				redirect_url = VALUES(redirect_url), scopes = VALUES(scopes), jit_enabled = VALUES(jit_enabled),
				default_role = VALUES(default_role), config_version = config_version + 1, updated_by = VALUES(updated_by)`,
			in.Issuer, in.ClientID, sealed, in.RedirectURL, scopes, in.JITEnabled, in.DefaultRole, updatedBy)
		if err != nil {
			return fmt.Errorf("ssoconfig: upsert with secret: %w", err)
		}
		return nil
	}

	// No secret change: insert with NULL secret (first boot), and on update leave client_secret_enc untouched.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_config
			(id, issuer, client_id, client_secret_enc, redirect_url, scopes, jit_enabled, default_role, config_version, updated_by)
		VALUES (1, ?, ?, NULL, ?, ?, ?, ?, 1, ?)
		ON DUPLICATE KEY UPDATE
			issuer = VALUES(issuer), client_id = VALUES(client_id),
			redirect_url = VALUES(redirect_url), scopes = VALUES(scopes), jit_enabled = VALUES(jit_enabled),
			default_role = VALUES(default_role), config_version = config_version + 1, updated_by = VALUES(updated_by)`,
		in.Issuer, in.ClientID, in.RedirectURL, scopes, in.JITEnabled, in.DefaultRole, updatedBy)
	if err != nil {
		return fmt.Errorf("ssoconfig: upsert: %w", err)
	}
	return nil
}

// splitScopes parses the comma-joined scopes column into a trimmed, empty-dropped slice. Returns nil for an empty/whitespace column so
// callers fall through to their default scope set.
func splitScopes(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
