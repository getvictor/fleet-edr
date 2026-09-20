package ssoconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
)

// ErrNotFound is returned by the Get methods when no oidc_config row exists (OIDC has not been configured for the deployment).
var ErrNotFound = errors.New("ssoconfig: not configured")

// ErrVersionConflict is returned by UpsertAtVersionTx when the stored configuration moved on since the caller read it: another
// writer saved in between, or, on a first save, won the race to create it. Nothing is written.
var ErrVersionConflict = errors.New("ssoconfig: it was changed since it was read")

// Config is the resolved OIDC configuration callers see. ClientSecret is populated ONLY by GetDecrypted (the login/resolver path);
// Get leaves it empty and reports presence via HasSecret so the admin read API can never serialize the secret. Scopes is the parsed
// list. Version is config_version, bumped on every Upsert, used by the per-replica provider cache to detect a change.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	HasSecret    bool
	Scopes       []string
	JITEnabled   bool
	DefaultRole  string
	// GroupsClaim names the ID-token claim listing the operator's IdP groups. Empty means group to role mapping is off.
	GroupsClaim string
	// GroupRoles maps IdP groups to roles, in the order the admin entered them.
	GroupRoles []GroupRole
	Version    int64
	UpdatedAt  time.Time
	UpdatedBy  sql.NullString
}

// GroupRole grants Role to the members of the IdP group Group. The JSON shape is both the stored column's and the admin API's.
type GroupRole struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// CallbackPath is the OIDC redirect/callback route the server serves. The registered redirect URI is the deployment external URL +
// CallbackPath; the external URL lives in the appconfig document, not here.
const CallbackPath = "/api/auth/callback"

// RedirectURLFor derives the OIDC redirect URI from a deployment external URL: a single trailing slash on the base is tolerated so
// "https://edr.acme.com" and "https://edr.acme.com/" both yield "https://edr.acme.com/api/auth/callback". A query string or fragment on
// the base is dropped rather than concatenated into the path, so a stray "?x=1" can't produce a malformed callback. Returns "" for an
// empty base so callers can detect an unconfigured deployment.
func RedirectURLFor(externalURL string) string {
	if externalURL == "" {
		return ""
	}
	u, err := url.Parse(externalURL)
	if err != nil || u.Host == "" {
		// Unparseable base: fall back to the trim-and-concat form. The admin path validates the external URL before persisting, so
		// this branch only covers legacy/env-seeded values.
		return strings.TrimRight(externalURL, "/") + CallbackPath
	}
	u.RawQuery = ""
	u.Fragment = ""
	// ForceQuery is set for a bare trailing "?"; clear it too so String() can't emit a stray trailing "?".
	u.ForceQuery = false
	u.Path = strings.TrimRight(u.Path, "/") + CallbackPath
	return u.String()
}

// row is the raw DB shape; client_secret_enc stays sealed until GetDecrypted opens it.
type row struct {
	Issuer          string         `db:"issuer"`
	ClientID        string         `db:"client_id"`
	ClientSecretEnc []byte         `db:"client_secret_enc"`
	Scopes          string         `db:"scopes"`
	JITEnabled      bool           `db:"jit_enabled"`
	DefaultRole     string         `db:"default_role"`
	GroupsClaim     string         `db:"groups_claim"`
	GroupRoles      []byte         `db:"group_roles"`
	Version         int64          `db:"config_version"`
	UpdatedAt       time.Time      `db:"updated_at"`
	UpdatedBy       sql.NullString `db:"updated_by"`
}

// UpsertInput is the write shape. NewSecret nil leaves the stored secret unchanged (rotate-only semantics); a non-nil pointer (even to
// "") rotates it to the sealed new value. Every other field replaces what is stored, the group mapping included, so a writer that
// leaves it empty turns mapping off. UpdatedBy nil records an env-seed (no operator); non-nil records the acting user id.
type UpsertInput struct {
	Issuer      string
	ClientID    string
	NewSecret   *string
	Scopes      []string
	JITEnabled  bool
	DefaultRole string
	GroupsClaim string
	GroupRoles  []GroupRole
	UpdatedBy   string
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
	SELECT issuer, client_id, client_secret_enc, scopes, jit_enabled, default_role, groups_claim, group_roles,
	       config_version, updated_at, updated_by
	FROM oidc_config
	WHERE id = 1`

func (s *Store) fetch(ctx context.Context) (*row, error) {
	return fetchFrom(ctx, s.db)
}

// fetchFrom reads the singleton row from any executor, so a caller can take the read inside a transaction alongside another table's
// and get one snapshot rather than two reads a concurrent writer can land between.
func fetchFrom(ctx context.Context, ext sqlx.ExtContext) (*row, error) {
	var r row
	err := sqlx.GetContext(ctx, ext, &r, selectConfig)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("ssoconfig: fetch: %w", err)
	}
	return &r, nil
}

// GetTx is Get against a caller-supplied executor. The SSO settings surface reads oidc_config and app_config in one transaction,
// because a version paired with a value read a moment later describes a state that never existed, and a client that sends such a
// version back passes the concurrency check holding stale data (issue #1046).
func (s *Store) GetTx(ctx context.Context, ext sqlx.ExtContext) (*Config, error) {
	r, err := fetchFrom(ctx, ext)
	if err != nil {
		return nil, err
	}
	return toConfig(r)
}

// encodeGroupRoles is the group_roles column value for pairs: NULL for none ([]byte(nil) is what binds as NULL), otherwise the JSON
// array. GroupRole holds only strings, so encoding it cannot fail.
func encodeGroupRoles(pairs []GroupRole) []byte {
	if len(pairs) == 0 {
		return nil
	}
	encoded, _ := json.Marshal(pairs)
	return encoded
}

func toConfig(r *row) (*Config, error) {
	var groupRoles []GroupRole
	if r.GroupRoles != nil {
		if err := json.Unmarshal(r.GroupRoles, &groupRoles); err != nil {
			return nil, fmt.Errorf("ssoconfig: decode group_roles: %w", err)
		}
	}
	return &Config{
		Issuer:      r.Issuer,
		ClientID:    r.ClientID,
		HasSecret:   len(r.ClientSecretEnc) > 0,
		Scopes:      splitScopes(r.Scopes),
		JITEnabled:  r.JITEnabled,
		DefaultRole: r.DefaultRole,
		GroupsClaim: r.GroupsClaim,
		GroupRoles:  groupRoles,
		Version:     r.Version,
		UpdatedAt:   r.UpdatedAt,
		UpdatedBy:   r.UpdatedBy,
	}, nil
}

// Get returns the configuration WITHOUT the client secret. HasSecret reports whether one is set. This is the read used by the admin
// API so the plaintext secret is never loaded into a response path.
func (s *Store) Get(ctx context.Context) (*Config, error) {
	r, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	return toConfig(r)
}

// GetDecrypted returns the configuration WITH the plaintext client secret opened. Used only by the OIDC login/resolver path that needs
// the secret to perform the token exchange. A sealed-but-unopenable secret (e.g. after a root-key rotation) surfaces as an error.
func (s *Store) GetDecrypted(ctx context.Context) (*Config, error) {
	r, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c, err := toConfig(r)
	if err != nil {
		return nil, err
	}
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
	return s.UpsertTx(ctx, s.db, in)
}

// UpsertTx is Upsert against a caller-supplied executor (*sqlx.Tx or the Store's *sqlx.DB), so the write can join a transaction that
// also updates other tables atomically (e.g. the SSO admin update that writes oidc_config and app_config together).
const (
	upsertRotatingClientKey = `
		INSERT INTO oidc_config
			(id, issuer, client_id, client_secret_enc, scopes, jit_enabled, default_role, groups_claim, group_roles, config_version, updated_by)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
		ON DUPLICATE KEY UPDATE
			issuer = VALUES(issuer), client_id = VALUES(client_id), client_secret_enc = VALUES(client_secret_enc),
			scopes = VALUES(scopes), jit_enabled = VALUES(jit_enabled), default_role = VALUES(default_role),
			groups_claim = VALUES(groups_claim), group_roles = VALUES(group_roles),
			config_version = config_version + 1, updated_by = VALUES(updated_by)`
	upsertKeepingClientKey = `
		INSERT INTO oidc_config
			(id, issuer, client_id, client_secret_enc, scopes, jit_enabled, default_role, groups_claim, group_roles, config_version, updated_by)
		VALUES (1, ?, ?, NULL, ?, ?, ?, ?, ?, 1, ?)
		ON DUPLICATE KEY UPDATE
			issuer = VALUES(issuer), client_id = VALUES(client_id),
			scopes = VALUES(scopes), jit_enabled = VALUES(jit_enabled), default_role = VALUES(default_role),
			groups_claim = VALUES(groups_claim), group_roles = VALUES(group_roles),
			config_version = config_version + 1, updated_by = VALUES(updated_by)`
	// The conditional forms, used when the caller names the version it read. The UPDATE matches nothing when the row has moved on,
	// and the INSERT is deliberately NOT an upsert: on a first save it is what gives two racing writers a defined winner, the loser
	// taking a duplicate-key error rather than silently overwriting (issue #1046). Locking the row first is not an option there,
	// because there is no row yet to lock.
	updateRotatingClientKey = `
		UPDATE oidc_config SET
			issuer = ?, client_id = ?, client_secret_enc = ?, scopes = ?, jit_enabled = ?, default_role = ?,
			groups_claim = ?, group_roles = ?, config_version = config_version + 1, updated_by = ?
		WHERE id = 1 AND config_version = ?`
	updateKeepingClientKey = `
		UPDATE oidc_config SET
			issuer = ?, client_id = ?, scopes = ?, jit_enabled = ?, default_role = ?,
			groups_claim = ?, group_roles = ?, config_version = config_version + 1, updated_by = ?
		WHERE id = 1 AND config_version = ?`
	insertRotatingClientKey = `
		INSERT INTO oidc_config
			(id, issuer, client_id, client_secret_enc, scopes, jit_enabled, default_role, groups_claim, group_roles, config_version, updated_by)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
	insertKeepingClientKey = `
		INSERT INTO oidc_config
			(id, issuer, client_id, client_secret_enc, scopes, jit_enabled, default_role, groups_claim, group_roles, config_version, updated_by)
		VALUES (1, ?, ?, NULL, ?, ?, ?, ?, ?, 1, ?)`
)

// upsertValues is the column set every write binds, so the unconditional and the conditional paths cannot drift in what they write.
// sealed is nil when the stored secret is kept, which is a different statement rather than a different value: writing NULL there
// would clear the secret instead of preserving it.
type upsertValues struct {
	scopes     string
	updatedBy  string
	groupRoles []byte
	sealed     []byte
	rotating   bool
}

func (s *Store) upsertValues(in UpsertInput) (upsertValues, error) {
	v := upsertValues{
		scopes: strings.Join(in.Scopes, ","),
		// An unset updater records the system principal (env-seed / background write), matching the column's NOT NULL DEFAULT 'sys'
		// and its FK to principals(id); an empty string would violate the FK.
		updatedBy:  in.UpdatedBy,
		groupRoles: encodeGroupRoles(in.GroupRoles),
	}
	if v.updatedBy == "" {
		v.updatedBy = api.PrincipalSystemID
	}
	if in.NewSecret != nil {
		sealed, err := s.sealer.Seal([]byte(*in.NewSecret))
		if err != nil {
			return upsertValues{}, err
		}
		v.sealed, v.rotating = sealed, true
	}
	return v, nil
}

func (s *Store) UpsertTx(ctx context.Context, ext sqlx.ExtContext, in UpsertInput) error {
	v, err := s.upsertValues(in)
	if err != nil {
		return err
	}
	// The two statements differ only in whether they write the sealed client secret column.
	if v.rotating {
		_, err = ext.ExecContext(ctx, upsertRotatingClientKey,
			in.Issuer, in.ClientID, v.sealed, v.scopes, in.JITEnabled, in.DefaultRole, in.GroupsClaim, v.groupRoles, v.updatedBy)
	} else {
		// No secret change: insert with NULL secret (first boot), and on update leave client_secret_enc untouched.
		_, err = ext.ExecContext(ctx, upsertKeepingClientKey,
			in.Issuer, in.ClientID, v.scopes, in.JITEnabled, in.DefaultRole, in.GroupsClaim, v.groupRoles, v.updatedBy)
	}
	if err != nil {
		return fmt.Errorf("ssoconfig: upsert: %w", err)
	}
	return nil
}

// UpsertAtVersionTx is UpsertTx conditioned on the version the caller read, and writes nothing when the stored configuration has
// moved on since (issue #1046). expectedVersion 0 means "there was no configuration": that is written as a plain INSERT rather than
// an upsert, so two writers racing to create the first configuration have a defined winner and the loser is told, instead of the
// second silently replacing the first.
func (s *Store) UpsertAtVersionTx(ctx context.Context, ext sqlx.ExtContext, in UpsertInput, expectedVersion int64) error {
	v, err := s.upsertValues(in)
	if err != nil {
		return err
	}
	if expectedVersion <= 0 {
		if v.rotating {
			_, err = ext.ExecContext(ctx, insertRotatingClientKey,
				in.Issuer, in.ClientID, v.sealed, v.scopes, in.JITEnabled, in.DefaultRole, in.GroupsClaim, v.groupRoles, v.updatedBy)
		} else {
			_, err = ext.ExecContext(ctx, insertKeepingClientKey,
				in.Issuer, in.ClientID, v.scopes, in.JITEnabled, in.DefaultRole, in.GroupsClaim, v.groupRoles, v.updatedBy)
		}
		if isDuplicateKey(err) {
			return ErrVersionConflict
		}
		if err != nil {
			return fmt.Errorf("ssoconfig: insert at version: %w", err)
		}
		return nil
	}
	var res sql.Result
	if v.rotating {
		res, err = ext.ExecContext(ctx, updateRotatingClientKey,
			in.Issuer, in.ClientID, v.sealed, v.scopes, in.JITEnabled, in.DefaultRole, in.GroupsClaim, v.groupRoles, v.updatedBy,
			expectedVersion)
	} else {
		res, err = ext.ExecContext(ctx, updateKeepingClientKey,
			in.Issuer, in.ClientID, v.scopes, in.JITEnabled, in.DefaultRole, in.GroupsClaim, v.groupRoles, v.updatedBy, expectedVersion)
	}
	if err != nil {
		return fmt.Errorf("ssoconfig: update at version: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("ssoconfig: update at version rows-affected: %w", err)
	}
	if rows == 0 {
		return ErrVersionConflict
	}
	return nil
}

// splitScopes parses the comma-joined scopes column into a trimmed, empty-dropped slice. Returns nil for an empty/whitespace column so
// callers fall through to their default scope set.
func splitScopes(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(csv, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
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
