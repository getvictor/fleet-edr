package breakglass

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jmoiron/sqlx"
)

// ErrCredentialClonedDetected is returned by RecordAssertion when the
// authenticator's reported sign_count has not advanced past the
// stored value. Per WebAuthn §6.1.1, a sign_count regression
// indicates the credential was cloned (or that the authenticator
// itself does not maintain a counter, which the implementation is
// permitted to ignore — but for break-glass we treat any regression
// as suspicious and refuse the assertion).
var ErrCredentialClonedDetected = errors.New("breakglass: webauthn sign_count regression — possible cloned credential")

// ErrCredentialNotFound is returned by FindByID when no row matches
// the supplied credential id. Distinguished from a generic store
// error so the assertion handler can map it to the directed
// `webauthn.unknown_credential` reason.
var ErrCredentialNotFound = errors.New("breakglass: webauthn credential not found")

// CredentialRow is the storage shape backing webauthn_credentials.
// Mirrors the schema ordering used by the assertion + registration
// flows; the "exported" fields here are read+written together via
// CredentialStore methods (no direct field-by-field exposure).
type CredentialRow struct {
	ID           int64          `db:"id"`
	UserID       int64          `db:"user_id"`
	CredentialID []byte         `db:"credential_id"`
	PublicKey    []byte         `db:"public_key"`
	SignCount    uint64         `db:"sign_count"`
	Transports   sql.NullString `db:"transports"`
	Name         sql.NullString `db:"name"`
	CreatedAt    time.Time      `db:"created_at"`
	LastUsedAt   sql.NullTime   `db:"last_used_at"`
}

// CredentialStore owns the webauthn_credentials table.
type CredentialStore struct {
	db *sqlx.DB
}

// NewCredentialStore constructs a CredentialStore. Panics on nil db
// to match the pattern used by sibling stores.
func NewCredentialStore(db *sqlx.DB) *CredentialStore {
	if db == nil {
		panic("breakglass.NewCredentialStore: db must not be nil")
	}
	return &CredentialStore{db: db}
}

// InsertWith persists a freshly-registered WebAuthn credential. Runs
// against a caller-supplied executor (typically *sqlx.Tx) so the
// insert lands in the same transaction as the bootstrap-token
// redemption + password set, preserving the spec's atomic-redemption
// guarantee.
func (s *CredentialStore) InsertWith(ctx context.Context, ec sqlxExec, userID int64, c webauthn.Credential, name string) (int64, error) {
	transports := encodeTransports(c.Transport)
	res, err := ec.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, name)
		VALUES (?, ?, ?, ?, ?, ?)
	`, userID, c.ID, c.PublicKey, c.Authenticator.SignCount,
		nullableString(transports), nullableString(strings.TrimSpace(name)))
	if err != nil {
		return 0, fmt.Errorf("breakglass credentials: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("breakglass credentials: last insert id: %w", err)
	}
	return id, nil
}

// ListByUserID returns every credential owned by the user. The
// assertion ceremony reads ALL credentials at once because go-webauthn
// matches the assertion against the union before deciding which
// credential signed; per-credential lookup would require trusting the
// browser's claim about which one it used, which a tampered assertion
// could spoof.
func (s *CredentialStore) ListByUserID(ctx context.Context, userID int64) ([]CredentialRow, error) {
	rows := []CredentialRow{}
	err := s.db.SelectContext(ctx, &rows, `
		SELECT id, user_id, credential_id, public_key, sign_count,
		       transports, name, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = ?
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("breakglass credentials: list: %w", err)
	}
	return rows, nil
}

// RecordAssertion bumps sign_count + last_used_at after a successful
// FinishLogin. Rejects with ErrCredentialClonedDetected when the
// authenticator's reported counter has not advanced past the stored
// value (WebAuthn §6.1.1). The atomicity guarantee here is weaker
// than InsertWith on purpose: a successful login that fails to
// record sign_count is still a successful login (the user already
// proved possession), but the missed update means the next attempt
// can no longer detect a clone via this credential. The slog WARN
// preserves the signal.
func (s *CredentialStore) RecordAssertion(ctx context.Context, credID []byte, newSignCount uint32) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET sign_count   = ?,
		    last_used_at = NOW(6)
		WHERE credential_id = ?
		  AND ? > sign_count
	`, newSignCount, credID, newSignCount)
	if err != nil {
		return fmt.Errorf("breakglass credentials: record assertion: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("breakglass credentials: rows affected: %w", err)
	}
	if n == 0 {
		// The UPDATE matched zero rows. Either the credential was
		// removed mid-flight (vanishingly rare) OR the new
		// sign_count did not exceed the stored one. Probe the row
		// to discriminate; only the regression case is a security
		// alarm.
		var stored uint64
		err = s.db.GetContext(ctx, &stored,
			`SELECT sign_count FROM webauthn_credentials WHERE credential_id = ?`,
			credID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCredentialNotFound
		}
		if err != nil {
			return fmt.Errorf("breakglass credentials: probe sign_count: %w", err)
		}
		if uint64(newSignCount) <= stored {
			return ErrCredentialClonedDetected
		}
		// Defensive: row exists, sign_count is fine, but UPDATE
		// matched zero. Should not happen; treat as transient and
		// surface as not-found so the operator retries.
		return ErrCredentialNotFound
	}
	return nil
}

// FindByID returns the row for a single credential id (raw bytes,
// not base64). Used by the login form's GET handler to assert at
// least one credential exists for the user before issuing a
// challenge — a user with zero credentials cannot satisfy WebAuthn
// at all and the form should render an admin-recovery hint
// instead.
func (s *CredentialStore) FindByID(ctx context.Context, credID []byte) (*CredentialRow, error) {
	var row CredentialRow
	err := s.db.GetContext(ctx, &row, `
		SELECT id, user_id, credential_id, public_key, sign_count,
		       transports, name, created_at, last_used_at
		FROM webauthn_credentials
		WHERE credential_id = ?
	`, credID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("breakglass credentials: find: %w", err)
	}
	return &row, nil
}

// ToWebauthnCredentials converts a slice of stored rows into the
// shape go-webauthn expects on the User interface's
// WebAuthnCredentials method. Pulled out so the User adapter and
// any future migration code can share the conversion.
func ToWebauthnCredentials(rows []CredentialRow) []webauthn.Credential {
	out := make([]webauthn.Credential, len(rows))
	for i, r := range rows {
		// SignCount is uint64 in the schema (matches MySQL UNSIGNED
		// BIGINT); the WebAuthn library carries uint32 because the
		// authenticatorData wire shape uses 32 bits. A counter that
		// somehow exceeds uint32 indicates either a bug in the
		// authenticator or a tampered database row; clamp to MaxUint32
		// so the comparison still rejects future regressions
		// deterministically.
		signCount := min(r.SignCount, math.MaxUint32)
		//nolint:gosec // signCount is clamped to MaxUint32 above; the conversion is safe.
		out[i] = webauthn.Credential{
			ID:        r.CredentialID,
			PublicKey: r.PublicKey,
			Transport: decodeTransports(r.Transports.String),
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(signCount),
			},
		}
	}
	return out
}

// encodeTransports collapses a slice of go-webauthn transport
// constants into a comma-separated wire string for the
// transports column. The schema uses VARCHAR(64) so a malicious
// authenticator advertising thousands of transports cannot blow
// the column; the join is bounded to 64 bytes by the DDL.
func encodeTransports(ts []protocol.AuthenticatorTransport) string {
	if len(ts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		s := strings.TrimSpace(string(t))
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

// decodeTransports is the inverse: take the persisted string,
// split on comma, return the typed slice for go-webauthn.
func decodeTransports(s string) []protocol.AuthenticatorTransport {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]protocol.AuthenticatorTransport, 0, len(raw))
	for _, p := range raw {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, protocol.AuthenticatorTransport(t))
		}
	}
	return out
}

// nullableString wraps a string in sql.NullString so the empty case
// inserts NULL rather than the empty string (the column allows NULL
// but disallows the empty string semantically — credentials without
// a name should read NULL when listed).
func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
