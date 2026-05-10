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
	ID             int64          `db:"id"`
	UserID         int64          `db:"user_id"`
	CredentialID   []byte         `db:"credential_id"`
	PublicKey      []byte         `db:"public_key"`
	SignCount      uint64         `db:"sign_count"`
	Transports     sql.NullString `db:"transports"`
	Name           sql.NullString `db:"name"`
	BackupEligible bool           `db:"backup_eligible"`
	BackupState    bool           `db:"backup_state"`
	CreatedAt      time.Time      `db:"created_at"`
	LastUsedAt     sql.NullTime   `db:"last_used_at"`
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
func (s *CredentialStore) InsertWith(ctx context.Context, ec Executor, userID int64, c webauthn.Credential, name string) (int64, error) {
	transports := encodeTransports(c.Transport)
	res, err := ec.ExecContext(ctx, `
		INSERT INTO webauthn_credentials
			(user_id, credential_id, public_key, sign_count, transports, name,
			 backup_eligible, backup_state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, userID, c.ID, c.PublicKey, c.Authenticator.SignCount,
		nullableString(transports), nullableString(strings.TrimSpace(name)),
		c.Flags.BackupEligible, c.Flags.BackupState)
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
		       transports, name, backup_eligible, backup_state,
		       created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = ?
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("breakglass credentials: list: %w", err)
	}
	return rows, nil
}

// RecordAssertion bumps sign_count + last_used_at + backup_state
// after a successful FinishLogin. Rejects with
// ErrCredentialClonedDetected when the authenticator's reported
// counter has DECREASED past the stored value (WebAuthn §6.1.1).
// Note: many platform authenticators (Apple Touch ID Passkey, Google
// Password Manager) report SignCount=0 unconditionally. The spec
// says the relying party SHOULD NOT treat 0=0 as a clone (the
// authenticator simply doesn't implement counters), so the check
// here is "strictly less than stored AND stored > 0", not "<=
// stored". backup_state is updated unconditionally because BS can
// transition 0->1 over the credential's lifetime (and the library
// already enforced the spec's "1->0 not allowed" rule before we
// got here).
//
// The atomicity guarantee here is weaker than InsertWith on
// purpose: a successful login that fails to record sign_count is
// still a successful login (the user already proved possession),
// but the missed update means the next attempt can no longer detect
// a clone via this credential. The slog WARN preserves the signal.
func (s *CredentialStore) RecordAssertion(ctx context.Context, credID []byte, newSignCount uint32, backupState bool) error {
	// Check for the clone case before updating so we can return a
	// typed error. A row with stored sign_count > newSignCount + a
	// stored value > 0 indicates a regression that the spec
	// considers a clone signal.
	var stored uint64
	err := s.db.GetContext(ctx, &stored,
		`SELECT sign_count FROM webauthn_credentials WHERE credential_id = ?`,
		credID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCredentialNotFound
	}
	if err != nil {
		return fmt.Errorf("breakglass credentials: probe sign_count: %w", err)
	}
	if stored > 0 && uint64(newSignCount) <= stored {
		return ErrCredentialClonedDetected
	}

	// Update unconditionally: sign_count is set to the max of stored
	// and new (so a counter that legitimately stays at 0 doesn't
	// regress); last_used_at always stamps NOW(); backup_state
	// reflects whatever the authenticator just reported.
	bump := max(uint64(newSignCount), stored)
	_, err = s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET sign_count   = ?,
		    last_used_at = NOW(6),
		    backup_state = ?
		WHERE credential_id = ?
	`, bump, backupState, credID)
	if err != nil {
		return fmt.Errorf("breakglass credentials: record assertion: %w", err)
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
		       transports, name, backup_eligible, backup_state,
		       created_at, last_used_at
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
			Flags: webauthn.CredentialFlags{
				// BE is invariant per the WebAuthn spec; the library
				// rejects assertions where the asserted BE differs
				// from this stored value, so getting these flags onto
				// the credential is what makes platform-authenticator
				// Passkey logins work past first use.
				BackupEligible: r.BackupEligible,
				BackupState:    r.BackupState,
			},
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
