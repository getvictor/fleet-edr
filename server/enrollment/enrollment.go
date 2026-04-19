package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// Enrollment mirrors the `enrollments` row shape used by admin listings. The raw token hash
// and salt are intentionally not exported; callers that need to verify a token go through
// Verify, not direct row access.
type Enrollment struct {
	HostID       string     `db:"host_id" json:"host_id"`
	Hostname     string     `db:"hostname" json:"hostname"`
	AgentVersion string     `db:"agent_version" json:"agent_version"`
	OSVersion    string     `db:"os_version" json:"os_version"`
	SourceIP     string     `db:"source_ip" json:"source_ip"`
	EnrolledAt   time.Time  `db:"enrolled_at" json:"enrolled_at"`
	ExpiresAt    *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	RevokedAt    *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	RevokeReason *string    `db:"revoke_reason" json:"revoke_reason,omitempty"`
	RevokedBy    *string    `db:"revoked_by" json:"revoked_by,omitempty"`
}

// Store owns the `enrollments` table. It is backed by *sqlx.DB (the store package already
// opens one via otelsql.Open); we take a db handle rather than the full *store.Store so this
// package stays unit-testable with a plain sqlx.DB.
type Store struct {
	db *sqlx.DB
}

// NewStore constructs an enrollment store over an existing sqlx.DB handle.
func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// RegisterRequest captures the inputs to a successful enrollment. The presented secret has
// already been validated by the handler; by the time Register is called we're committed to
// issuing a token.
type RegisterRequest struct {
	HostID       string
	Hostname     string
	AgentVersion string
	OSVersion    string
	SourceIP     string
}

// RegisterResult carries the generated token back to the caller.
type RegisterResult struct {
	HostID     string
	HostToken  string
	EnrolledAt time.Time
}

// Register issues a new token for HostID and replaces any existing row keyed by host_id. The
// enrollments table holds the *current* enrollment state only; an older design called for an
// archive UPDATE before REPLACE, but REPLACE on the primary key deletes and re-inserts the
// row, so "re-enrolled" audit metadata cannot survive in the same row. Enrollment history
// (revocation reasons, who revoked, etc.) will live in a dedicated history table in Phase 4;
// for the MVP, the audit trail lives in structured logs emitted by handler.go (enroll) and
// admin.go (revoke).
func (s *Store) Register(ctx context.Context, req RegisterRequest) (*RegisterResult, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	hash, salt, err := hashToken(token)
	if err != nil {
		return nil, err
	}
	tokID := tokenID(token)

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		REPLACE INTO enrollments (
			host_id, host_token_id, host_token_hash, host_token_salt,
			hostname, agent_version, os_version, source_ip,
			enrolled_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.HostID, tokID, hash, salt,
		req.Hostname, req.AgentVersion, req.OSVersion, req.SourceIP,
		now,
	); err != nil {
		return nil, fmt.Errorf("insert enrollment: %w", err)
	}

	return &RegisterResult{
		HostID:     req.HostID,
		HostToken:  token,
		EnrolledAt: now,
	}, nil
}

// Verify returns the host_id associated with token, or an error. Returns ErrTokenMismatch
// when the token does not match any active enrollment — callers should map that to 401.
//
// Implementation: look up the single candidate row by host_token_id (SHA-256 of the token),
// then run argon2id verify against that row's hash+salt. This is O(1) regardless of fleet
// size, and the argon2id step is still run on every auth so DB theft doesn't yield usable
// tokens.
func (s *Store) Verify(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrTokenMismatch
	}
	// Bearer tokens have 32 bytes of entropy (43 base64url chars); short-circuit obviously bad
	// lengths before paying the argon2 price.
	if len(token) != 43 {
		return "", ErrTokenMismatch
	}

	var row struct {
		HostID string `db:"host_id"`
		Hash   []byte `db:"host_token_hash"`
		Salt   []byte `db:"host_token_salt"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT host_id, host_token_hash, host_token_salt
		FROM enrollments
		WHERE host_token_id = ? AND revoked_at IS NULL
	`, tokenID(token))
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrTokenMismatch
	}
	if err != nil {
		return "", fmt.Errorf("query enrollment by token id: %w", err)
	}
	if !verifyToken(token, row.Hash, row.Salt) {
		// Token_id match but hash mismatch would require a SHA-256 collision — treat as
		// mismatch rather than internal error.
		return "", ErrTokenMismatch
	}
	return row.HostID, nil
}

// List returns every enrollment row, active + revoked, for the admin UI. The token hash/salt
// columns are intentionally omitted.
func (s *Store) List(ctx context.Context) ([]Enrollment, error) {
	var rows []Enrollment
	err := s.db.SelectContext(ctx, &rows, `
		SELECT host_id, hostname, agent_version, os_version, source_ip,
		       enrolled_at, expires_at, revoked_at, revoke_reason, revoked_by
		FROM enrollments
		ORDER BY enrolled_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	return rows, nil
}

// Get returns a single enrollment. Returns sql.ErrNoRows when absent.
func (s *Store) Get(ctx context.Context, hostID string) (*Enrollment, error) {
	var e Enrollment
	err := s.db.GetContext(ctx, &e, `
		SELECT host_id, hostname, agent_version, os_version, source_ip,
		       enrolled_at, expires_at, revoked_at, revoke_reason, revoked_by
		FROM enrollments
		WHERE host_id = ?
	`, hostID)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Revoke marks a host's enrollment as revoked. Idempotent: calling Revoke a second time
// preserves the original revoked_at + revoke_reason + revoked_by. Returns sql.ErrNoRows
// if the host_id is not in the table at all.
func (s *Store) Revoke(ctx context.Context, hostID, reason, actor string) error {
	// Verify the row exists first so "not found" and "already revoked" are distinguishable in
	// RowsAffected — MySQL's affected-rows counter excludes no-op updates.
	var exists bool
	err := s.db.GetContext(ctx, &exists, `SELECT 1 FROM enrollments WHERE host_id = ?`, hostID)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	if err != nil {
		return fmt.Errorf("revoke lookup: %w", err)
	}

	// Only set the columns when they are still null. COALESCE preserves the original
	// revoke_reason/revoked_by across subsequent revoke calls, so the first revoker's audit
	// trail is the source of truth.
	_, err = s.db.ExecContext(ctx, `
		UPDATE enrollments
		SET revoked_at    = COALESCE(revoked_at, ?),
		    revoke_reason = COALESCE(revoke_reason, ?),
		    revoked_by    = COALESCE(revoked_by, ?)
		WHERE host_id = ?
	`, time.Now().UTC(), reason, actor, hostID)
	if err != nil {
		return fmt.Errorf("revoke enrollment: %w", err)
	}
	return nil
}

// ErrNotFound mirrors sql.ErrNoRows without leaking the database concept to callers that
// do not import database/sql.
var ErrNotFound = errors.New("enrollment: not found")
