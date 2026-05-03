package mysql

import (
	"context"
	"database/sql"
	"encoding/hex"
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

// VerifyResult is the rotation-aware shape returned by VerifyWithMeta:
// HostID identifies the matched enrollment, CurrentTokenID is the
// SHA-256 of the matched token (used by the service layer as the
// optimistic-lock key for RotateHostToken), TokenIssuedAt is the
// current token's issue timestamp (the rotation-eligibility input),
// and MatchedPrevious tells the caller whether the verify succeeded
// against the grace-window previous token (in which case rotation is
// already in flight and the caller must NOT trigger another).
type VerifyResult struct {
	HostID          string
	CurrentTokenID  []byte
	TokenIssuedAt   time.Time
	MatchedPrevious bool
}

// Verify is the thin wrapper that callers who only need the host_id keep
// using; new callers (the service-level rotation trigger) reach for
// VerifyWithMeta below.
func (s *Store) Verify(ctx context.Context, token string) (string, error) {
	r, err := s.VerifyWithMeta(ctx, token)
	if err != nil {
		return "", err
	}
	return r.HostID, nil
}

// VerifyWithMeta returns the host_id + rotation metadata for a presented
// token, or ErrTokenMismatch on any kind of mismatch (unknown token,
// revoked enrollment, expired previous-token grace, hash mismatch).
//
// Implementation: try the current token first by host_token_id (SHA-256
// O(1) lookup, then argon2id verify). On miss, fall back to the previous
// token via previous_host_token_id WHERE previous_token_expires_at >
// NOW(): this is the grace window the rotation flow opens. Both lookups
// pay one argon2id evaluation on a hit; a miss against the current path
// still pays one argon2id on the previous path before declaring
// mismatch, which is intentional rate-limiting against guessing.
func (s *Store) VerifyWithMeta(ctx context.Context, token string) (VerifyResult, error) {
	if token == "" {
		return VerifyResult{}, ErrTokenMismatch
	}
	// Bearer tokens have 32 bytes of entropy (43 base64url chars); short-circuit obviously bad
	// lengths before paying the argon2 price.
	if len(token) != 43 {
		return VerifyResult{}, ErrTokenMismatch
	}
	tid := tokenID(token)

	if r, ok, err := s.verifyAgainstCurrent(ctx, token, tid); err != nil {
		return VerifyResult{}, err
	} else if ok {
		return r, nil
	}
	return s.verifyAgainstPrevious(ctx, token, tid)
}

// verifyAgainstCurrent does the host_token_id lookup. ok=false means the
// row was not found (caller should fall through to previous-token path);
// any other error is surfaced as-is. ok=true with err=nil is the happy
// path; ok=true with ErrTokenMismatch means the row was found but the
// argon2id verify failed (treat as mismatch, do NOT fall through to
// previous since that would be redundant computation against the same
// host).
func (s *Store) verifyAgainstCurrent(ctx context.Context, token string, tid []byte) (VerifyResult, bool, error) {
	var row struct {
		HostID   string    `db:"host_id"`
		Hash     []byte    `db:"host_token_hash"`
		Salt     []byte    `db:"host_token_salt"`
		IssuedAt time.Time `db:"host_token_issued_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT host_id, host_token_hash, host_token_salt, host_token_issued_at
		FROM enrollments
		WHERE host_token_id = ? AND revoked_at IS NULL
	`, tid)
	if errors.Is(err, sql.ErrNoRows) {
		return VerifyResult{}, false, nil
	}
	if err != nil {
		return VerifyResult{}, false, fmt.Errorf("query enrollment by token id: %w", err)
	}
	if !verifyToken(token, row.Hash, row.Salt) {
		// Token_id match but hash mismatch would require a SHA-256 collision; treat as
		// mismatch rather than internal error and do not fall through to previous-token
		// lookup (which is for a different token entirely, by id).
		return VerifyResult{}, true, ErrTokenMismatch
	}
	return VerifyResult{
		HostID:         row.HostID,
		CurrentTokenID: tid,
		TokenIssuedAt:  row.IssuedAt,
	}, true, nil
}

// verifyAgainstPrevious does the previous_host_token_id lookup, gated on
// previous_token_expires_at > NOW. Returns the same VerifyResult shape
// with MatchedPrevious=true so the service layer skips the rotation
// trigger (rotation is already in flight; another would be wasteful).
func (s *Store) verifyAgainstPrevious(ctx context.Context, token string, tid []byte) (VerifyResult, error) {
	var row struct {
		HostID   string    `db:"host_id"`
		Hash     []byte    `db:"previous_host_token_hash"`
		Salt     []byte    `db:"previous_host_token_salt"`
		IssuedAt time.Time `db:"host_token_issued_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT host_id, previous_host_token_hash, previous_host_token_salt, host_token_issued_at
		FROM enrollments
		WHERE previous_host_token_id = ?
		  AND revoked_at IS NULL
		  AND previous_token_expires_at IS NOT NULL
		  AND previous_token_expires_at > ?
	`, tid, time.Now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		return VerifyResult{}, ErrTokenMismatch
	}
	if err != nil {
		return VerifyResult{}, fmt.Errorf("query enrollment by previous token id: %w", err)
	}
	if !verifyToken(token, row.Hash, row.Salt) {
		return VerifyResult{}, ErrTokenMismatch
	}
	return VerifyResult{
		HostID:          row.HostID,
		CurrentTokenID:  nil, // intentionally nil: caller must not trigger rotation against a previous-token match
		TokenIssuedAt:   row.IssuedAt,
		MatchedPrevious: true,
	}, nil
}

// RotateResult carries the freshly minted token + audit-friendly metadata
// back to the caller. NewToken is the raw bearer the service layer
// queues into a rotate_token command for the agent. PreviousTokenIDPrefix
// is the first 8 hex chars of the prior host_token_id, included on the
// audit row so reviewers can correlate a rotation to the verify request
// that triggered it without storing the full token id (which is
// preimage-resistant but still a per-host identifier).
type RotateResult struct {
	NewToken              string
	PreviousTokenIDPrefix string
}

// RotateHostToken atomically swaps a host's bearer token: generates a
// fresh (id, hash, salt), captures the existing values into previous_*,
// sets previous_token_expires_at = NOW + grace, and updates
// host_token_issued_at to NOW. The atomic UPDATE is keyed on the
// currentTokenID the caller asserts (typically the value returned from
// a recent VerifyWithMeta), so two concurrent rotations serialise:
// only the one whose currentTokenID matches the row's host_token_id
// commits; the loser's UPDATE affects 0 rows and returns
// ErrRotateRaced. Callers map ErrRotateRaced to a "no-op, the other
// rotation already swapped the token" branch.
//
// The UPDATE uses LEFT-side ordering carefully (previous_* before
// host_*) because MySQL evaluates SET assignments left-to-right and
// uses the new value for subsequent right-side reads. Reversing the
// order would copy the NEW host_token_id into previous_host_token_id,
// not the old one.
func (s *Store) RotateHostToken(ctx context.Context, hostID string, currentTokenID []byte, grace time.Duration) (RotateResult, error) {
	if hostID == "" {
		return RotateResult{}, errors.New("RotateHostToken: hostID is required")
	}
	if len(currentTokenID) == 0 {
		return RotateResult{}, errors.New("RotateHostToken: currentTokenID is required")
	}
	if grace <= 0 {
		return RotateResult{}, errors.New("RotateHostToken: grace must be > 0")
	}

	newToken, err := generateToken()
	if err != nil {
		return RotateResult{}, err
	}
	newHash, newSalt, err := hashToken(newToken)
	if err != nil {
		return RotateResult{}, err
	}
	newID := tokenID(newToken)
	expiresAt := time.Now().UTC().Add(grace)

	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollments
		SET previous_host_token_id    = host_token_id,
		    previous_host_token_hash  = host_token_hash,
		    previous_host_token_salt  = host_token_salt,
		    previous_token_expires_at = ?,
		    host_token_id             = ?,
		    host_token_hash           = ?,
		    host_token_salt           = ?,
		    host_token_issued_at      = CURRENT_TIMESTAMP(6)
		WHERE host_id = ? AND host_token_id = ? AND revoked_at IS NULL
	`, expiresAt, newID, newHash, newSalt, hostID, currentTokenID)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate host token: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate rows affected: %w", err)
	}
	if affected == 0 {
		return RotateResult{}, ErrRotateRaced
	}

	prefix := ""
	if len(currentTokenID) >= 4 {
		prefix = hex.EncodeToString(currentTokenID[:4])
	}
	return RotateResult{
		NewToken:              newToken,
		PreviousTokenIDPrefix: prefix,
	}, nil
}

// CountActive returns how many non-revoked enrollments exist. Cheaper than
// ActiveHostIDs when the caller only needs the count — Phase 4's OTel gauge
// `edr.enrolled.hosts` is the primary caller.
func (s *Store) CountActive(ctx context.Context) (int, error) {
	var n int
	if err := s.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM enrollments WHERE revoked_at IS NULL`); err != nil {
		return 0, fmt.Errorf("count active enrollments: %w", err)
	}
	return n, nil
}

// ActiveHostIDs returns the host_id of every currently-active (non-revoked) enrollment.
// Phase 2 uses this to fan out policy updates to the set of hosts that still have a
// valid token; returning just the id column keeps the payload small when the caller is
// already going to look up the full row by id.
func (s *Store) ActiveHostIDs(ctx context.Context) ([]string, error) {
	var ids []string
	if err := s.db.SelectContext(ctx, &ids, `
		SELECT host_id FROM enrollments WHERE revoked_at IS NULL ORDER BY host_id
	`); err != nil {
		return nil, fmt.Errorf("list active host ids: %w", err)
	}
	return ids, nil
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
