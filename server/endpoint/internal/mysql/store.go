package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/endpoint/internal/revocation"
)

const (
	// hostTokenBase64Len is the base64url-no-padding length of a tokenLen-byte token (tokenLen lives in hash.go). For n bytes the encoded
	// length is ceil(n*4/3), computed as (n*4+2)/3. It is derived from tokenLen rather than hard-coded so a future tokenLen bump stays in
	// sync without a second edit. Anything else is a malformed presentation; we reject before the DB lookup.
	hostTokenBase64Len = (tokenLen*4 + 2) / 3

	// tokenIDPrefixBytes is how many leading bytes of a host_token_id we hex-encode for audit metadata (8 hex chars). Long enough to
	// disambiguate in operator UIs, short enough that the prefix stays a credential-free identifier.
	tokenIDPrefixBytes = 4

	// minPepperLen is the floor for the HMAC pepper, matching the HKDF-SHA256 output width the keyring derives. A shorter pepper would
	// make host-token hashing effectively unkeyed, so NewStore treats it as a fatal wiring bug.
	minPepperLen = 32
)

// Enrollment mirrors the `enrollments` row shape used by admin listings. The raw token hash is intentionally not exported;
// callers that need to verify a token go through Verify, not direct row access.
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

// Store owns the `enrollments` table. It is backed by *sqlx.DB (the store package already opens one via otelsql.Open); we take a db
// handle rather than the full *store.Store so this package stays unit-testable with a plain sqlx.DB. The pepper is the server-held
// HMAC key (derived from the deployment root secret) every token hash + verify keys on.
type Store struct {
	db     *sqlx.DB
	pepper []byte
}

// NewStore constructs an enrollment store over an existing sqlx.DB handle. pepper is the HMAC key used to hash and verify host tokens
// (the endpoint bootstrap derives it from the deployment root key via internal/keyring). NewStore enforces the minPepperLen minimum
// with a panic: a short pepper would make host-token hashing effectively unkeyed, which is a fatal wiring bug, not a recoverable
// runtime condition (the only callers are bootstrap, which validates first, and tests). The pepper is cloned so a later mutation of
// the caller's slice cannot change the store's key material out from under in-flight verifications.
func NewStore(db *sqlx.DB, pepper []byte) *Store {
	if len(pepper) < minPepperLen {
		panic(fmt.Sprintf("mysql.NewStore: host-token pepper must be at least %d bytes, got %d", minPepperLen, len(pepper)))
	}
	return &Store{db: db, pepper: bytes.Clone(pepper)}
}

// RegisterRequest captures the inputs to a successful enrollment. The presented secret has already been validated by the handler;
// by the time Register is called we're committed to issuing a token.
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

// Register issues a new token for HostID and replaces any existing row keyed by host_id. The enrollments table holds the *current*
// enrollment state only; an older design called for an archive UPDATE before REPLACE, but REPLACE on the primary key deletes and
// re-inserts the row, so "re-enrolled" audit metadata cannot survive in the same row. Enrollment history (revocation reasons, who
// revoked, etc.) is deferred to a dedicated history table; for the MVP, the audit trail lives in structured logs emitted by handler.go
// (enroll) and admin.go (revoke).
func (s *Store) Register(ctx context.Context, req RegisterRequest) (*RegisterResult, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	hash := hashToken(s.pepper, token)
	tokID := tokenID(token)

	// One app-clock timestamp for both enrolled_at and host_token_issued_at: on enroll they denote the same instant (the schema
	// comment relies on that equality), and the verify path's rotation-age check reads host_token_issued_at against the app clock,
	// so sourcing it from the app clock rather than the DB default keeps a single clock per write.
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		REPLACE INTO enrollments (
			host_id, host_token_id, host_token_hash,
			hostname, agent_version, os_version, source_ip,
			enrolled_at, host_token_issued_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		req.HostID, tokID, hash,
		req.Hostname, req.AgentVersion, req.OSVersion, req.SourceIP,
		now, now,
	); err != nil {
		return nil, fmt.Errorf("insert enrollment: %w", err)
	}

	return &RegisterResult{
		HostID:     req.HostID,
		HostToken:  token,
		EnrolledAt: now,
	}, nil
}

// VerifyResult is the rotation-aware shape returned by VerifyWithMeta: HostID identifies the matched enrollment, CurrentTokenID is
// the SHA-256 of the matched token (used by the service layer as the optimistic-lock key for RotateHostToken), TokenIssuedAt is the
// current token's issue timestamp (the rotation-eligibility input), and MatchedPrevious tells the caller whether the verify succeeded
// against the grace-window previous token (in which case rotation is already in flight and the caller must NOT trigger another).
type VerifyResult struct {
	HostID          string
	CurrentTokenID  []byte
	TokenIssuedAt   time.Time
	MatchedPrevious bool
}

// Verify is the thin wrapper that callers who only need the host_id keep using; new callers (the service-level rotation trigger) reach
// for VerifyWithMeta below.
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
// O(1) lookup, then keyed HMAC verify). On miss, fall back to the previous
// token via previous_host_token_id WHERE previous_token_expires_at is still
// ahead of the app clock (bound as a query parameter, not DB NOW()): this is
// the grace window the rotation flow opens.
func (s *Store) VerifyWithMeta(ctx context.Context, token string) (VerifyResult, error) {
	if token == "" {
		return VerifyResult{}, ErrTokenMismatch
	}
	// Bearer tokens have 32 bytes of entropy (43 base64url chars); short-circuit obviously bad lengths before the DB lookup.
	if len(token) != hostTokenBase64Len {
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

// verifyAgainstCurrent does the host_token_id lookup. ok=false means the row was not found (caller should fall through to
// previous-token path); any other error is surfaced as-is. ok=true with err=nil is the happy path; ok=true with ErrTokenMismatch means
// the row was found but the HMAC verify failed (treat as mismatch, do NOT fall through to previous since that would be redundant
// computation against the same host).
func (s *Store) verifyAgainstCurrent(ctx context.Context, token string, tid []byte) (VerifyResult, bool, error) {
	var row struct {
		HostID   string    `db:"host_id"`
		Hash     []byte    `db:"host_token_hash"`
		IssuedAt time.Time `db:"host_token_issued_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT host_id, host_token_hash, host_token_issued_at
		FROM enrollments
		WHERE host_token_id = ? AND revoked_at IS NULL
	`, tid)
	if errors.Is(err, sql.ErrNoRows) {
		return VerifyResult{}, false, nil
	}
	if err != nil {
		return VerifyResult{}, false, fmt.Errorf("query enrollment by token id: %w", err)
	}
	if !verifyToken(s.pepper, token, row.Hash) {
		// Token_id match but hash mismatch would require a SHA-256 collision; treat as mismatch rather than internal error and
		// do not fall through to previous-token lookup (which is for a different token entirely, by id).
		return VerifyResult{}, true, ErrTokenMismatch
	}
	return VerifyResult{
		HostID:         row.HostID,
		CurrentTokenID: tid,
		TokenIssuedAt:  row.IssuedAt,
	}, true, nil
}

// verifyAgainstPrevious does the previous_host_token_id lookup, gated on previous_token_expires_at being ahead of the app clock (bound
// as a query parameter, not DB NOW()). Returns the same
// VerifyResult shape with MatchedPrevious=true so the service layer skips the rotation trigger (rotation is already in flight; another
// would be wasteful).
func (s *Store) verifyAgainstPrevious(ctx context.Context, token string, tid []byte) (VerifyResult, error) {
	var row struct {
		HostID   string    `db:"host_id"`
		Hash     []byte    `db:"previous_host_token_hash"`
		IssuedAt time.Time `db:"host_token_issued_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT host_id, previous_host_token_hash, host_token_issued_at
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
	if !verifyToken(s.pepper, token, row.Hash) {
		return VerifyResult{}, ErrTokenMismatch
	}
	return VerifyResult{
		HostID:          row.HostID,
		CurrentTokenID:  nil, // intentionally nil: caller must not trigger rotation against a previous-token match
		TokenIssuedAt:   row.IssuedAt,
		MatchedPrevious: true,
	}, nil
}

// RotateResult carries the freshly minted token + audit-friendly metadata back to the caller. NewToken is the raw bearer the service
// layer queues into a rotate_token command for the agent. PreviousTokenIDPrefix is the first 8 hex chars of the prior host_token_id,
// included on the audit row so reviewers can correlate a rotation to the verify request that triggered it without storing the full
// token id (which is preimage-resistant but still a per-host identifier).
type RotateResult struct {
	NewToken              string
	PreviousTokenIDPrefix string
}

// RotateHostToken atomically swaps a host's bearer token: generates a
// fresh (id, hash), captures the existing values into previous_*,
// sets previous_token_expires_at = now + grace, and updates
// host_token_issued_at to now, where now is a single app-clock
// time.Now().UTC() bound as a parameter (not DB-side NOW(); see the
// inline comment at the UPDATE). The atomic UPDATE is keyed on the
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
	newHash := hashToken(s.pepper, newToken)
	newID := tokenID(newToken)
	// Single app-clock timestamp: previous_token_expires_at and host_token_issued_at are both derived from it so the grace expiry
	// and the new token's issue time share one clock (the verify path also reads both against the app clock).
	now := time.Now().UTC()
	expiresAt := now.Add(grace)

	res, err := s.db.ExecContext(ctx, `
		UPDATE enrollments
		SET previous_host_token_id    = host_token_id,
		    previous_host_token_hash  = host_token_hash,
		    previous_token_expires_at = ?,
		    host_token_id             = ?,
		    host_token_hash           = ?,
		    host_token_issued_at      = ?
		WHERE host_id = ? AND host_token_id = ? AND revoked_at IS NULL
	`, expiresAt, newID, newHash, now, hostID, currentTokenID)
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
	if len(currentTokenID) >= tokenIDPrefixBytes {
		prefix = hex.EncodeToString(currentTokenID[:tokenIDPrefixBytes])
	}
	return RotateResult{
		NewToken:              newToken,
		PreviousTokenIDPrefix: prefix,
	}, nil
}

// RotateHostTokenForce is the operator-driven counterpart to
// RotateHostToken: it commits a rotation regardless of recent
// rotations, gated only on (host exists AND not revoked). Used by the
// POST /api/enrollments/{host_id}/rotate handler where the operator's
// intent is "issue a fresh token NOW," not "rotate only if no other
// rotation slipped in." Returns ErrNotFound when the host has no
// non-revoked enrollment.
//
// Internally a SELECT FOR UPDATE inside a tx serialises concurrent
// operator-clicks for the same host so the previous_* slot reflects
// the most recently superseded token (not whichever one a non-locked
// UPDATE happened to read mid-flip). The same SET-clause ordering rule
// applies as RotateHostToken: previous_* assignments must come before
// the host_* assignments since MySQL evaluates left-to-right.
func (s *Store) RotateHostTokenForce(ctx context.Context, hostID string, grace time.Duration) (RotateResult, error) {
	if hostID == "" {
		return RotateResult{}, errors.New("RotateHostTokenForce: hostID is required")
	}
	if grace <= 0 {
		return RotateResult{}, errors.New("RotateHostTokenForce: grace must be > 0")
	}

	newToken, err := generateToken()
	if err != nil {
		return RotateResult{}, err
	}
	newHash := hashToken(s.pepper, newToken)
	newID := tokenID(newToken)
	// Single app-clock timestamp for the grace expiry and the new token's issue time (see RotateHostToken).
	now := time.Now().UTC()
	expiresAt := now.Add(grace)

	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate force begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var currentID []byte
	err = tx.GetContext(ctx, &currentID, `
		SELECT host_token_id FROM enrollments
		WHERE host_id = ? AND revoked_at IS NULL
		FOR UPDATE
	`, hostID)
	if errors.Is(err, sql.ErrNoRows) {
		return RotateResult{}, ErrNotFound
	}
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate force lock: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE enrollments
		SET previous_host_token_id    = host_token_id,
		    previous_host_token_hash  = host_token_hash,
		    previous_token_expires_at = ?,
		    host_token_id             = ?,
		    host_token_hash           = ?,
		    host_token_issued_at      = ?
		WHERE host_id = ? AND revoked_at IS NULL
	`, expiresAt, newID, newHash, now, hostID); err != nil {
		return RotateResult{}, fmt.Errorf("rotate force update: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return RotateResult{}, fmt.Errorf("rotate force commit: %w", err)
	}
	committed = true

	prefix := ""
	if len(currentID) >= tokenIDPrefixBytes {
		prefix = hex.EncodeToString(currentID[:tokenIDPrefixBytes])
	}
	return RotateResult{
		NewToken:              newToken,
		PreviousTokenIDPrefix: prefix,
	}, nil
}

// CountActive returns how many non-revoked enrollments exist. Cheaper than ActiveHostIDs when the caller only needs the count. The
// OTel gauge `edr.enrolled.hosts` is the primary caller.
func (s *Store) CountActive(ctx context.Context) (int, error) {
	var n int
	if err := s.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM enrollments WHERE revoked_at IS NULL`); err != nil {
		return 0, fmt.Errorf("count active enrollments: %w", err)
	}
	return n, nil
}

// ActiveHostIDs returns the host_id of every currently-active (non-revoked) enrollment. Used to fan out policy updates to the set of
// hosts that still have a valid token; returning just the id column keeps the payload small when the caller is already going to look
// up the full row by id.
func (s *Store) ActiveHostIDs(ctx context.Context) ([]string, error) {
	var ids []string
	if err := s.db.SelectContext(ctx, &ids, `
		SELECT host_id FROM enrollments WHERE revoked_at IS NULL ORDER BY host_id
	`); err != nil {
		return nil, fmt.Errorf("list active host ids: %w", err)
	}
	return ids, nil
}

// List returns every enrollment row, active + revoked, for the admin UI. The token hash
// column is intentionally omitted.
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

// Revoke marks a host's enrollment as revoked. Idempotent: calling Revoke a second time preserves the original revoked_at +
// revoke_reason + revoked_by. Returns sql.ErrNoRows if the host_id is not in the table at all.
func (s *Store) Revoke(ctx context.Context, hostID, reason, actor string) error {
	// Verify the row exists first so "not found" and "already revoked" are distinguishable in
	// RowsAffected: MySQL's affected-rows counter excludes no-op updates.
	var exists bool
	err := s.db.GetContext(ctx, &exists, `SELECT 1 FROM enrollments WHERE host_id = ?`, hostID)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	if err != nil {
		return fmt.Errorf("revoke lookup: %w", err)
	}

	// Only set the columns when they are still null. COALESCE preserves the original revoke_reason/revoked_by across subsequent revoke
	// calls, so the first revoker's audit trail is the source of truth.
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

// BumpTokenEpoch increments a host's token_epoch by one, invalidating every signed token minted at the prior epoch. This is the
// operator-driven "cycle this host's credentials" action under the self-validating-token model: there is no opaque token to rotate, so
// revocation of the current credential is expressed as an epoch bump that the per-replica revocation snapshot then enforces. The agent
// recovers by re-enrolling (its refresh, carrying the now-stale epoch, 401s). Returns ErrNotFound when the host has no enrollment row.
func (s *Store) BumpTokenEpoch(ctx context.Context, hostID string) error {
	if hostID == "" {
		return errors.New("BumpTokenEpoch: hostID is required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE enrollments SET token_epoch = token_epoch + 1 WHERE host_id = ?`, hostID)
	if err != nil {
		return fmt.Errorf("bump token epoch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("bump token epoch rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TokenStatus returns a host's current token_epoch and whether it is revoked. Used by the refresh path (not the hot verify path) to
// mint a new token at the host's current epoch and to refuse refresh for a revoked host. Returns ErrNotFound when the host has no
// enrollment row.
func (s *Store) TokenStatus(ctx context.Context, hostID string) (epoch int64, revoked bool, err error) {
	var row struct {
		Epoch   int64 `db:"token_epoch"`
		Revoked int   `db:"revoked"`
	}
	e := s.db.GetContext(ctx, &row, `
		SELECT token_epoch, IF(revoked_at IS NOT NULL, 1, 0) AS revoked
		FROM enrollments
		WHERE host_id = ?
	`, hostID)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, false, ErrNotFound
	}
	if e != nil {
		return 0, false, fmt.Errorf("token status: %w", e)
	}
	return row.Epoch, row.Revoked != 0, nil
}

// RevocationEntries returns every host that is revoked or has a non-zero token_epoch: the minimal set the revocation snapshot needs to
// reject cut-off or cycled tokens. The bulk of a fleet is neither, so the result stays small even at large host counts. Implements
// revocation.Source.
func (s *Store) RevocationEntries(ctx context.Context) ([]revocation.Entry, error) {
	var rows []struct {
		HostID  string `db:"host_id"`
		Epoch   int64  `db:"token_epoch"`
		Revoked int    `db:"revoked"`
	}
	// IF(...,1,0) rather than the bare boolean expression: the MySQL driver yields int64 for a boolean column expression, which
	// database/sql will not Scan into a Go bool, so we select an explicit int and map it below.
	if err := s.db.SelectContext(ctx, &rows, `
		SELECT host_id, token_epoch, IF(revoked_at IS NOT NULL, 1, 0) AS revoked
		FROM enrollments
		WHERE token_epoch > 0 OR revoked_at IS NOT NULL
	`); err != nil {
		return nil, fmt.Errorf("load revocation entries: %w", err)
	}
	out := make([]revocation.Entry, len(rows))
	for i, r := range rows {
		out[i] = revocation.Entry{HostID: r.HostID, Epoch: r.Epoch, Revoked: r.Revoked != 0}
	}
	return out, nil
}

// ErrNotFound mirrors sql.ErrNoRows without leaking the database concept to callers that
// do not import database/sql.
var ErrNotFound = errors.New("enrollment: not found")
