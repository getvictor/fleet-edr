// Package users owns the `users` table that backs UI login. The store exposes a minimal CRUD surface (Create, GetByEmail) because MVP
// has exactly one admin account. Anything more is v1.1. Password hashing uses argon2id with the same parameter set as the enrollment
// token hash so a future consolidation into a shared `passcrypto` package is mechanical.
package users

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/argon2"
)

// argon2id parameters per OWASP Password Storage Cheat Sheet 2024. ~30 ms per hash on M-series Mac; the hot path (login verify) hashes
// at most once per login attempt and we rate-limit logins, so CPU-DoS via login-storm is capped.
//
// Package-level vars (not consts) so the init() below can lower them under `go test`. Tests at this package and downstream
// (identity/internal/breakglass, identity/internal/tests) pay an argon2id hash per case; at production cost they dominated CI wall
// clock (issue #170). The pattern mirrors bcrypt's MinCost/DefaultCost split; argon2 has no library constant for it, so we follow
// RFC 9106's minimum (t=1, m=8 MiB, p=1) for the test build only. Production binaries keep the OWASP-2024 cost.
var (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
)

const (
	argonKeyLen  uint32 = 32
	argonSaltLen int    = 16
)

func init() {
	if testing.Testing() {
		argonTime = 1
		argonMemory = 8 * 1024 // 8 MiB, RFC 9106 minimum
		argonThreads = 1
	}
}

// User is the storage row. The password_hash / password_salt columns are intentionally
// not exposed on the struct so callers that log a User can't accidentally leak them.
//
// IsBreakglass backs the wave-1 user-management surface; the AuthZ
// chokepoint reads it when building the per-request Actor.
type User struct {
	ID           int64  `db:"id" json:"id"`
	Email        string `db:"email" json:"email"`
	IsBreakglass bool   `db:"is_breakglass" json:"is_breakglass"`
	// Status is the account status ("active" / "disabled"). LoadActor reads it to lock a disabled account out of every authed request
	// (#135). Populated by Get; other read paths that don't select it leave it empty, which is treated as active.
	Status    string    `db:"status" json:"status"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// ErrNotFound is returned by GetByEmail when no row matches.
var ErrNotFound = errors.New("users: not found")

// ErrBadPassword is returned by VerifyPassword when the presented password doesn't match the stored hash. Kept separate from
// ErrNotFound so callers can emit identical 401s to the client (preventing email enumeration) while differentiating reasons in the
// server-side audit log.
var ErrBadPassword = errors.New("users: password mismatch")

// ErrExistingNonBreakglass is returned by CreateBreakglass when a row for the requested email already exists with is_breakglass=0.
// Caller (seed.Admin / cmd/main wave-0 migration check) handles the wave-0 non-breakglass admin via an operator runbook rather than
// destructively rewriting the row.
var ErrExistingNonBreakglass = errors.New("users: existing non-breakglass user")

// errEmailRequired is the canonical message every "email is required" path emits. Lifted to a const so Sonar's S1192 (duplicated
// literal) stays satisfied as new helpers land.
const errEmailRequired = "users: email is required"

// errPasswordRequired is the password-required twin: same Sonar
// S1192 reasoning. Used by Create, HashPassword, and SetPassword.
const errPasswordRequired = "users: password is required"

// Store owns the users table.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store over an existing sqlx.DB handle.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// CreateRequest is the shape accepted by Create. The plaintext password is hashed before
// it touches the DB; the caller never sees the hash bytes.
type CreateRequest struct {
	Email    string
	Password string
}

// Create inserts a new user and returns the row (without the hash/salt). Email is normalised to lowercase + trimmed before the
// uniqueness check. Customer admins like to type "Admin@Example.COM" and expect it to resolve to the same account.
func (s *Store) Create(ctx context.Context, req CreateRequest) (*User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, errors.New(errEmailRequired)
	}
	if req.Password == "" {
		return nil, errors.New(errPasswordRequired)
	}
	hash, salt, err := hashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (email, password_hash, password_salt) VALUES (?, ?, ?)
	`, email, hash, salt)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert id: %w", err)
	}
	return s.Get(ctx, id)
}

// CreateOIDCRequest is the shape accepted by CreateOIDC. password_* columns are NULL on the resulting row: OIDC users have no
// server-stored credential, only an external identity binding.
type CreateOIDCRequest struct {
	Email string
}

// CreateOIDC inserts a new user without a password and returns a
// synthesized row carrying the inserted id + normalised email. Email
// is normalised the same way Create does. Caller passes an *sqlx.Tx
// executor so the JIT provisioner can roll the whole flow back if the
// identity insert or role binding fails downstream.
//
// The returned User does NOT round-trip through Get because Get reads
// against s.db (outside the caller's tx) and the in-flight INSERT is
// invisible until commit. The synthesized row carries enough fields
// for the JIT path's audit + session-mint; CreatedAt/UpdatedAt are
// left zero (the audit row carries the wall clock independently).
func (s *Store) CreateOIDC(ctx context.Context, ec Executor, req CreateOIDCRequest) (*User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, errors.New(errEmailRequired)
	}
	res, err := ec.ExecContext(ctx,
		`INSERT INTO users (email) VALUES (?)`,
		email)
	if err != nil {
		return nil, fmt.Errorf("insert oidc user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert id: %w", err)
	}
	return &User{
		ID:           id,
		Email:        email,
		IsBreakglass: false,
	}, nil
}

// Executor is the subset of sqlx.Tx / sqlx.DB that CreateOIDC (and any future under-transaction insert) consumes. Lets the JIT
// provisioner pass a *sqlx.Tx without the users package importing the JIT or transaction-management code. Named per the Go convention
// (single-method interface ends in -er).
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// CreateBreakglassRequest is the shape accepted by CreateBreakglass. password_* columns are NULL on the resulting row: the
// break-glass redemption flow sets them later in the same transaction that consumes the bootstrap token.
type CreateBreakglassRequest struct {
	Email string
}

// CreateBreakglass inserts the wave-1 break-glass admin user with is_breakglass=1 and NULL password. Idempotent on email: returns the
// existing row when one is present so first-boot seeding is safe to re-run on container restart. Used by seed/admin.go.
func (s *Store) CreateBreakglass(ctx context.Context, req CreateBreakglassRequest) (*User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, errors.New(errEmailRequired)
	}
	// INSERT ... ON DUPLICATE KEY UPDATE id=id is the canonical MySQL idiom for "INSERT IGNORE that returns the row id". Plain INSERT
	// IGNORE doesn't populate LastInsertId on duplicate, which would leave the caller without an id. The no-op UPDATE keeps the INSERT
	// path cheap on repeated calls.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (email, is_breakglass)
		VALUES (?, 1)
		ON DUPLICATE KEY UPDATE id = id
	`, email)
	if err != nil {
		return nil, fmt.Errorf("upsert breakglass user: %w", err)
	}
	var u User
	err = s.db.GetContext(ctx, &u, `
		SELECT id, email, is_breakglass, created_at, updated_at
		FROM users WHERE email = ?
	`, email)
	if err != nil {
		return nil, fmt.Errorf("read breakglass user: %w", err)
	}
	// A pre-existing row at the same email that is NOT is_breakglass came from the wave-0 schema (admin with a printed password). Surface
	// a typed error so the caller (seed.Admin / cmd/main wave-0 migration) can handle it explicitly via the operator runbook rather than
	// silently flipping the row's flag and stranding the existing password.
	if !u.IsBreakglass {
		return &u, ErrExistingNonBreakglass
	}
	return &u, nil
}

// HashPassword runs argon2id over the plaintext and returns the resulting (hash, salt) pair. Exported so callers (specifically the
// break-glass FinishSetup flow) can do the CPU-intensive hash BEFORE opening a database transaction. Argon2 holds locks for ~30ms per
// call on M-series hardware, which is unacceptable inside a multi-statement transaction.
func HashPassword(password string) (hash, salt []byte, err error) {
	if password == "" {
		return nil, nil, errors.New(errPasswordRequired)
	}
	return hashPassword(password)
}

// SetPassword updates password_hash + password_salt for an existing user. Argon2id-hashed via the same helper Create uses. Runs
// against a caller-supplied executor (typically *sqlx.Tx) so the break-glass redemption flow can wrap the password set + credential
// persist + identity insert in one transaction.
func (s *Store) SetPassword(ctx context.Context, ec Executor, userID int64, password string) error {
	if password == "" {
		return errors.New(errPasswordRequired)
	}
	hash, salt, err := hashPassword(password)
	if err != nil {
		return err
	}
	return s.SetHashedPassword(ctx, ec, userID, hash, salt)
}

// SetHashedPassword updates password_hash + password_salt for an existing user using a pre-computed argon2 hash. Skips the argon2 CPU
// work: caller MUST have computed (hash, salt) via HashPassword or an equivalent argon2id-compatible helper. Used by the break-glass
// FinishSetup flow so the hash runs OUTSIDE the redemption tx.
func (s *Store) SetHashedPassword(ctx context.Context, ec Executor, userID int64, hash, salt []byte) error {
	if len(hash) == 0 || len(salt) == 0 {
		return errors.New("users: hash + salt are required")
	}
	res, err := ec.ExecContext(ctx, `
		UPDATE users SET password_hash = ?, password_salt = ?
		WHERE id = ?
	`, hash, salt, userID)
	if err != nil {
		return fmt.Errorf("set password for user %d: %w", userID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected for set password: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetByEmail looks up a user row by its normalised email. Returns ErrNotFound when no row matches. Distinct from VerifyPassword
// because the break-glass login flow needs the user id BEFORE password verification (to look up the user's WebAuthn credentials and
// issue the assertion challenge against them).
func (s *Store) GetByEmail(ctx context.Context, email string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var u User
	err := s.db.GetContext(ctx, &u, `
		SELECT id, email, is_breakglass, created_at, updated_at
		FROM users WHERE email = ?
	`, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &u, nil
}

// Get returns a user by id without hash/salt. Returns ErrNotFound if absent.
func (s *Store) Get(ctx context.Context, id int64) (*User, error) {
	var u User
	err := s.db.GetContext(ctx, &u, `
		SELECT id, email, is_breakglass, status, created_at, updated_at
		FROM users WHERE id = ?
	`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user %d: %w", id, err)
	}
	return &u, nil
}

// AdminUser is the admin user-management list row (#135). It carries display_name + status, which the lean login-path User row omits.
// Kept as a separate type so the login / break-glass queries are untouched.
type AdminUser struct {
	ID           int64          `db:"id" json:"id"`
	Email        string         `db:"email" json:"email"`
	DisplayName  sql.NullString `db:"display_name" json:"-"`
	Status       string         `db:"status" json:"status"`
	IsBreakglass bool           `db:"is_breakglass" json:"is_breakglass"`
	CreatedAt    time.Time      `db:"created_at" json:"created_at"`
}

// List returns every user as an admin-list row, ordered by id. Backs GET /api/settings/users. The operator population is small (a
// handful per pilot deployment), so a single unpaginated scan is fine; pagination is a wave-3 concern if a deployment ever grows past
// it.
func (s *Store) List(ctx context.Context) ([]AdminUser, error) {
	rows := []AdminUser{}
	err := s.db.SelectContext(ctx, &rows, `
		SELECT id, email, display_name, status, is_breakglass, created_at
		FROM users ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return rows, nil
}

// GetAdmin returns one user as an admin-list row (with status + display_name), or ErrNotFound. The user-management handler loads its
// target through GetAdmin so it has status + is_breakglass for the guardrails in a single read.
func (s *Store) GetAdmin(ctx context.Context, id int64) (*AdminUser, error) {
	var u AdminUser
	err := s.db.GetContext(ctx, &u, `
		SELECT id, email, display_name, status, is_breakglass, created_at
		FROM users WHERE id = ?
	`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get admin user %d: %w", id, err)
	}
	return &u, nil
}

// Count returns the number of users. Used by the first-boot seeder to decide whether to
// create the initial admin. A bare Count query is faster than SELECT ... LIMIT 1.
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM users`); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// VerifyPassword looks up a user by email and verifies the presented password. On
// success it returns the user without hash/salt. On any failure it returns
// ErrNotFound (unknown email) or ErrBadPassword (wrong password). Callers should map
// both to the same client-facing 401 to prevent email enumeration.
//
// Runs the argon2id computation even when the email is unknown so the timing profile
// of "unknown email" matches "known email + wrong password". Without this, an attacker
// can probe valid emails via login latency.
func (s *Store) VerifyPassword(ctx context.Context, email, password string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	var row struct {
		ID           int64     `db:"id"`
		Email        string    `db:"email"`
		IsBreakglass bool      `db:"is_breakglass"`
		PasswordHash []byte    `db:"password_hash"`
		PasswordSalt []byte    `db:"password_salt"`
		CreatedAt    time.Time `db:"created_at"`
		UpdatedAt    time.Time `db:"updated_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT id, email, is_breakglass, password_hash, password_salt, created_at, updated_at
		FROM users WHERE email = ?
	`, email)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn the argon2 cycles anyway so we don't leak via timing. The dummy salt is a per-process constant, and argon2id is
		// deterministic given the same salt, producing a stable "unknown email" timing profile. (argon2.IDKey still allocates
		// its output slice; the timing property we care about is work done under the same memory + cost parameters as the real
		// path, not allocation-free execution.)
		_ = argon2.IDKey([]byte(password), dummySalt, argonTime, argonMemory, argonThreads, argonKeyLen)
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query user by email: %w", err)
	}
	if !verifyHash(password, row.PasswordHash, row.PasswordSalt) {
		return nil, ErrBadPassword
	}
	return &User{
		ID: row.ID, Email: row.Email,
		IsBreakglass: row.IsBreakglass,
		CreatedAt:    row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// dummySalt is the constant-time fallback salt used when an email lookup misses. Its content doesn't matter (we throw away the hash),
// but its length must match the real salt length or the argon2 cost won't match exactly.
var dummySalt = make([]byte, argonSaltLen)

// hashPassword generates a fresh salt + argon2id hash for the plaintext password.
func hashPassword(password string) (hash, salt []byte, err error) {
	salt = make([]byte, argonSaltLen)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate salt: %w", err)
	}
	hash = argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return hash, salt, nil
}

// verifyHash returns true when `password` hashes to `wantHash` under `salt`. Uses
// subtle.ConstantTimeCompare to prevent the hash-compare step from leaking timing info.
func verifyHash(password string, wantHash, salt []byte) bool {
	if len(wantHash) == 0 || len(salt) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, wantHash) == 1
}
