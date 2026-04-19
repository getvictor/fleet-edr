// Package users owns the `users` table that backs Phase 3 UI login. The store exposes
// a minimal CRUD surface (Create, GetByEmail) because MVP has exactly one admin account
// — anything more is v1.1. Password hashing uses argon2id with the same parameter set
// as the enrollment token hash so a future consolidation into a shared `passcrypto`
// package is mechanical.
package users

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/argon2"
)

// argon2id parameters per OWASP Password Storage Cheat Sheet 2024. ~30 ms per hash on
// M-series Mac; the hot path (login verify) hashes at most once per login attempt and
// we rate-limit logins, so CPU-DoS via login-storm is capped.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// User is the storage row. The password_hash / password_salt columns are intentionally
// not exposed on the struct so callers that log a User can't accidentally leak them.
type User struct {
	ID        int64     `db:"id" json:"id"`
	Email     string    `db:"email" json:"email"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// ErrNotFound is returned by GetByEmail when no row matches.
var ErrNotFound = errors.New("users: not found")

// ErrBadPassword is returned by VerifyPassword when the presented password doesn't
// match the stored hash. Kept separate from ErrNotFound so callers can emit identical
// 401s to the client (preventing email enumeration) while differentiating reasons in
// the server-side audit log.
var ErrBadPassword = errors.New("users: password mismatch")

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

// Create inserts a new user and returns the row (without the hash/salt). Email is
// normalised to lowercase + trimmed before the uniqueness check — customer admins like
// to type "Admin@Example.COM" and expect it to resolve to the same account.
func (s *Store) Create(ctx context.Context, req CreateRequest) (*User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, errors.New("users: email is required")
	}
	if req.Password == "" {
		return nil, errors.New("users: password is required")
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

// Get returns a user by id without hash/salt. Returns ErrNotFound if absent.
func (s *Store) Get(ctx context.Context, id int64) (*User, error) {
	var u User
	err := s.db.GetContext(ctx, &u, `
		SELECT id, email, created_at, updated_at FROM users WHERE id = ?
	`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user %d: %w", id, err)
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
// ErrNotFound (unknown email) or ErrBadPassword (wrong password) — callers should map
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
		PasswordHash []byte    `db:"password_hash"`
		PasswordSalt []byte    `db:"password_salt"`
		CreatedAt    time.Time `db:"created_at"`
		UpdatedAt    time.Time `db:"updated_at"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT id, email, password_hash, password_salt, created_at, updated_at
		FROM users WHERE email = ?
	`, email)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn the argon2 cycles anyway so we don't leak via timing. The dummy salt is a
		// per-process constant — argon2id is deterministic given the same salt so this
		// produces a stable "unknown email" timing profile without allocating.
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
		ID: row.ID, Email: row.Email, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// dummySalt is the constant-time fallback salt used when an email lookup misses. Its
// content doesn't matter — we throw away the hash — but its length must match the real
// salt length or the argon2 cost won't match exactly.
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
