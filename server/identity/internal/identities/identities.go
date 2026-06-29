// Package identities owns the `identities` table: the (provider,
// subject) → user_id mapping that lets the same user authenticate via
// multiple flows (local password, OIDC, future api_token). Used to
// look up an OIDC subject's user on callback and to insert a new
// (provider='oidc', subject=<sub>) row during JIT provisioning.
//
// The table's UNIQUE(provider, subject) ensures a given IdP subject
// resolves to exactly one local user; the wave-1 schema also CASCADEs
// identity rows when their owning user is deleted, so identity cleanup
// is automatic.

package identities

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// Provider names the authentication flow that produced the identity.
// Wave 1 ships local_password + oidc; api_token is a wave-2 reservation.
const (
	ProviderLocalPassword = "local_password"
	ProviderOIDC          = "oidc"
)

// ErrNotFound is returned by FindByProviderSubject when no row matches.
var ErrNotFound = errors.New("identities: not found")

// Identity is the row shape callers see after a Find / Insert. Subject is the IdP-stable identifier (sub claim for OIDC, email for the
// local_password seed). user_id FKs into users.
type Identity struct {
	ID        int64     `db:"id"`
	UserID    int64     `db:"user_id"`
	Provider  string    `db:"provider"`
	Subject   string    `db:"subject"`
	CreatedAt time.Time `db:"created_at"`
}

// Store owns the identities table.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store. Panics if db is nil: a Store backed by
// nothing has no useful behavior.
func New(db *sqlx.DB) *Store {
	if db == nil {
		panic("identities.New: db must not be nil")
	}
	return &Store{db: db}
}

// FindByProviderSubject returns the identity (and its owning user_id) for a given (provider, subject) pair, or ErrNotFound if no row
// exists. UNIQUE(provider, subject) guarantees the result is unique.
func (s *Store) FindByProviderSubject(ctx context.Context, provider, subject string) (*Identity, error) {
	var i Identity
	err := s.db.GetContext(ctx, &i, `
		SELECT id, user_id, provider, subject, created_at
		FROM identities
		WHERE provider = ? AND subject = ?
	`, provider, subject)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("identities: lookup %q/%q: %w", provider, subject, err)
	}
	return &i, nil
}

// Executor is the executor subset Insert / InsertWith consume. Pass an *sqlx.Tx for the JIT provisioner's atomic insert; pass the
// Store's db for standalone calls. Caller is responsible for matching tx + user_id: the identity row's FK CASCADEs on user delete,
// so inserting into an uncommitted user orphans if the parent rolls back. Named per the Go convention (single-method interface ends in
// -er).
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// InsertWith persists a new identity row using the provided executor (typically the *sqlx.Tx wrapping a JIT provision). Returns the
// row id assigned by MySQL's auto_increment.
//
// JIT provisioning relies on the duplicate-key error this raises on a (provider, subject) collision: it IS the concurrency-race signal
// that oidc.ProvisionOrFind re-resolves on. A caller whose duplicate is expected and benign (an idempotent re-resolve) wants UpsertWith
// instead, so the expected collision never raises a hasError trace span (#522).
func (s *Store) InsertWith(ctx context.Context, ec Executor, userID int64, provider, subject string) (int64, error) {
	res, err := ec.ExecContext(ctx, `
		INSERT INTO identities (user_id, provider, subject) VALUES (?, ?, ?)
	`, userID, provider, subject)
	if err != nil {
		return 0, fmt.Errorf("identities: insert %q/%q: %w", provider, subject, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("identities: last insert id: %w", err)
	}
	return id, nil
}

// UpsertWith persists a new identity row, or returns the id of the existing (provider, subject) row when one is already present, in a
// single statement. Unlike InsertWith it never raises a duplicate-key error on the expected-duplicate path: ON DUPLICATE KEY UPDATE
// id = LAST_INSERT_ID(id) makes res.LastInsertId() return the existing row's id on the matched path. Used by the break-glass redemption
// to re-resolve a local_password identity that an earlier seed already created, so an idempotent re-run does not surface a benign
// hasError trace span (#522). It runs on the caller's executor, so the read of the existing row stays inside the redemption transaction.
//
// JIT provisioning deliberately keeps using InsertWith: there the duplicate-key error is the concurrency-race signal that must surface.
func (s *Store) UpsertWith(ctx context.Context, ec Executor, userID int64, provider, subject string) (int64, error) {
	res, err := ec.ExecContext(ctx, `
		INSERT INTO identities (user_id, provider, subject) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)
	`, userID, provider, subject)
	if err != nil {
		return 0, fmt.Errorf("identities: upsert %q/%q: %w", provider, subject, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("identities: upsert last insert id: %w", err)
	}
	return id, nil
}
