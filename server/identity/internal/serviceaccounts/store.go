// Package serviceaccounts owns the persistence and credential lifecycle for non-human API principals (issue #376, ADR-0013).
//
// A service account holds a long-lived client credential (client_id + secret) stored only as a SHA-256 hash; the secret is returned
// once at creation/rotation and never again. The credential is exchanged at the token endpoint for a short-lived self-validating
// access token (see package satoken). Revocation is generational: revoke and rotate bump the row's epoch, and the per-replica
// revocation snapshot (revocation.go) rejects any outstanding access token carrying a stale epoch.
package serviceaccounts

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"time"

	"github.com/jmoiron/sqlx"
)

// clientIDPrefix and secretPrefix are self-describing so a leaked secret is greppable by secret-scanners and a client id is
// recognizable in logs. The secret prefix in particular lets GitHub-style push protection match it.
const (
	clientIDPrefix = "sa_"
	secretPrefix   = "edrsa_" //nolint:gosec // G101: a credential PREFIX used for secret-scanning, not a credential.
)

// ErrNotFound is returned when no service account matches the lookup.
var ErrNotFound = errors.New("serviceaccounts: not found")

// ServiceAccount is the read model returned to the admin surface. It never carries the secret or its hash.
type ServiceAccount struct {
	ID         int64        `db:"id"`
	ClientID   string       `db:"client_id"`
	Name       string       `db:"name"`
	RoleID     string       `db:"role_id"`
	Epoch      int64        `db:"epoch"`
	CreatedBy  *int64       `db:"created_by"`
	ExpiresAt  time.Time    `db:"expires_at"`
	RevokedAt  sql.NullTime `db:"revoked_at"`
	LastUsedAt sql.NullTime `db:"last_used_at"`
	CreatedAt  time.Time    `db:"created_at"`
}

// AuthRecord is the secret-bearing lookup used only by the token endpoint to validate a presented credential. It carries the stored
// hash (never the plaintext) plus the fields needed to mint and to decide whether minting is allowed.
type AuthRecord struct {
	ID         int64        `db:"id"`
	ClientID   string       `db:"client_id"`
	Name       string       `db:"name"`
	RoleID     string       `db:"role_id"`
	SecretHash []byte       `db:"secret_hash"`
	Epoch      int64        `db:"epoch"`
	ExpiresAt  time.Time    `db:"expires_at"`
	RevokedAt  sql.NullTime `db:"revoked_at"`
}

// Store is the MySQL-backed service-account store.
type Store struct {
	db *sqlx.DB
}

// New constructs a Store over db.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// CreateInput is the resolved, validated input to Create. The handler resolves the role (rejecting management-capable roles) and the
// expiry (defaulted/capped) before calling.
type CreateInput struct {
	Name      string
	RoleID    string
	CreatedBy *int64
	ExpiresAt time.Time
}

// Create inserts a new service account with a freshly generated credential and returns the read model plus the one-time plaintext
// secret. The secret exists only in this return value; the database holds only its SHA-256 hash.
func (s *Store) Create(ctx context.Context, in CreateInput) (ServiceAccount, string, error) {
	clientID, err := generateClientID()
	if err != nil {
		return ServiceAccount{}, "", fmt.Errorf("serviceaccounts: generate client id: %w", err)
	}
	secret, err := generateSecret()
	if err != nil {
		return ServiceAccount{}, "", fmt.Errorf("serviceaccounts: generate secret: %w", err)
	}
	hash := hashSecret(secret)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO service_accounts (client_id, name, role_id, secret_hash, expires_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?)`,
		clientID, in.Name, in.RoleID, hash, in.ExpiresAt.UTC(), in.CreatedBy)
	if err != nil {
		return ServiceAccount{}, "", fmt.Errorf("serviceaccounts: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return ServiceAccount{}, "", fmt.Errorf("serviceaccounts: last insert id: %w", err)
	}
	sa, err := s.getByID(ctx, id)
	if err != nil {
		return ServiceAccount{}, "", err
	}
	return sa, secret, nil
}

// List returns all service accounts ordered newest first, without secrets.
func (s *Store) List(ctx context.Context) ([]ServiceAccount, error) {
	var out []ServiceAccount
	if err := s.db.SelectContext(ctx, &out, `
		SELECT id, client_id, name, role_id, epoch, created_by, expires_at, revoked_at, last_used_at, created_at
		FROM service_accounts ORDER BY created_at DESC, id DESC`); err != nil {
		return nil, fmt.Errorf("serviceaccounts: list: %w", err)
	}
	return out, nil
}

// AuthByClientID loads the secret-bearing auth record for the token endpoint. Returns ErrNotFound when no row matches.
func (s *Store) AuthByClientID(ctx context.Context, clientID string) (AuthRecord, error) {
	var rec AuthRecord
	err := s.db.GetContext(ctx, &rec, `
		SELECT id, client_id, name, role_id, secret_hash, epoch, expires_at, revoked_at
		FROM service_accounts WHERE client_id = ?`, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthRecord{}, ErrNotFound
	}
	if err != nil {
		return AuthRecord{}, fmt.Errorf("serviceaccounts: auth lookup: %w", err)
	}
	return rec, nil
}

// Rotate generates a new secret for the account, replacing the stored hash and bumping the epoch so any access token minted from the
// old secret stops validating (a rotate is assumed to follow a suspected leak). Returns the one-time new secret. ErrNotFound when no
// row matches.
func (s *Store) Rotate(ctx context.Context, id int64) (string, error) {
	secret, err := generateSecret()
	if err != nil {
		return "", fmt.Errorf("serviceaccounts: generate secret: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE service_accounts SET secret_hash = ?, epoch = epoch + 1 WHERE id = ?`,
		hashSecret(secret), id)
	if err != nil {
		return "", fmt.Errorf("serviceaccounts: rotate: %w", err)
	}
	if err := requireAffected(res); err != nil {
		return "", err
	}
	return secret, nil
}

// Revoke marks the account revoked and bumps its epoch so outstanding access tokens stop validating within the snapshot refresh
// window and no new token can be minted. Idempotent on an already-revoked row (still bumps epoch). ErrNotFound when no row matches.
func (s *Store) Revoke(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE service_accounts SET revoked_at = CURRENT_TIMESTAMP(6), epoch = epoch + 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("serviceaccounts: revoke: %w", err)
	}
	return requireAffected(res)
}

// MarkUsed stamps last_used_at for the account on a successful token issuance. Best-effort; callers log but do not fail issuance on a
// MarkUsed error.
func (s *Store) MarkUsed(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE service_accounts SET last_used_at = CURRENT_TIMESTAMP(6) WHERE client_id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("serviceaccounts: mark used: %w", err)
	}
	return nil
}

// RevocationEntries implements the revocation snapshot Source: it returns only accounts that are revoked or have a bumped epoch, so
// the result set is bounded by the count of revoked/rotated accounts, not the total.
func (s *Store) RevocationEntries(ctx context.Context) ([]Entry, error) {
	var rows []struct {
		ClientID string `db:"client_id"`
		Epoch    int64  `db:"epoch"`
		Revoked  int    `db:"revoked"`
	}
	if err := s.db.SelectContext(ctx, &rows, `
		SELECT client_id, epoch, IF(revoked_at IS NOT NULL, 1, 0) AS revoked
		FROM service_accounts
		WHERE epoch > 0 OR revoked_at IS NOT NULL`); err != nil {
		return nil, fmt.Errorf("serviceaccounts: revocation entries: %w", err)
	}
	out := make([]Entry, len(rows))
	for i, r := range rows {
		out[i] = Entry{ClientID: r.ClientID, Epoch: r.Epoch, Revoked: r.Revoked != 0}
	}
	return out, nil
}

func (s *Store) getByID(ctx context.Context, id int64) (ServiceAccount, error) {
	var sa ServiceAccount
	err := s.db.GetContext(ctx, &sa, `
		SELECT id, client_id, name, role_id, epoch, created_by, expires_at, revoked_at, last_used_at, created_at
		FROM service_accounts WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceAccount{}, ErrNotFound
	}
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("serviceaccounts: get by id: %w", err)
	}
	return sa, nil
}

func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("serviceaccounts: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// hashSecret returns the SHA-256 digest the column stores. The token endpoint hashes the presented secret and compares against this
// in constant time.
func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// SecretMatches reports whether presented hashes to stored, in constant time.
func SecretMatches(stored []byte, presented string) bool {
	return hmac.Equal(stored, hashSecret(presented))
}

// generateClientID returns a recognizable, unique-by-construction client id ("sa_" + 16 hex).
func generateClientID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return clientIDPrefix + hex.EncodeToString(b[:]), nil
}

// generateSecret returns a high-entropy secret with a self-describing prefix and a CRC32 suffix. The server does not validate the
// checksum (it hashes the whole string); the checksum lets offline secret-scanners recognize and verify a leaked token.
func generateSecret() (string, error) {
	var b [30]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(b[:])
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE([]byte(body)))
	return secretPrefix + body + hex.EncodeToString(sum[:]), nil
}
