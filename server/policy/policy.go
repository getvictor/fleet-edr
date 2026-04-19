// Package policy owns the Phase 2 server-driven blocklist. A single "default" row in the
// `policies` table holds the current version + serialized blocklist payload. Admin writes
// bump the version atomically inside a transaction and can be fanned out to hosts via the
// Enqueue helper.
//
// The package deliberately does NOT depend on the command queue — callers (admin handler,
// enrollment handler) compose the two: first Update, then Enqueue. This keeps the policy
// code easy to test without mocking commands, and leaves scheduling/targeting decisions
// with the caller.
package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// DefaultName is the name of the singleton policy row. v1.1 will add targeted policies
// (per team / per host group); for MVP this is the only name any production code should use.
const DefaultName = "default"

// Policy mirrors a row in `policies`. Blocklist is returned as `Blocklist`, not as the raw
// JSON column, so callers don't need to parse.
type Policy struct {
	Name      string    `json:"name"`
	Version   int64     `json:"version"`
	Blocklist Blocklist `json:"blocklist"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// Blocklist is the subject of policy pushes. `Paths` is a sorted, deduplicated list of
// absolute file-system paths the extension should DENY under AUTH_EXEC. `Hashes` is a
// sorted, deduplicated list of lowercase hex SHA-256 strings (extension-side hashing is
// still a v1.1 feature, but we keep the wire contract future-proof).
type Blocklist struct {
	Paths  []string `json:"paths"`
	Hashes []string `json:"hashes"`
}

// ErrNotFound is returned when the requested policy row is missing.
var ErrNotFound = errors.New("policy: not found")

// Store owns the policies table.
type Store struct {
	db *sqlx.DB
}

// New returns a Store over an existing sqlx.DB handle.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// Get returns the policy row named `name`. Returns ErrNotFound if no row exists — callers
// that bootstrap from the seed should use DefaultName and can treat ErrNotFound as an
// operational anomaly (the store schema seeds it).
func (s *Store) Get(ctx context.Context, name string) (*Policy, error) {
	var row struct {
		Name      string    `db:"name"`
		Version   int64     `db:"version"`
		Blocklist []byte    `db:"blocklist"`
		UpdatedAt time.Time `db:"updated_at"`
		UpdatedBy string    `db:"updated_by"`
	}
	err := s.db.GetContext(ctx, &row, `
		SELECT name, version, blocklist, updated_at, updated_by
		FROM policies
		WHERE name = ?
	`, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query policy %q: %w", name, err)
	}

	var bl Blocklist
	if err := json.Unmarshal(row.Blocklist, &bl); err != nil {
		return nil, fmt.Errorf("decode blocklist for policy %q: %w", name, err)
	}
	return &Policy{
		Name:      row.Name,
		Version:   row.Version,
		Blocklist: bl,
		UpdatedAt: row.UpdatedAt,
		UpdatedBy: row.UpdatedBy,
	}, nil
}

// UpdateRequest carries the new blocklist plus the actor performing the change. The actor
// ends up in `updated_by` and in the audit log; it must be non-empty so post-mortems on a
// bad policy push always have a name to call.
type UpdateRequest struct {
	Name   string
	Paths  []string
	Hashes []string
	Actor  string
}

// Update atomically bumps the named policy's version and replaces its blocklist. Paths +
// Hashes are normalised (sorted + deduplicated, paths trimmed) before persisting so the
// wire payload the extension sees is canonical regardless of input order.
//
// Returns the new Policy with the bumped version. If the row is missing Update inserts it
// at version 1; callers don't need to distinguish insert vs update. Actor must be non-empty.
func (s *Store) Update(ctx context.Context, req UpdateRequest) (*Policy, error) {
	if req.Name == "" {
		return nil, errors.New("policy: name is required")
	}
	if strings.TrimSpace(req.Actor) == "" {
		return nil, errors.New("policy: actor is required")
	}
	normalized := normalizeBlocklist(req.Paths, req.Hashes)
	payload, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal blocklist: %w", err)
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	// Upsert so the row is created if the seed migration hasn't yet landed on a fresh DB.
	// VALUES()-style assignment bumps the version by one on every PUT; the initial insert
	// starts at 1.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO policies (name, version, blocklist, updated_at, updated_by)
		VALUES (?, 1, ?, NOW(6), ?)
		ON DUPLICATE KEY UPDATE
			version    = version + 1,
			blocklist  = VALUES(blocklist),
			updated_at = NOW(6),
			updated_by = VALUES(updated_by)
	`, req.Name, payload, req.Actor); err != nil {
		return nil, fmt.Errorf("upsert policy %q: %w", req.Name, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit policy update: %w", err)
	}

	// Round-trip read so we return the canonical stored form (paths/hashes normalised,
	// timestamps populated by the server).
	return s.Get(ctx, req.Name)
}

// normalizeBlocklist returns a deterministic blocklist: paths trimmed + deduped + sorted,
// hashes lowercased + deduped + sorted. Nil slices become empty so the JSON output is always
// an array, never null.
func normalizeBlocklist(paths, hashes []string) Blocklist {
	bl := Blocklist{
		Paths:  dedupSort(paths, strings.TrimSpace),
		Hashes: dedupSort(hashes, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }),
	}
	if bl.Paths == nil {
		bl.Paths = []string{}
	}
	if bl.Hashes == nil {
		bl.Hashes = []string{}
	}
	return bl
}

func dedupSort(in []string, norm func(string) string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = norm(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
