// Package watchedpaths stores the watched-path set and pushes it to hosts (issue #998, ADR-0008 step 4). The set is file paths the
// extension's file-tamper client watches on top of the ones built into it.
package watchedpaths

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rules/api"
)

// Store reads and replaces the single watched_path_set row.
type Store struct {
	db *sqlx.DB
}

// NewStore builds a Store. Panics on a nil db, which is a wiring bug.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("watchedpaths.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

type setRow struct {
	Version   int64        `db:"version"`
	Paths     []byte       `db:"paths"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UpdatedBy string       `db:"updated_by"`
}

func (r setRow) set() (api.WatchedPathSet, error) {
	out := api.WatchedPathSet{Version: r.Version, UpdatedBy: r.UpdatedBy, Paths: []api.WatchedPath{}}
	if err := json.Unmarshal(r.Paths, &out.Paths); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("decode watched paths: %w", err)
	}
	if r.UpdatedAt.Valid {
		t := r.UpdatedAt.Time
		out.UpdatedAt = &t
	}
	return out, nil
}

// Get returns the stored set.
func (s *Store) Get(ctx context.Context) (api.WatchedPathSet, error) {
	var row setRow
	if err := sqlx.GetContext(ctx, s.db, &row,
		`SELECT version, paths, updated_at, updated_by FROM watched_path_set WHERE id = 1`); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("read watched path set: %w", err)
	}
	return row.set()
}

// Replace stores paths as the new set and returns it, one version past the one it replaced. The version advances in the same
// statement that writes the paths, so two concurrent replacements each get their own version and the later write is the later
// version.
func (s *Store) Replace(ctx context.Context, paths []api.WatchedPath, actor string, now time.Time) (api.WatchedPathSet, error) {
	encoded, err := json.Marshal(paths)
	if err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("encode watched paths: %w", err)
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("begin watched path set replace: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE watched_path_set SET version = version + 1, paths = ?, updated_at = ?, updated_by = ? WHERE id = 1`,
		encoded, now.UTC(), actor); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("replace watched path set: %w", err)
	}
	var row setRow
	if err := sqlx.GetContext(ctx, tx, &row,
		`SELECT version, paths, updated_at, updated_by FROM watched_path_set WHERE id = 1`); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("read replaced watched path set: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("commit watched path set replace: %w", err)
	}
	return row.set()
}
