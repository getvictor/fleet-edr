// Package watchedpaths stores the watched-path set and pushes it to hosts (issue #998, ADR-0008 step 4). The set is file paths the
// extension's file-tamper client watches on top of the ones built into it.
package watchedpaths

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

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

// ErrVersionConflict is returned for a conditional replacement of a set that has changed since the caller read it.
var ErrVersionConflict = errors.New("the watched paths were changed since they were read")

const selectSet = `SELECT version, paths, updated_at, updated_by FROM watched_path_set WHERE id = 1`

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
	if err := sqlx.GetContext(ctx, s.db, &row, selectSet); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("read watched path set: %w", err)
	}
	return row.set()
}

// Replace stores paths as the new set and returns the set it replaced and the new one, one version past it.
//
// The previous set, the version and the update time are all read and written under the row lock, so concurrent replacements are
// ordered by who takes the lock: each gets the next version, reports the set it actually replaced, and gets an update time strictly
// later than the one before. That last property is load-bearing. A host orders sets by version or by update time (the epoch), so a
// later version stamped with an earlier time, which reading the clock before taking the lock could produce, would let an out-of-order
// delivery put the older set back. The time comes from the database for the same reason: one clock orders every replica's writes.
//
// A non-nil expectedVersion makes the replacement conditional: when the stored set is at any other version, which means someone changed
// it since the caller read it, Replace stores nothing and returns ErrVersionConflict. Compared under the same lock, so two operators
// saving edits of the same version cannot both succeed.
func (s *Store) Replace(
	ctx context.Context, paths []api.WatchedPath, actor string, expectedVersion *int64,
) (previous, next api.WatchedPathSet, err error) {
	encoded, err := json.Marshal(paths)
	if err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("encode watched paths: %w", err)
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("begin watched path set replace: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var before setRow
	if err := sqlx.GetContext(ctx, tx, &before, selectSet+` FOR UPDATE`); err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("lock watched path set: %w", err)
	}
	if expectedVersion != nil && before.Version != *expectedVersion {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("%w: it is at version %d, not %d",
			ErrVersionConflict, before.Version, *expectedVersion)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE watched_path_set
		SET version = version + 1, paths = ?, updated_by = ?,
		    updated_at = GREATEST(NOW(6), COALESCE(updated_at + INTERVAL 1 MICROSECOND, NOW(6)))
		WHERE id = 1`, encoded, actor); err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("replace watched path set: %w", err)
	}
	var after setRow
	if err := sqlx.GetContext(ctx, tx, &after, selectSet); err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("read replaced watched path set: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, fmt.Errorf("commit watched path set replace: %w", err)
	}
	if previous, err = before.set(); err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, err
	}
	next, err = after.set()
	return previous, next, err
}
