package reachable

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/auditoutbox"
	"github.com/fleetdm/edr/server/response/api"
)

// Store reads and replaces the single containment_reachable_set row.
type Store struct {
	db     *sqlx.DB
	outbox *auditoutbox.Store
}

// NewStore builds a Store. Panics on a nil db or outbox, which is a wiring bug: the outbox is where a replacement's audit entry
// commits with it, so a Store without one could widen every contained host's reach with nothing saying who did it.
func NewStore(db *sqlx.DB, outbox *auditoutbox.Store) *Store {
	if db == nil || outbox == nil {
		panic("reachable.NewStore: db and outbox must not be nil")
	}
	return &Store{db: db, outbox: outbox}
}

const selectSet = `SELECT version, addresses, updated_at, updated_by FROM containment_reachable_set WHERE id = 1`

type setRow struct {
	Version   int64        `db:"version"`
	Addresses []byte       `db:"addresses"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UpdatedBy string       `db:"updated_by"`
}

func (r setRow) set() (api.ReachableSet, error) {
	out := api.ReachableSet{Version: r.Version, UpdatedBy: r.UpdatedBy, Addresses: []api.ReachableAddress{}}
	if err := json.Unmarshal(r.Addresses, &out.Addresses); err != nil {
		return api.ReachableSet{}, fmt.Errorf("decode reachable addresses: %w", err)
	}
	if r.UpdatedAt.Valid {
		t := r.UpdatedAt.Time
		out.UpdatedAt = &t
	}
	return out, nil
}

// Get returns the stored set.
func (s *Store) Get(ctx context.Context) (api.ReachableSet, error) {
	var row setRow
	if err := sqlx.GetContext(ctx, s.db, &row, selectSet); err != nil {
		return api.ReachableSet{}, fmt.Errorf("read reachable set: %w", err)
	}
	return row.set()
}

// Replace stores addresses as the new set and returns the set it replaced and the new one, one version past it.
//
// The previous set, the version and the update time are read and written under the row lock, so concurrent replacements are ordered
// by who takes the lock: each gets the next version, reports the set it actually replaced, and gets an update time strictly later
// than the one before. The time comes from the database rather than from a replica's clock, for the same reason the containment
// state's does: one clock has to order every replica's writes, or a later version could carry an earlier time and let an
// out-of-order delivery put the older set back.
//
// A non-nil expectedVersion makes the replacement conditional: when the stored set is at any other version, which means someone
// changed it since the caller read it, Replace stores nothing and returns ErrReachableVersionConflict. Compared under the same lock,
// so two operators saving edits of the same version cannot both succeed.
//
// The audit entry that audit builds from the two sets is written in the same transaction, so a widened set and the record of who
// widened it are one commit or neither.
func (s *Store) Replace(
	ctx context.Context, addresses []api.ReachableAddress, actor string, expectedVersion *int64,
	audit func(previous, next api.ReachableSet) (auditoutbox.Entry, error),
) (previous, next api.ReachableSet, err error) {
	encoded, err := json.Marshal(addresses)
	if err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("encode reachable addresses: %w", err)
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("begin reachable set replace: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var before setRow
	if err := sqlx.GetContext(ctx, tx, &before, selectSet+` FOR UPDATE`); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("lock reachable set: %w", err)
	}
	if expectedVersion != nil && before.Version != *expectedVersion {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("%w: it is at version %d, not %d",
			api.ErrReachableVersionConflict, before.Version, *expectedVersion)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE containment_reachable_set
		SET version = version + 1, addresses = ?, updated_by = ?,
		    updated_at = GREATEST(NOW(6), COALESCE(updated_at + INTERVAL 1 MICROSECOND, NOW(6)))
		WHERE id = 1`, encoded, actor); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("replace reachable set: %w", err)
	}
	var after setRow
	if err := sqlx.GetContext(ctx, tx, &after, selectSet); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("read replaced reachable set: %w", err)
	}
	if previous, err = before.set(); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, err
	}
	if next, err = after.set(); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, err
	}
	entry, err := audit(previous, next)
	if err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, err
	}
	if err := s.outbox.Enqueue(ctx, tx, entry); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, fmt.Errorf("commit reachable set replace: %w", err)
	}
	return previous, next, nil
}
