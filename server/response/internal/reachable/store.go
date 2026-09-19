package reachable

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/internal/versionedset"
	"github.com/fleetdm/edr/server/auditoutbox"
	"github.com/fleetdm/edr/server/response/api"
)

// Store reads and replaces the single containment_reachable_set row.
//
// The row's concurrency (the lock, the conditional replace, the strictly increasing update time) is versionedset's, shared with
// the rules context's watched-path set because the two had drifted apart into two copies of the same subtle thing (issue #1109).
// What stays here is what is genuinely this context's: the payload type and its decoding, the conflict error, and the audit
// entry that commits with the change.
type Store struct {
	set    *versionedset.Store
	outbox *auditoutbox.Store
}

// NewStore builds a Store. Panics on a nil db or outbox, which is a wiring bug: the outbox is where a replacement's audit entry
// commits with it, so a Store without one could widen every contained host's reach with nothing saying who did it.
func NewStore(db *sqlx.DB, outbox *auditoutbox.Store) *Store {
	if db == nil || outbox == nil {
		panic("reachable.NewStore: db and outbox must not be nil")
	}
	return &Store{
		set: versionedset.New(db, versionedset.Table{
			Name:          "containment_reachable_set",
			PayloadColumn: "addresses",
			Noun:          "reachable set",
		}),
		outbox: outbox,
	}
}

// decode maps a stored row onto the API's set.
func decode(row versionedset.Row) (api.ReachableSet, error) {
	out := api.ReachableSet{
		Version:   row.Version,
		UpdatedBy: row.UpdatedBy,
		UpdatedAt: row.UpdatedAtPtr(),
		Addresses: []api.ReachableAddress{},
	}
	if err := json.Unmarshal(row.Payload, &out.Addresses); err != nil {
		return api.ReachableSet{}, fmt.Errorf("decode reachable addresses: %w", err)
	}
	return out, nil
}

// Get returns the stored set.
func (s *Store) Get(ctx context.Context) (api.ReachableSet, error) {
	row, err := s.set.Get(ctx)
	if err != nil {
		return api.ReachableSet{}, err
	}
	return decode(row)
}

// Replace stores addresses as the new set and returns the set it replaced and the new one, one version past it.
//
// A non-nil expectedVersion makes the replacement conditional: when the stored set is at any other version, which means someone
// changed it since the caller read it, Replace stores nothing and returns ErrReachableVersionConflict.
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
	_, _, err = s.set.Replace(ctx, encoded, actor, expectedVersion, api.ErrReachableVersionConflict,
		func(ctx context.Context, tx *sqlx.Tx, beforeRow, afterRow versionedset.Row) error {
			if previous, err = decode(beforeRow); err != nil {
				return err
			}
			if next, err = decode(afterRow); err != nil {
				return err
			}
			entry, aerr := audit(previous, next)
			if aerr != nil {
				return aerr
			}
			return s.outbox.Enqueue(ctx, tx, entry)
		})
	if err != nil {
		return api.ReachableSet{}, api.ReachableSet{}, err
	}
	return previous, next, nil
}
