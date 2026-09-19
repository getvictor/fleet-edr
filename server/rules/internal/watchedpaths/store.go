// Package watchedpaths stores the watched-path set and pushes it to hosts (issue #998, ADR-0008 step 4). The set is file paths the
// extension's file-tamper client watches on top of the ones built into it.
package watchedpaths

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/internal/versionedset"
	"github.com/fleetdm/edr/server/auditoutbox"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

// Store reads and replaces the single watched_path_set row.
//
// The row's concurrency (the lock, the conditional replace, the strictly increasing update time) is versionedset's, shared with
// the response context's reachable-address set because the two had drifted apart into two copies of the same subtle thing
// (issue #1109). What stays here is this context's own: the payload type and its decoding, the conflict error, and the held
// audit entry a later push seals.
type Store struct {
	set    *versionedset.Store
	outbox *auditoutbox.Store
}

// NewStore builds a Store. Panics on a nil db, which is a wiring bug.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("watchedpaths.NewStore: db must not be nil")
	}
	return &Store{
		set: versionedset.New(db, versionedset.Table{
			Name:          "watched_path_set",
			PayloadColumn: "paths",
			Noun:          "watched path set",
		}),
		outbox: auditoutbox.NewStore(db, detectionconfig.AuditOutboxTable),
	}
}

// ErrVersionConflict is returned for a conditional replacement of a set that has changed since the caller read it.
var ErrVersionConflict = errors.New("the watched paths were changed since they were read")

// decode maps a stored row onto the API's set.
func decode(row versionedset.Row) (api.WatchedPathSet, error) {
	out := api.WatchedPathSet{
		Version:   row.Version,
		UpdatedBy: row.UpdatedBy,
		UpdatedAt: row.UpdatedAtPtr(),
		Paths:     []api.WatchedPath{},
	}
	if err := json.Unmarshal(row.Payload, &out.Paths); err != nil {
		return api.WatchedPathSet{}, fmt.Errorf("decode watched paths: %w", err)
	}
	return out, nil
}

// Get returns the stored set.
func (s *Store) Get(ctx context.Context) (api.WatchedPathSet, error) {
	row, err := s.set.Get(ctx)
	if err != nil {
		return api.WatchedPathSet{}, err
	}
	return decode(row)
}

// Replace stores paths as the new set and returns the set it replaced and the new one, one version past it.
//
// A non-nil expectedVersion makes the replacement conditional: when the stored set is at any other version, which means someone
// changed it since the caller read it, Replace stores nothing and returns ErrVersionConflict.
//
// The audit entry audit builds from the two sets is written in the same transaction, held for auditHold so the caller can add
// the push's host counts with SealAudit before it is delivered (issue #1022). Replace returns the entry's id for that.
func (s *Store) Replace(
	ctx context.Context, paths []api.WatchedPath, actor string, expectedVersion *int64,
	audit func(previous, next api.WatchedPathSet) (auditoutbox.Entry, error),
) (previous, next api.WatchedPathSet, auditID int64, err error) {
	encoded, err := json.Marshal(paths)
	if err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, 0, fmt.Errorf("encode watched paths: %w", err)
	}
	_, _, err = s.set.Replace(ctx, encoded, actor, expectedVersion, ErrVersionConflict,
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
			auditID, aerr = s.outbox.EnqueueHeld(ctx, tx, entry, auditHold)
			return aerr
		})
	if err != nil {
		return api.WatchedPathSet{}, api.WatchedPathSet{}, 0, err
	}
	return previous, next, auditID, nil
}

// auditHold is how long a replacement's audit entry waits for the push's host counts. The push is one host listing and one batched
// insert, which take well under a second, so five minutes only matters when the replica died between committing the change and
// adding the counts: the entry is then delivered without them, five minutes late, rather than never.
const auditHold = 5 * time.Minute

// SealAudit adds the push's host counts to a replacement's held audit entry and releases it for delivery. It reports false when the
// hold had already passed, in which case the entry is delivered without the counts.
func (s *Store) SealAudit(ctx context.Context, id int64, entry auditoutbox.Entry) (bool, error) {
	return s.outbox.Seal(ctx, id, entry)
}
