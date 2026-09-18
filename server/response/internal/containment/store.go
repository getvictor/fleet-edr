package containment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/response/api"
)

// Store owns the host_containment table.
type Store struct {
	db *sqlx.DB
}

// NewStore returns a Store over db.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("containment.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

type stateRow struct {
	HostID    string    `db:"host_id"`
	Contained bool      `db:"contained"`
	Version   int64     `db:"version"`
	Reason    string    `db:"reason"`
	UpdatedBy string    `db:"updated_by"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (r stateRow) state() api.ContainmentState {
	updated := r.UpdatedAt
	return api.ContainmentState{
		HostID: r.HostID, Contained: r.Contained, Version: r.Version, Epoch: updated.UnixMicro(), Reason: r.Reason,
		UpdatedBy: r.UpdatedBy, UpdatedAt: &updated,
	}
}

const selectState = `SELECT host_id, contained, version, reason, updated_by, updated_at FROM host_containment`

// Get returns a host's state, or the zero state (not contained, version 0) for a host that has none.
func (s *Store) Get(ctx context.Context, hostID string) (api.ContainmentState, error) {
	var row stateRow
	err := sqlx.GetContext(ctx, s.db, &row, selectState+` WHERE host_id = ?`, hostID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return api.ContainmentState{HostID: hostID}, nil
	case err != nil:
		return api.ContainmentState{}, fmt.Errorf("read containment of %s: %w", hostID, err)
	}
	return row.state(), nil
}

// QueueFunc is how a caller queues the command carrying a state, through the transaction that records it. Returning an error rolls
// the change back, so a host's state and the command carrying it are recorded together or not at all.
type QueueFunc func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error)

// Set records contained as the host's state, queues the command carrying it through the same transaction, and reports whether that
// changed anything. A request for the state the host already has (or a release of a host that has none) changes nothing.
//
// The row is read and written under its lock, so concurrent changes to one host each get the next version, and the change time comes
// from the database and is strictly later than the previous one: the epoch a host orders by then agrees with the version. A host's
// first containment creates its row at version 0 inside the same transaction before locking it, so two first containments serialize
// on that row instead of one failing on a duplicate key; the row is never committed at version 0.
//
// The command is queued while that lock is still held, so the commands queued for one host are in the order of the states they carry
// (issue #1073), and a change whose command cannot be queued records no state.
func (s *Store) Set(ctx context.Context, hostID string, contained bool, reason, actor string, expected *int64,
	queue QueueFunc) (api.ContainmentState, bool, int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.ContainmentState{}, false, 0, fmt.Errorf("begin containment change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if contained {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_containment (host_id, contained, version, reason, updated_by, updated_at)
			VALUES (?, FALSE, 0, '', '', NOW(6)) ON DUPLICATE KEY UPDATE host_id = host_id`, hostID); err != nil {
			return api.ContainmentState{}, false, 0, fmt.Errorf("create containment row of %s: %w", hostID, err)
		}
	}
	var before stateRow
	err = sqlx.GetContext(ctx, tx, &before, selectState+` WHERE host_id = ? FOR UPDATE`, hostID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Only a release reaches here: a containment created the row above. A host with no row has never been contained, which is
		// version 0, so a caller expecting anything else was reading a state this host does not have.
		if expected != nil && *expected != 0 {
			return api.ContainmentState{HostID: hostID}, false, 0, api.ErrContainmentVersionConflict
		}
		return api.ContainmentState{HostID: hostID}, false, 0, nil
	case err != nil:
		return api.ContainmentState{}, false, 0, fmt.Errorf("lock containment of %s: %w", hostID, err)
	}
	// Checked under the row's lock and BEFORE the no-op check, so a caller that read the state and then asked is told the host moved
	// rather than having its request applied to a state it never saw (issue #1076). Before the no-op check because a request that
	// changes nothing still acted on a view that is gone, and reporting it as a success would leave the caller believing the state it
	// read is the state that stands.
	if expected != nil && *expected != before.Version {
		// Returned WITH the conflict, and it is the state the refusal was decided against rather than one read afterwards: a
		// third change landing between the two reads would answer the caller with a version that is not the one their request
		// lost to, and a read that failed would leave the refusal with no state to carry at all.
		return before.state(), false, 0, api.ErrContainmentVersionConflict
	}
	if before.Contained == contained {
		return before.state(), false, 0, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE host_containment
		SET contained = ?, version = version + 1, reason = ?, updated_by = ?,
		    updated_at = GREATEST(NOW(6), updated_at + INTERVAL 1 MICROSECOND)
		WHERE host_id = ?`, contained, reason, actor, hostID); err != nil {
		return api.ContainmentState{}, false, 0, fmt.Errorf("change containment of %s: %w", hostID, err)
	}
	var after stateRow
	if err := sqlx.GetContext(ctx, tx, &after, selectState+` WHERE host_id = ?`, hostID); err != nil {
		return api.ContainmentState{}, false, 0, fmt.Errorf("read changed containment of %s: %w", hostID, err)
	}
	// Inside the transaction, with the host's row still locked: a concurrent change to this host is waiting on that lock, so it
	// cannot queue its own command between this state being written and its command being queued. That is what keeps the commands
	// for one host in the order of the states they carry (issue #1073).
	commandID, err := queue(ctx, tx, after.state())
	if err != nil {
		return api.ContainmentState{}, false, 0, fmt.Errorf("queue containment command of %s: %w", hostID, err)
	}
	if err := tx.Commit(); err != nil {
		return api.ContainmentState{}, false, 0, fmt.Errorf("commit containment change of %s: %w", hostID, err)
	}
	return after.state(), true, commandID, nil
}

// QueueCurrent queues the command for a host's state as the catch-up decided it, unless the host has moved on: the row is locked and
// re-read first, and a version or epoch that no longer matches means a change committed since the sweep read it and queued a command
// of its own. Queuing then would put an older state behind a newer one (issue #1073). Reports whether it queued.
func (s *Store) QueueCurrent(ctx context.Context, want api.ContainmentState, queue QueueFunc) (int64, bool, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin containment catch-up: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var current stateRow
	err = sqlx.GetContext(ctx, tx, &current, selectState+` WHERE host_id = ? FOR UPDATE`, want.HostID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("lock containment of %s: %w", want.HostID, err)
	}
	state := current.state()
	if state.Version != want.Version || state.Epoch != want.Epoch {
		return 0, false, nil
	}
	commandID, err := queue(ctx, tx, state)
	if err != nil {
		return 0, false, fmt.Errorf("queue containment command of %s: %w", want.HostID, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit containment catch-up of %s: %w", want.HostID, err)
	}
	return commandID, true, nil
}

// All returns every host's state, in host_id order. The catch-up reads it; a row exists only for a host whose containment was changed.
func (s *Store) All(ctx context.Context) ([]api.ContainmentState, error) {
	var rows []stateRow
	if err := sqlx.SelectContext(ctx, s.db, &rows, selectState+` ORDER BY host_id`); err != nil {
		return nil, fmt.Errorf("list containment states: %w", err)
	}
	out := make([]api.ContainmentState, len(rows))
	for i, r := range rows {
		out[i] = r.state()
	}
	return out, nil
}
