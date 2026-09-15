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

// Set records contained as the host's state and reports whether that changed it. A request for the state the host already has (or
// a release of a host that has none) changes nothing.
//
// The row is read and written under its lock, so concurrent changes to one host each get the next version, and the change time comes
// from the database and is strictly later than the previous one: the epoch a host orders by then agrees with the version. A host's
// first containment creates its row at version 0 inside the same transaction before locking it, so two first containments serialize
// on that row instead of one failing on a duplicate key; the row is never committed at version 0.
func (s *Store) Set(ctx context.Context, hostID string, contained bool, reason, actor string) (api.ContainmentState, bool, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.ContainmentState{}, false, fmt.Errorf("begin containment change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if contained {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_containment (host_id, contained, version, reason, updated_by, updated_at)
			VALUES (?, FALSE, 0, '', '', NOW(6)) ON DUPLICATE KEY UPDATE host_id = host_id`, hostID); err != nil {
			return api.ContainmentState{}, false, fmt.Errorf("create containment row of %s: %w", hostID, err)
		}
	}
	var before stateRow
	err = sqlx.GetContext(ctx, tx, &before, selectState+` WHERE host_id = ? FOR UPDATE`, hostID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Only a release reaches here: a containment created the row above.
		return api.ContainmentState{HostID: hostID}, false, nil
	case err != nil:
		return api.ContainmentState{}, false, fmt.Errorf("lock containment of %s: %w", hostID, err)
	case before.Contained == contained:
		return before.state(), false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE host_containment
		SET contained = ?, version = version + 1, reason = ?, updated_by = ?,
		    updated_at = GREATEST(NOW(6), updated_at + INTERVAL 1 MICROSECOND)
		WHERE host_id = ?`, contained, reason, actor, hostID); err != nil {
		return api.ContainmentState{}, false, fmt.Errorf("change containment of %s: %w", hostID, err)
	}
	var after stateRow
	if err := sqlx.GetContext(ctx, tx, &after, selectState+` WHERE host_id = ?`, hostID); err != nil {
		return api.ContainmentState{}, false, fmt.Errorf("read changed containment of %s: %w", hostID, err)
	}
	if err := tx.Commit(); err != nil {
		return api.ContainmentState{}, false, fmt.Errorf("commit containment change of %s: %w", hostID, err)
	}
	return after.state(), true, nil
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
