package auditoutbox

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// Store is the rules context's own outbox table, detection_config_audit_outbox, which detection-config changes write their audit
// entries into (issue #1022). It is the Outbox a detection-config Drain reads.
type Store struct {
	db *sqlx.DB
}

var _ Outbox = (*Store)(nil)

// NewStore builds a Store. Panics on a nil db, which is a wiring bug.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("auditoutbox.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

// Enqueue writes entry inside the caller's transaction, deliverable as soon as the transaction commits.
func Enqueue(ctx context.Context, tx sqlx.ExecerContext, entry Entry) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO detection_config_audit_outbox (kind, payload) VALUES (?, ?)`, entry.Kind, string(entry.Payload)); err != nil {
		return fmt.Errorf("enqueue audit entry: %w", err)
	}
	return nil
}

// EnqueueHeld writes entry inside the caller's transaction, withheld from delivery for hold, and returns its id. The writer releases
// it sooner with Seal. A writer that dies first leaves the entry to be delivered as written once hold passes.
func EnqueueHeld(ctx context.Context, tx sqlx.ExecerContext, entry Entry, hold time.Duration) (int64, error) {
	res, err := tx.ExecContext(ctx,
		`INSERT INTO detection_config_audit_outbox (kind, payload, held_until) VALUES (?, ?, NOW(6) + INTERVAL ? MICROSECOND)`,
		entry.Kind, string(entry.Payload), hold.Microseconds())
	if err != nil {
		return 0, fmt.Errorf("enqueue held audit entry: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("held audit entry id: %w", err)
	}
	return id, nil
}

// Seal replaces a held entry's payload with entry's and makes it deliverable. It reports false when the entry is gone, because its
// hold passed and a drain delivered it as first written.
func (s *Store) Seal(ctx context.Context, id int64, entry Entry) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE detection_config_audit_outbox SET payload = ?, held_until = NULL WHERE id = ?`, string(entry.Payload), id)
	if err != nil {
		return false, fmt.Errorf("seal audit entry %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("seal audit entry %d rows: %w", id, err)
	}
	return n > 0, nil
}

// PendingAuditEntries returns up to limit deliverable entries, oldest first. A held entry whose hold has not passed is left out.
func (s *Store) PendingAuditEntries(ctx context.Context, limit int) ([]Pending, error) {
	var rows []struct {
		ID      int64  `db:"id"`
		Kind    string `db:"kind"`
		Payload []byte `db:"payload"`
	}
	if err := s.db.SelectContext(ctx, &rows,
		`SELECT id, kind, payload FROM detection_config_audit_outbox
		 WHERE held_until IS NULL OR held_until <= NOW(6) ORDER BY id LIMIT ?`, limit); err != nil {
		return nil, fmt.Errorf("read detection config audit outbox: %w", err)
	}
	out := make([]Pending, len(rows))
	for i, r := range rows {
		out[i] = Pending{ID: r.ID, Kind: r.Kind, Payload: r.Payload}
	}
	return out, nil
}

// DeleteAuditEntries removes delivered entries.
func (s *Store) DeleteAuditEntries(ctx context.Context, ids []int64) error {
	query, args, err := sqlx.In(`DELETE FROM detection_config_audit_outbox WHERE id IN (?)`, ids)
	if err != nil {
		return fmt.Errorf("build audit outbox delete: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("delete delivered audit entries: %w", err)
	}
	return nil
}
