package auditoutbox

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/jmoiron/sqlx"
)

// Store reads and writes one context's outbox table. The table is named at construction because the encoding, the ordering and the
// hold semantics are this package's while the table belongs to the context whose transactions write it: the detection-config outbox
// and the response outbox hold the same rows and differ only in which changes commit into them.
type Store struct {
	db    *sqlx.DB
	table string
}

var _ Outbox = (*Store)(nil)

// tableName is what a table this package will interpolate into a statement may look like. The name is wiring, never input, and this
// is here so that stays true: a name from anywhere else cannot reach the SQL.
var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// mustBeTableName panics unless table is a plain identifier. Every exported function that puts a table name into statement text goes
// through it, so the check cannot be had by one entry point and missed by another.
func mustBeTableName(caller, table string) {
	if !tableName.MatchString(table) {
		panic("auditoutbox." + caller + ": table must be a plain identifier, got " + table)
	}
}

// CreateTableSQL is the table a Store reads and writes, as the context adopting the outbox must migrate it.
//
// goose reads SQL files and not Go, so this does not generate a context's migration: what it does is give the migration and this
// package one definition to agree on, and the conformance test at test/integration asserts every migrated outbox table matches what
// this produces. Before that, the shape lived in each migration and again in this package's test fixture, where the two could drift
// and the fixture would keep passing.
//
// held_until is part of the shape even for a context that writes no held entry, because PendingAuditEntries reads every outbox with
// one query and a table without the column could not be read by it.
func CreateTableSQL(table string) string {
	mustBeTableName("CreateTableSQL", table)
	return fmt.Sprintf(`CREATE TABLE %s (
	id         BIGINT       NOT NULL AUTO_INCREMENT,
	kind       VARCHAR(64)  NOT NULL,
	payload    JSON         NOT NULL,
	created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	held_until TIMESTAMP(6) NULL,
	PRIMARY KEY (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci`, table)
}

// NewStore builds a Store over table. Panics on a nil db or a table name that is not a plain identifier, both wiring bugs.
func NewStore(db *sqlx.DB, table string) *Store {
	if db == nil {
		panic("auditoutbox.NewStore: db must not be nil")
	}
	mustBeTableName("NewStore", table)
	return &Store{db: db, table: table}
}

// Enqueue writes entry inside the caller's transaction, deliverable as soon as the transaction commits.
func (s *Store) Enqueue(ctx context.Context, tx sqlx.ExecerContext, entry Entry) error {
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`INSERT INTO %s (kind, payload) VALUES (?, ?)`, s.table), entry.Kind, string(entry.Payload)); err != nil {
		return fmt.Errorf("enqueue audit entry: %w", err)
	}
	return nil
}

// EnqueueHeld writes entry inside the caller's transaction, withheld from delivery for hold, and returns its id. The writer releases
// it sooner with Seal. A writer that dies first leaves the entry to be delivered as written once hold passes.
func (s *Store) EnqueueHeld(ctx context.Context, tx sqlx.ExecerContext, entry Entry, hold time.Duration) (int64, error) {
	res, err := tx.ExecContext(ctx,
		fmt.Sprintf(`INSERT INTO %s (kind, payload, held_until) VALUES (?, ?, NOW(6) + INTERVAL ? MICROSECOND)`, s.table),
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

// Seal replaces a held entry's payload with entry's and makes it deliverable, provided its hold has not passed. It reports false when
// the hold has passed, because from then on a drain may already have read the entry as first written, and a seal it did not see would
// claim a delivery it cannot promise. Such an entry is delivered as first written. The hold is compared on the database clock, the
// same one PendingAuditEntries uses, so a drain can only read a held entry once a seal can no longer change it.
func (s *Store) Seal(ctx context.Context, id int64, entry Entry) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		fmt.Sprintf(`UPDATE %s SET payload = ?, held_until = NULL WHERE id = ? AND held_until > NOW(6)`, s.table),
		string(entry.Payload), id)
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
//
// A locking read, not a plain read, and that is what makes Seal and delivery exclusive. A plain read sees the last committed version,
// so a seal begun before the hold passed but not yet committed would let a drain read the unsealed payload and record it while the
// seal went on to report success. A locking read waits for that seal to commit and then reads the sealed entry, in its place in the
// order. It does not skip the row: skipping would deliver the entries after it first. The wait is bounded by the writers it can meet,
// a seal or a change's own transaction, each a few statements long, and the share locks last only for this statement.
func (s *Store) PendingAuditEntries(ctx context.Context, limit int) ([]Pending, error) {
	var rows []struct {
		ID      int64  `db:"id"`
		Kind    string `db:"kind"`
		Payload []byte `db:"payload"`
	}
	if err := s.db.SelectContext(ctx, &rows,
		fmt.Sprintf(`SELECT id, kind, payload FROM %s
		 WHERE held_until IS NULL OR held_until <= NOW(6) ORDER BY id LIMIT ? FOR SHARE`, s.table), limit); err != nil {
		return nil, fmt.Errorf("read %s: %w", s.table, err)
	}
	out := make([]Pending, len(rows))
	for i, r := range rows {
		out[i] = Pending{ID: r.ID, Kind: r.Kind, Payload: r.Payload}
	}
	return out, nil
}

// DeleteAuditEntries removes delivered entries.
func (s *Store) DeleteAuditEntries(ctx context.Context, ids []int64) error {
	query, args, err := sqlx.In(fmt.Sprintf(`DELETE FROM %s WHERE id IN (?)`, s.table), ids)
	if err != nil {
		return fmt.Errorf("build audit outbox delete: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("delete delivered audit entries: %w", err)
	}
	return nil
}
