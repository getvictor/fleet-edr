// Package versionedset stores a whole set as one versioned JSON row, and replaces it under a row lock.
//
// Two bounded contexts need exactly this: the rules context's watched-path set and the response context's containment
// reachable-address set. Copying it sideways between them is what the contributor guide forbids, and the reason is not tidiness
// (issue #1109). The valuable part is the concurrency, and it is subtle: the lock ordering, the conditional-replace refusal, and
// above all the strictly increasing update time. A host orders sets by version or by that time, so a later version stamped with
// an earlier one lets an out-of-order delivery reinstate an older set. Two copies can drift on any of that, and the drift shows
// up as a rare mis-ordered push on a host rather than as a failing test.
//
// The package deliberately stops at bytes. Each context decodes its own payload and maps the row onto its own API type, because
// those types differ and the mapping is the part that is genuinely per-context. What is shared is what has to agree.
package versionedset

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/jmoiron/sqlx"
)

// identifier is what a table or column name may look like. Neither can be a bound parameter, so they are interpolated, and this
// is what keeps that safe. Deliberately narrow: every name in this schema is lowercase with underscores, so anything else is a
// caller mistake rather than a name worth supporting.
var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Table names the row a Store owns: the table, the column holding the payload, and the noun its errors are written in.
//
// The row itself is always `id = 1`. A set that is a whole deployment's is one row by definition, and offering a key would
// invite a second row that nothing else in this design would order.
type Table struct {
	// Name is the table, which must hold exactly one row at id = 1.
	Name string
	// PayloadColumn is the column holding the set's JSON.
	PayloadColumn string
	// Noun is what the set is called in error messages, such as "watched path set". Lowercase, since it is interpolated
	// mid-sentence.
	Noun string
}

// Row is one read of the set: its version, its payload as stored, and who last changed it and when.
type Row struct {
	Version   int64        `db:"version"`
	Payload   []byte       `db:"payload"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	UpdatedBy string       `db:"updated_by"`
}

// UpdatedAtPtr is the update time as an optional, which is how both contexts' API types carry it. Nil for a set no operator has
// changed.
func (r Row) UpdatedAtPtr() *time.Time {
	if !r.UpdatedAt.Valid {
		return nil
	}
	t := r.UpdatedAt.Time
	return &t
}

// Store reads and replaces one versioned single-row set.
type Store struct {
	db        *sqlx.DB
	table     Table
	selectSet string
	update    string
}

// New builds a Store for one table. It panics on a nil db or an identifier that is not a plain lowercase name, both of which are
// wiring bugs: the identifiers are interpolated into SQL, so the check has to happen before any statement is built, and a
// deployment is better off failing at startup than running with a store pointed somewhere unintended.
func New(db *sqlx.DB, table Table) *Store {
	if db == nil {
		panic("versionedset.New: db must not be nil")
	}
	if !identifier.MatchString(table.Name) {
		panic("versionedset.New: table name is not a plain identifier: " + table.Name)
	}
	if !identifier.MatchString(table.PayloadColumn) {
		panic("versionedset.New: payload column is not a plain identifier: " + table.PayloadColumn)
	}
	if table.Noun == "" {
		panic("versionedset.New: noun must not be empty")
	}
	return &Store{
		db:    db,
		table: table,
		// The payload column is aliased to `payload` so Row's db tags are the same whatever the column is called.
		selectSet: fmt.Sprintf("SELECT version, %s AS payload, updated_at, updated_by FROM %s WHERE id = 1",
			table.PayloadColumn, table.Name),
		// GREATEST against the stored time plus a microsecond is what makes the time STRICTLY increasing, rather than merely
		// current: two replacements inside one clock tick would otherwise share a timestamp, and a host ordering by it could
		// not tell them apart. NOW(6) is the database's clock, so one clock orders every replica's writes.
		update: fmt.Sprintf(`UPDATE %s
			SET version = version + 1, %s = ?, updated_by = ?,
			    updated_at = GREATEST(NOW(6), COALESCE(updated_at + INTERVAL 1 MICROSECOND, NOW(6)))
			WHERE id = 1`, table.Name, table.PayloadColumn),
	}
}

// Get returns the stored row.
func (s *Store) Get(ctx context.Context) (Row, error) {
	var row Row
	if err := sqlx.GetContext(ctx, s.db, &row, s.selectSet); err != nil {
		return Row{}, fmt.Errorf("read %s: %w", s.table.Noun, err)
	}
	return row, nil
}

// Replace stores payload as the new set and returns the row it replaced and the new one, one version past it.
//
// The previous row, the version and the update time are read and written under the row lock, so concurrent replacements are
// ordered by who takes the lock: each gets the next version, reports the set it actually replaced, and gets an update time
// strictly later than the one before.
//
// A non-nil expectedVersion makes the replacement conditional. When the stored set is at any other version, which means someone
// changed it since the caller read it, Replace stores nothing and returns conflict wrapped with both versions. Compared under
// the same lock, so two operators saving edits of the same version cannot both succeed.
//
// inTx runs inside the transaction, after the replacement and before the commit, and is where the caller writes whatever must
// land with the change or not at all: both callers enqueue an audit entry there. Returning an error from it abandons the
// replacement, which is the point. It is a callback rather than a returned transaction because the two callers enqueue
// differently, one holding the entry for a later seal, and neither difference belongs in here.
func (s *Store) Replace(
	ctx context.Context, payload []byte, actor string, expectedVersion *int64, conflict error,
	inTx func(ctx context.Context, tx *sqlx.Tx, previous, next Row) error,
) (previous, next Row, err error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return Row{}, Row{}, fmt.Errorf("begin %s replace: %w", s.table.Noun, err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := sqlx.GetContext(ctx, tx, &previous, s.selectSet+" FOR UPDATE"); err != nil {
		return Row{}, Row{}, fmt.Errorf("lock %s: %w", s.table.Noun, err)
	}
	if expectedVersion != nil && previous.Version != *expectedVersion {
		return Row{}, Row{}, fmt.Errorf("%w: it is at version %d, not %d", conflict, previous.Version, *expectedVersion)
	}
	if _, err := tx.ExecContext(ctx, s.update, payload, actor); err != nil {
		return Row{}, Row{}, fmt.Errorf("replace %s: %w", s.table.Noun, err)
	}
	// Read back rather than computed, so the version and the update time are the ones the database actually stored.
	if err := sqlx.GetContext(ctx, tx, &next, s.selectSet); err != nil {
		return Row{}, Row{}, fmt.Errorf("read replaced %s: %w", s.table.Noun, err)
	}
	if err := inTx(ctx, tx, previous, next); err != nil {
		return Row{}, Row{}, err
	}
	if err := tx.Commit(); err != nil {
		return Row{}, Row{}, fmt.Errorf("commit %s replace: %w", s.table.Noun, err)
	}
	return previous, next, nil
}
