package versionedset

import (
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These are deliberately DB-free. The behaviour that needs a database (the lock ordering, the conditional replace, the strictly
// increasing stamp) is exercised against this one implementation by both callers' integration tests, and this package cannot
// reach server/testdb: nothing under internal/ imports server/, because the agent imports internal/ and that boundary is what
// keeps it standalone.
//
// What is left here is what those tests cannot see: the identifiers are interpolated rather than bound, so the validation that
// makes that safe is checked directly, and the two statements are asserted as text so the guarantee written into them cannot be
// edited away silently.

func testStore(t *testing.T, table Table) *Store {
	t.Helper()
	// A wrapper around a nil driver connection: New only builds statements, and nothing here executes one.
	return New(sqlx.NewDb(&sql.DB{}, "mysql"), table)
}

var validTable = Table{Name: "watched_path_set", PayloadColumn: "paths", Noun: "watched path set"}

// The identifiers cannot be bound as parameters, so they are interpolated, and this is the whole of what keeps that safe. It
// fails at construction rather than at the first query: a deployment is better off not starting than running with a store
// pointed somewhere unintended.
func TestNewRefusesAnythingButAPlainIdentifier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc  string
		table Table
	}{
		{desc: "a quoted name", table: Table{Name: "`watched_path_set`", PayloadColumn: "paths", Noun: "n"}},
		{desc: "a name carrying a statement", table: Table{Name: "t; DROP TABLE users", PayloadColumn: "paths", Noun: "n"}},
		{desc: "a name carrying a comment", table: Table{Name: "t -- x", PayloadColumn: "paths", Noun: "n"}},
		{desc: "a schema-qualified name", table: Table{Name: "edr.watched_path_set", PayloadColumn: "paths", Noun: "n"}},
		{desc: "an uppercase name", table: Table{Name: "Watched_Path_Set", PayloadColumn: "paths", Noun: "n"}},
		{desc: "a name starting with a digit", table: Table{Name: "1set", PayloadColumn: "paths", Noun: "n"}},
		{desc: "an empty name", table: Table{Name: "", PayloadColumn: "paths", Noun: "n"}},
		{desc: "a column carrying a statement", table: Table{Name: "watched_path_set", PayloadColumn: "paths, x = 1", Noun: "n"}},
		{desc: "a quoted column", table: Table{Name: "watched_path_set", PayloadColumn: "`paths`", Noun: "n"}},
		{desc: "an empty column", table: Table{Name: "watched_path_set", PayloadColumn: "", Noun: "n"}},
		{desc: "no noun, which would leave errors unattributable", table: Table{Name: "watched_path_set", PayloadColumn: "paths"}},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			assert.Panics(t, func() { _ = testStore(t, tc.table) })
		})
	}
}

func TestNewAcceptsTheIdentifiersThisSchemaUses(t *testing.T) {
	t.Parallel()
	for _, table := range []Table{
		validTable,
		{Name: "containment_reachable_set", PayloadColumn: "addresses", Noun: "reachable set"},
		{Name: "_leading_underscore", PayloadColumn: "c9", Noun: "n"},
	} {
		assert.NotPanics(t, func() { _ = testStore(t, table) })
	}
}

func TestNewRefusesANilDB(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { _ = New(nil, validTable) })
}

// The payload column is aliased to `payload` so Row's db tags hold whatever the column is called. Without the alias a caller
// whose column is not literally named payload would scan nothing into it, and the set would read as empty rather than fail.
func TestSelectAliasesThePayloadColumn(t *testing.T) {
	t.Parallel()
	s := testStore(t, validTable)

	assert.Equal(t, "SELECT version, paths AS payload, updated_at, updated_by FROM watched_path_set WHERE id = 1", s.selectSet)
}

// The strictly increasing stamp is the subtlest thing this package owns and the one whose loss would show up as a rare
// mis-ordered push on a host rather than a failing test, so it is asserted as text.
//
// GREATEST against the stored time plus a microsecond is what makes it strictly increasing rather than merely current: two
// replacements inside one clock tick would otherwise share a stamp. NOW(6) is the database's clock, so one clock orders every
// replica's writes.
func TestUpdateStampsStrictlyAfterTheStoredTime(t *testing.T) {
	t.Parallel()
	s := testStore(t, validTable)

	require.Contains(t, s.update, "version = version + 1")
	assert.Contains(t, s.update, "GREATEST(NOW(6), COALESCE(updated_at + INTERVAL 1 MICROSECOND, NOW(6)))",
		"a later version stamped with an earlier time lets an out-of-order delivery reinstate an older set")
	assert.Contains(t, s.update, "UPDATE watched_path_set")
	assert.Contains(t, s.update, "paths = ?")
	assert.Contains(t, s.update, "WHERE id = 1")
}

func TestUpdatedAtPtrDistinguishesUnsetFromZero(t *testing.T) {
	t.Parallel()
	assert.Nil(t, Row{}.UpdatedAtPtr(), "a set no operator has changed has no update time")

	row := Row{UpdatedAt: sql.NullTime{Valid: true}}
	require.NotNil(t, row.UpdatedAtPtr())
	assert.True(t, row.UpdatedAtPtr().IsZero(), "a stored zero time is a time, not an absence")
}
