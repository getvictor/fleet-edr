//go:build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/auditoutbox"
	"github.com/fleetdm/edr/server/testdb/full"
)

// outboxColumn is one row of SHOW COLUMNS, which carries the name, the type, whether the column is nullable, its default and its
// extra (auto_increment, DEFAULT_GENERATED). Comparing the whole row is what makes this catch a widened VARCHAR or a dropped NOT NULL
// rather than only a missing column.
type outboxColumn struct {
	Field   string  `db:"Field"`
	Type    string  `db:"Type"`
	Null    string  `db:"Null"`
	Key     string  `db:"Key"`
	Default *string `db:"Default"`
	Extra   string  `db:"Extra"`
}

func columnsOf(t *testing.T, db *sqlx.DB, table string) []outboxColumn {
	t.Helper()
	rows, err := db.QueryxContext(t.Context(), fmt.Sprintf("SHOW COLUMNS FROM %s", table))
	require.NoError(t, err)
	defer rows.Close()
	var out []outboxColumn
	for rows.Next() {
		var c outboxColumn
		require.NoError(t, rows.StructScan(&c))
		out = append(out, c)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, out, "%s has no columns", table)
	return out
}

// Each context migrates its own audit outbox table with its own hand-written SQL file, while one shared store reads and writes all of
// them with one set of statements. That only holds while the tables agree, and nothing in a migration says which shape it owes: a
// migration that widened a column or dropped a NOT NULL would keep passing its own context's tests and break the shared store's
// reads somewhere else. This asserts every migrated outbox table matches what auditoutbox.CreateTableSQL builds.
//
// Cross-context rather than per-context deliberately: the point is that the tables agree with ONE definition, which no single
// context's test can say.
func TestAuditOutboxTablesMatchTheSharedDefinition(t *testing.T) {
	t.Parallel()
	db := full.Open(t)

	const reference = "audit_outbox_reference"
	_, err := db.ExecContext(t.Context(), auditoutbox.CreateTableSQL(reference))
	require.NoError(t, err)
	want := columnsOf(t, db, reference)

	// Every outbox table a context migrates. A context adopting the outbox adds its table here.
	for _, table := range []string{"detection_config_audit_outbox", "containment_audit_outbox"} {
		t.Run(table, func(t *testing.T) {
			assert.Equal(t, want, columnsOf(t, db, table),
				"%s has drifted from auditoutbox.CreateTableSQL, which the shared store's statements assume", table)
		})
	}
}
