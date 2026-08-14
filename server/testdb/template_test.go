package testdb_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb"
)

// synthetic is a schema small enough to reason about and shaped like the real one where it matters: a parent, a child with a
// FOREIGN KEY onto it, a secondary index, and a migration-version table whose rows the replay has to carry over.
func synthetic(ctx context.Context, db *sqlx.DB) error {
	stmts := []string{
		// name_len is GENERATED: MySQL rejects an INSERT that names such a column, so the row copy has to skip it. The real
		// schema has one (events.payload_pid, extracted from the JSON payload); without it here, dropping that filter would
		// pass every test in this file and only break the full integration suite.
		"CREATE TABLE parent (id BIGINT PRIMARY KEY, name VARCHAR(64) NOT NULL, " +
			"name_len INT GENERATED ALWAYS AS (CHAR_LENGTH(name)) STORED)",
		`CREATE TABLE child (
			id BIGINT PRIMARY KEY,
			parent_id BIGINT NOT NULL,
			label VARCHAR(64) NOT NULL,
			KEY idx_child_label (label),
			CONSTRAINT fk_child_parent FOREIGN KEY (parent_id) REFERENCES parent(id)
		)`,
		"CREATE TABLE synthetic_goose_db_version (id BIGINT AUTO_INCREMENT PRIMARY KEY, version_id BIGINT NOT NULL, is_applied BOOL NOT NULL)",
		"INSERT INTO synthetic_goose_db_version (version_id, is_applied) VALUES (1, 1), (2, 1)",
		// Seed data in an ordinary table, mirroring the migrations that insert the `sys` principal and friends.
		"INSERT INTO parent (id, name) VALUES (1, 'seeded')",
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// dumpSchema reads every table's DDL back, which is the strongest available statement of "these two databases are the same".
func dumpSchema(t *testing.T, db *sqlx.DB) map[string]string {
	t.Helper()
	var tables []string
	require.NoError(t, db.SelectContext(t.Context(), &tables, "SHOW TABLES"))
	out := make(map[string]string, len(tables))
	for _, table := range tables {
		var name, ddl string
		require.NoError(t, db.QueryRowContext(t.Context(), "SHOW CREATE TABLE `"+table+"`").Scan(&name, &ddl))
		out[name] = ddl
	}
	return out
}

// TestOpenTemplated_ReplayMatchesTheBuild pins the property the whole optimisation rests on: a database that replayed the
// template is byte-for-byte the same schema as the one that ran the build.
//
// The subtests are deliberately sequential. The first Open of a key BUILDS the template from its own database and returns it
// unchanged, so only the second and later calls exercise the replay path; running "built" first is what makes "replayed" a
// genuine clone rather than a second build.
func TestOpenTemplated_ReplayMatchesTheBuild(t *testing.T) { //nolint:paralleltest // subtests are ordered on purpose: the first Open of a key BUILDS the template, so only a later one exercises the replay
	const key = "synthetic-equivalence"
	var built, replayed map[string]string

	t.Run("built", func(t *testing.T) {
		built = dumpSchema(t, testdb.OpenTemplated(t, key, synthetic))
	})
	t.Run("replayed", func(t *testing.T) {
		replayed = dumpSchema(t, testdb.OpenTemplated(t, key, synthetic))
	})

	require.Len(t, replayed, len(built), "the replay must produce the same set of tables")
	for table, ddl := range built {
		assert.Equal(t, ddl, replayed[table], "table %s differs between the built and replayed schema", table)
	}
}

// TestOpenTemplated_ReplayKeepsForeignKeysEnforced is the reason the capture uses SHOW CREATE TABLE rather than
// CREATE TABLE ... LIKE. LIKE is simpler and would drop the constraints silently, leaving tests passing against a database
// shape production cannot have. Asserting the DDL text alone would not catch a constraint that exists but is not enforced, so
// this writes a row that violates it.
func TestOpenTemplated_ReplayKeepsForeignKeysEnforced(t *testing.T) { //nolint:paralleltest // subtests are ordered on purpose: the first Open of a key BUILDS the template, so only a later one exercises the replay
	const key = "synthetic-fk"
	t.Run("build", func(t *testing.T) { _ = testdb.OpenTemplated(t, key, synthetic) })

	t.Run("replayed enforces the constraint", func(t *testing.T) {
		db := testdb.OpenTemplated(t, key, synthetic)
		_, err := db.ExecContext(t.Context(), "INSERT INTO child (id, parent_id, label) VALUES (1, 999, 'orphan')")
		require.Error(t, err, "an orphan child must be rejected; the foreign key did not survive the replay")

		// And the constraint must accept a legitimate row, so the test cannot pass by the table being broken outright.
		_, err = db.ExecContext(t.Context(), "INSERT INTO parent (id, name) VALUES (999, 'p')")
		require.NoError(t, err)
		_, err = db.ExecContext(t.Context(), "INSERT INTO child (id, parent_id, label) VALUES (1, 999, 'ok')")
		require.NoError(t, err)
	})
}

// TestOpenTemplated_ReplayCarriesSeededRows covers the rows a migration leaves behind, of which this repo has three kinds: the
// migration-version bookkeeping (so a cloned database reads as already-migrated rather than re-running everything), and real
// seed data like the `sys` principal and the detection-config version row that product code expects to exist.
func TestOpenTemplated_ReplayCarriesSeededRows(t *testing.T) { //nolint:paralleltest // subtests are ordered on purpose: the first Open of a key BUILDS the template, so only a later one exercises the replay
	const key = "synthetic-versions"
	t.Run("build", func(t *testing.T) { _ = testdb.OpenTemplated(t, key, synthetic) })

	t.Run("replayed", func(t *testing.T) {
		db := testdb.OpenTemplated(t, key, synthetic)
		var versions []int64
		require.NoError(t, db.SelectContext(t.Context(), &versions,
			"SELECT version_id FROM synthetic_goose_db_version ORDER BY version_id"))
		assert.Equal(t, []int64{1, 2}, versions, "the replay must record the same applied migrations as the build")

		// And ordinary seeded data, which is what five of this repo's migrations actually insert.
		var seeded []string
		require.NoError(t, db.SelectContext(t.Context(), &seeded, "SELECT name FROM parent ORDER BY id"))
		assert.Equal(t, []string{"seeded"}, seeded, "the replay must carry rows the schema build inserted")

		// And the generated column recomputes from the copied row rather than being copied (which MySQL would reject).
		var nameLen int
		require.NoError(t, db.QueryRowContext(t.Context(), "SELECT name_len FROM parent WHERE id = 1").Scan(&nameLen))
		assert.Equal(t, len("seeded"), nameLen, "the generated column must be recomputed in the replayed database")
	})
}

// TestOpenTemplated_ReplayLeavesForeignKeyChecksOn guards the one piece of session state the replay touches. The DDL runs with
// FOREIGN_KEY_CHECKS off (the tables reference each other and SHOW TABLES hands them back alphabetically), and the connection
// goes back to a shared pool afterwards. A connection returned with checks still disabled would silently drop referential
// integrity for whichever test drew it next.
func TestOpenTemplated_ReplayLeavesForeignKeyChecksOn(t *testing.T) { //nolint:paralleltest // subtests are ordered on purpose: the first Open of a key BUILDS the template, so only a later one exercises the replay
	const key = "synthetic-session"
	t.Run("build", func(t *testing.T) { _ = testdb.OpenTemplated(t, key, synthetic) })

	t.Run("replayed", func(t *testing.T) {
		db := testdb.OpenTemplated(t, key, synthetic)
		// Drain more connections than the replay used so the check is not looking at a single lucky one.
		for range 4 {
			var enabled int
			require.NoError(t, db.QueryRowContext(t.Context(), "SELECT @@SESSION.foreign_key_checks").Scan(&enabled))
			assert.Equal(t, 1, enabled, "the replay must restore foreign key checks before releasing the connection")
		}
	})
}

// TestOpenTemplated_ParallelCallersShareOneBuild covers the concurrency the suite actually runs under: the template is built
// once even when many parallel tests reach it at the same time, and every one of them gets a usable schema.
func TestOpenTemplated_ParallelCallersShareOneBuild(t *testing.T) {
	t.Parallel()
	const key = "synthetic-parallel"
	// Atomic, because this counter's whole job is to catch OpenTemplated building concurrently. A plain int would be a data
	// race in exactly that regression, and could lose an increment and report the count it was supposed to catch.
	var builds atomic.Int64
	counted := func(ctx context.Context, db *sqlx.DB) error {
		builds.Add(1)
		return synthetic(ctx, db)
	}
	for i := range 6 {
		t.Run(fmt.Sprintf("caller-%d", i), func(t *testing.T) {
			t.Parallel()
			db := testdb.OpenTemplated(t, key, counted)
			var n int
			require.NoError(t, db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM parent").Scan(&n),
				"caller %d did not get a usable schema", i)
		})
	}
	t.Cleanup(func() {
		assert.Equal(t, int64(1), builds.Load(), "the schema must be built once per process, not once per caller")
	})
}
