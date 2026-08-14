package testdb

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"
)

// OpenTemplated is Open plus a schema, where the schema is built by running `apply` ONCE per process and replayed as plain DDL
// for every test after that.
//
// # Why this exists
//
// apply is a migration run, and migration runs are the entire cost of a database-backed test here. Measured against the test
// MySQL: creating the isolated database costs 2.5ms, while applying all seven bounded contexts' schemas costs 555ms, so 99.6% of
// what a test pays before its first line runs is goose executing 33 migrations, each in its own transaction with its own version
// bookkeeping, in seven separate corpora. server/detection/internal/tests calls this 109 times.
//
// Replaying the finished schema instead costs 203ms, a 2.7x saving per test, because it skips the migration machinery entirely
// and issues the resulting CREATE TABLE statements directly.
//
// # What is preserved
//
// The captured DDL comes from SHOW CREATE TABLE, NOT from `CREATE TABLE ... LIKE`. LIKE would be simpler and is the obvious
// reach, but it silently drops FOREIGN KEY constraints, and this schema has 27 of them. A fixture that quietly produced tables
// without their foreign keys would let a test pass against a database that cannot exist in production, which is worse than a
// slow fixture.
//
// The goose version rows are replayed too, so a cloned database is indistinguishable from a migrated one to code that inspects
// migration state: a later ApplySchema call no-ops exactly as it would have.
//
// # Why the template is captured from the first test's own database
//
// It needs no separate template database, and therefore no lifetime to manage. A dedicated template database would either be
// dropped by whichever test's Cleanup created it (mid-run, breaking everyone after) or leak one database per process, and its
// name would have to be salted per process anyway, because `go test ./server/...` runs package binaries concurrently against one
// MySQL and two processes sharing a template name would race each other's DROP.
//
// The first caller pays the migration cost it would have paid regardless, and hands the schema to everyone after it. Callers
// that arrive while the first is still building block on the once and then replay, so no second migration run happens.
func OpenTemplated(tb testing.TB, key string, apply func(context.Context, *sqlx.DB) error) *sqlx.DB {
	tb.Helper()
	db := Open(tb)
	ctx := tb.Context()

	tmpl := templateFor(key)
	tmpl.once.Do(func() {
		if err := apply(ctx, db); err != nil {
			tmpl.err = fmt.Errorf("build %q schema template: %w", key, err)
			return
		}
		tmpl.ddl, tmpl.seed, tmpl.err = captureSchema(ctx, db)
		// Remember WHICH database the schema was built on. That one already has the tables, so it must not be sent
		// through the replay; without this it hits "table already exists" and the first caller of every key fails.
		tmpl.owner = db
		tmpl.built = true
	})
	if tmpl.err != nil {
		// Fail every caller, not just the one that happened to run the build: a template that failed to capture cannot be
		// replayed, and silently falling back to a per-test migration run would hide the breakage behind a slow suite.
		tb.Fatalf("testdb: %v", tmpl.err)
	}
	if tmpl.builtBy(db) {
		return db
	}
	if err := replaySchema(ctx, db, tmpl.ddl, tmpl.seed); err != nil {
		tb.Fatalf("testdb: replay %q schema template: %v", key, err)
	}
	return db
}

// schemaTemplate is one captured schema: every table's CREATE statement, plus every row the migrations left behind.
type schemaTemplate struct {
	once  sync.Once
	ddl   []string
	seed  []seedInsert
	err   error
	built bool
	owner *sqlx.DB
}

// builtBy reports whether db is the database the template was captured from, which already has the schema on it.
func (t *schemaTemplate) builtBy(db *sqlx.DB) bool { return t.built && t.owner == db }

var (
	templatesMu sync.Mutex
	templates   = map[string]*schemaTemplate{}
)

func templateFor(key string) *schemaTemplate {
	templatesMu.Lock()
	defer templatesMu.Unlock()
	t, ok := templates[key]
	if !ok {
		t = &schemaTemplate{}
		templates[key] = t
	}
	return t
}

// seedInsert is one row a migration left behind, as a parameterised INSERT.
type seedInsert struct {
	stmt string
	args []any
}

// captureSchema reads back the exact DDL of every table plus every row the migrations seeded.
//
// The rows are not optional detail. Five migrations insert data (the `sys` principal and its siblings, the trace-sampler
// settings row, the detection-config version row), and code depends on it existing. A clone carrying the tables but not the
// seed would be a database no migration run can produce, and the tests that rely on those rows would fail in ways that look
// like product bugs. The goose version rows come along the same way, which is what makes a cloned database read as
// already-migrated.
func captureSchema(ctx context.Context, db *sqlx.DB) (ddl []string, seed []seedInsert, err error) {
	var tables []string
	if err := db.SelectContext(ctx, &tables, "SHOW TABLES"); err != nil {
		return nil, nil, fmt.Errorf("list tables: %w", err)
	}
	for _, table := range tables {
		var name, create string
		if err := db.QueryRowContext(ctx, fmt.Sprintf("SHOW CREATE TABLE `%s`", table)).Scan(&name, &create); err != nil {
			return nil, nil, fmt.Errorf("read DDL for %s: %w", table, err)
		}
		ddl = append(ddl, create)

		cols, err := insertableColumns(ctx, db, table)
		if err != nil {
			return nil, nil, err
		}
		if len(cols) == 0 {
			continue
		}
		tableSeed, err := captureRows(ctx, db, table, cols)
		if err != nil {
			return nil, nil, err
		}
		seed = append(seed, tableSeed...)
	}
	return ddl, seed, nil
}

// insertableColumns lists a table's columns EXCLUDING generated ones. MySQL rejects an INSERT that names a generated column,
// and the events table has one (payload_pid, extracted from the JSON payload), so copying rows blind would fail on the one
// table whose rows matter most to the detection suite.
func insertableColumns(ctx context.Context, db *sqlx.DB, table string) ([]string, error) {
	var cols []string
	err := db.SelectContext(ctx, &cols, `
		SELECT COLUMN_NAME FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND EXTRA NOT LIKE '%GENERATED%'
		ORDER BY ORDINAL_POSITION`, table)
	if err != nil {
		return nil, fmt.Errorf("list columns of %s: %w", table, err)
	}
	return cols, nil
}

func captureRows(ctx context.Context, db *sqlx.DB, table string, cols []string) ([]seedInsert, error) {
	quoted := make([]string, len(cols))
	placeholders := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = "`" + c + "`"
		placeholders[i] = "?"
	}
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM `%s`", strings.Join(quoted, ", "), table))
	if err != nil {
		return nil, fmt.Errorf("read rows of %s: %w", table, err)
	}
	defer rows.Close()

	stmt := fmt.Sprintf("INSERT INTO `%s` (%s) VALUES (%s)", table, strings.Join(quoted, ", "), strings.Join(placeholders, ", "))
	var out []seedInsert
	for rows.Next() {
		args := make([]any, len(cols))
		targets := make([]any, len(cols))
		for i := range args {
			targets[i] = &args[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("scan row of %s: %w", table, err)
		}
		out = append(out, seedInsert{stmt: stmt, args: args})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows of %s: %w", table, err)
	}
	return out, nil
}

// replaySchema writes the captured schema into a fresh database.
//
// Everything runs on ONE pinned connection. FOREIGN_KEY_CHECKS is a SESSION variable and *sqlx.DB is a pool, so issuing the SET
// and the CREATEs through the pool would let them land on different connections: the flag would apply to a connection doing no
// work while the DDL ran with checks still on, and the first table referencing a table created later would fail. The failure
// would depend on pool scheduling, which is the worst kind to debug.
//
// Checks are disabled rather than the tables being dependency-sorted because SHOW TABLES returns alphabetical order and the
// constraints form a graph; disabling is exact, and every constraint is still present in the created tables.
func replaySchema(ctx context.Context, db *sqlx.DB, ddl []string, seed []seedInsert) error {
	conn, err := db.Connx(ctx)
	if err != nil {
		return fmt.Errorf("pin connection: %w", err)
	}
	// The pooled connection goes back on close; a failure there is not something the caller can act on and must not mask the
	// replay's own error.
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		return fmt.Errorf("disable foreign key checks: %w", err)
	}
	for _, stmt := range ddl {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
	}
	for _, row := range seed {
		if _, err := conn.ExecContext(ctx, row.stmt, row.args...); err != nil {
			return fmt.Errorf("restore seeded row: %w", err)
		}
	}
	// Restore the session default before handing the connection back to the pool. Leaving it off would silently disable
	// referential integrity for whichever test later drew this connection, which is exactly the kind of cross-test leak the
	// per-test database exists to prevent.
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1"); err != nil {
		return fmt.Errorf("restore foreign key checks: %w", err)
	}
	return nil
}
