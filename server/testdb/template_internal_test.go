package testdb

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplaySchema_RestoresForeignKeyChecksAfterAFailure pins the failure path of the replay.
//
// The success path was already covered, and that is exactly what made this worth adding: the first version of replaySchema
// restored FOREIGN_KEY_CHECKS only at the end, so a DDL error returned early and handed the pooled connection back with
// referential integrity switched off. Every later test drawing that connection would have accepted rows the schema forbids,
// and the damage would have surfaced nowhere near this code.
//
// The test is in-package because it drives replaySchema directly: reaching the failure path through OpenTemplated would mean
// corrupting a template, which is harder to arrange and states the invariant less directly.
func TestReplaySchema_RestoresForeignKeyChecksAfterAFailure(t *testing.T) {
	t.Parallel()
	db := Open(t)

	err := replaySchema(t.Context(), db, []string{"CREATE TABLE definitely not valid sql"}, nil)
	require.Error(t, err, "a bad statement must surface as an error rather than being swallowed")

	// Drain several connections: the replay pins one, and the check must hold for whichever the pool hands out next.
	for range 4 {
		var enabled int
		require.NoError(t, db.QueryRowContext(t.Context(), "SELECT @@SESSION.foreign_key_checks").Scan(&enabled))
		assert.Equal(t, 1, enabled, "a failed replay must still restore foreign key checks before releasing the connection")
	}
}

// TestReplaySchema_SurfacesASeedFailure covers the other half of the replay's error handling. The DDL and the seed rows fail
// for different reasons (a malformed table versus a row the schema rejects), and only the DDL half was exercised.
func TestReplaySchema_SurfacesASeedFailure(t *testing.T) {
	t.Parallel()
	db := Open(t)

	err := replaySchema(t.Context(), db,
		[]string{"CREATE TABLE seeded (id BIGINT PRIMARY KEY)"},
		[]seedInsert{{stmt: "INSERT INTO seeded (nosuchcolumn) VALUES (?)", args: []any{1}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restore seeded row", "the error must say which phase failed")
}

// recordingTB stands in for the test so OpenTemplated's own failure can be asserted rather than aborting the run. Embedding
// *testing.T is what satisfies testing.TB (the interface has an unexported method); only Name and Fatalf are overridden.
type recordingTB struct {
	*testing.T
	name   string
	failed []string
}

func (r *recordingTB) Name() string { return r.name }

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.failed = append(r.failed, fmt.Sprintf(format, args...))
}

// TestOpenTemplated_ABrokenBuildFailsEveryCaller pins the deliberate choice not to fall back.
//
// A template that failed to build cannot be replayed, and the tempting alternative (quietly running the migrations per test
// instead) would turn a broken fixture into a suite that is merely slow, hiding the breakage behind the very cost this code
// exists to remove. The second caller matters most: sync.Once means only the first one runs the build, so without the stored
// error every caller after it would sail past with an empty schema.
func TestOpenTemplated_ABrokenBuildFailsEveryCaller(t *testing.T) {
	t.Parallel()
	const key = "synthetic-broken-build"
	broken := func(context.Context, *sqlx.DB) error { return errors.New("schema build exploded") }

	first := &recordingTB{T: t, name: t.Name() + "_first"}
	_ = OpenTemplated(first, key, broken)
	require.NotEmpty(t, first.failed, "the caller that ran the build must fail")
	assert.Contains(t, first.failed[0], "schema build exploded", "the failure must name the underlying cause")

	second := &recordingTB{T: t, name: t.Name() + "_second"}
	_ = OpenTemplated(second, key, broken)
	require.NotEmpty(t, second.failed, "a later caller must fail too rather than silently getting no schema")
	assert.Contains(t, second.failed[0], "schema build exploded")
}
