package testdb

import (
	"testing"

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
