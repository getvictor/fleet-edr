//go:build integration

package mysql

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb"
)

// TestTxWriter_RemembersTheFirstFailureAndSkipsTheRest pins the contract the pack operations lean on.
//
// They stopped checking an error after every statement and now run a sequence and check once, which is only safe if the writer
// really does stop at the first failure: a later statement running against a transaction whose earlier write failed could commit
// half an operation. The error it reports also has to name the step, or one error for ten statements would say nothing about
// which failed.
func TestTxWriter_RemembersTheFirstFailureAndSkipsTheRest(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	ctx := t.Context()

	tx, err := db.BeginTxx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback() //nolint:errcheck

	w := &txWriter{ctx: ctx, tx: tx}
	w.exec("first step", "SELECT 1")
	require.NoError(t, w.err, "a statement that succeeds leaves no error")

	w.exec("the failing step", "INSERT INTO a_table_that_does_not_exist (x) VALUES (1)")
	require.Error(t, w.err)
	assert.Contains(t, w.err.Error(), "the failing step", "the one error must name which statement failed")
	first := w.err

	// The whole point: nothing after a failure runs, and the first error is the one reported.
	w.exec("a later step", "INSERT INTO another_missing_table (x) VALUES (1)")
	assert.Same(t, first, w.err, "a later statement must not run, nor replace the first failure")
}
