//go:build integration

// Flush-path coverage for issue #535: the set-based flush must isolate a permanent data error by degrading to a per-row apply,
// and that per-row fallback must still resolve a same-batch re-exec chain's back-reference. This is the corner where the batched
// multi-row INSERT cannot be used (the chain link needs the predecessor's real id) AND a poison row forces the fallback at once.

package tests

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

// spec:server-process-graph-builder/set-based-batch-materialization-is-equivalent-to-per-event-application/a-poison-data-error-is-isolated-under-batched-persistence
func TestProcessBatch_PoisonFallbackPreservesReExecChain(t *testing.T) {
	t.Parallel()
	b, db := newBuilder(t)
	ctx := t.Context()

	now := time.Now().UnixNano()
	poisonHost := strings.Repeat("h", 300) // exceeds host_id VARCHAR(255): permanent ER_DATA_TOO_LONG, forces the per-row fallback
	events := []api.Event{
		// A re-exec chain built entirely within this batch: fork -> exec -> re-exec. The new re-exec generation links to a
		// predecessor created in the same batch, so the flush cannot use the plain multi-row INSERT and must resolve the link to a
		// real id during the per-row apply that the poison row triggers.
		{EventID: "f1", HostID: "good", TimestampNs: now, IngestedAtNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":800,"parent_pid":1}`)},
		{EventID: "e1", HostID: "good", TimestampNs: now + 1, IngestedAtNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":800,"ppid":1,"path":"/bin/a"}`)},
		{EventID: "e2", HostID: "good", TimestampNs: now + 2, IngestedAtNs: now + 2, EventType: "exec",
			Payload: json.RawMessage(`{"pid":800,"ppid":1,"path":"/bin/b"}`)},
		{EventID: "poison", HostID: poisonHost, TimestampNs: now + 3, IngestedAtNs: now + 3, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":900,"parent_pid":1}`)},
	}

	require.NoError(t, b.ProcessBatch(ctx, events), "the poison row must be isolated, not fail the batch")

	var rows []api.Process
	require.NoError(t, db.SelectContext(ctx, &rows,
		`SELECT id, host_id, pid, ppid, path, fork_time_ns, exec_time_ns, exit_time_ns, exit_reason, previous_exec_id
		 FROM processes WHERE host_id = 'good' AND pid = 800 ORDER BY id`))
	require.Len(t, rows, 2, "the in-batch re-exec chain persists despite the poison sibling")

	// One generation is closed with the reexec reason; the live one back-references it.
	var closed, live *api.Process
	for i := range rows {
		if rows[i].ExitTimeNs == nil {
			live = &rows[i]
		} else {
			closed = &rows[i]
		}
	}
	require.NotNil(t, closed, "the prior generation is closed")
	require.NotNil(t, live, "the new generation is live")
	assert.Equal(t, api.ExitReasonReExec, *closed.ExitReason)
	assert.Equal(t, "/bin/a", closed.Path)
	assert.Equal(t, "/bin/b", live.Path)
	require.NotNil(t, live.PreviousExecID, "the re-exec link survives the per-row fallback")
	assert.Equal(t, closed.ID, *live.PreviousExecID, "the link resolves to the predecessor's real id, not a provisional one")

	var poison int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM processes WHERE pid = 900").Scan(&poison))
	assert.Equal(t, 0, poison, "the poison fork is dropped")
}
