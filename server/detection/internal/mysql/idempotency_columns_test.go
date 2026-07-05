package mysql_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// The graph builder drives writes through the batch overlay + set-based flush, so the per-event Store write methods below are reached
// directly only here. These tests pin the migration-00011 idempotency columns (source_event_id / exec_event_id / exit_event_id), the
// EventAlreadyApplied probe the builder guards on, the exit fork-time bound, and the monotonic last-seen bump.

// TestStore_EventAlreadyApplied pins the re-processing guard probe: a row records the fork/exec/exit event ids that materialized it,
// and EventAlreadyApplied reports true for any of them, scoped to (host_id, pid).
func TestStore_EventAlreadyApplied(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	// source_event_id + exec_event_id are set at insert; exit_event_id is stamped only by the exit UPDATE, never at insert.
	_, err := s.InsertProcess(ctx, api.Process{
		HostID: "h", PID: 10, ForkTimeNs: 100,
		SourceEventID: new("fork-1"), ExecEventID: new("exec-1"),
	})
	require.NoError(t, err)
	affected, err := s.UpdateProcessExit(ctx, mysql.ProcessExitUpdate{
		HostID: "h", PID: 10, ExitTimeNs: 200, ExitIngestedAtNs: 201, ExitCode: 0, Reason: api.ExitReasonEvent, ExitEventID: "exit-1",
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)

	for _, id := range []string{"fork-1", "exec-1", "exit-1"} {
		applied, err := s.EventAlreadyApplied(ctx, "h", 10, id)
		require.NoError(t, err)
		assert.True(t, applied, "event %s should read as already applied", id)
	}

	applied, err := s.EventAlreadyApplied(ctx, "h", 10, "never-seen")
	require.NoError(t, err)
	assert.False(t, applied, "an unknown event is not applied")

	applied, err = s.EventAlreadyApplied(ctx, "h", 999, "fork-1")
	require.NoError(t, err)
	assert.False(t, applied, "the probe is scoped to the pid")
}

// TestStore_UpdateProcessExit_ForkTimeBound pins that an exit only closes a row that forked at or before the exit, and stamps the
// closing event's id so a replay is recognized.
func TestStore_UpdateProcessExit_ForkTimeBound(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	// A row that forked at 200; an exit at 100 (before its fork) must not close it.
	_, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 20, ForkTimeNs: 200})
	require.NoError(t, err)

	affected, err := s.UpdateProcessExit(ctx, mysql.ProcessExitUpdate{
		HostID: "h", PID: 20, ExitTimeNs: 100, ExitIngestedAtNs: 101, ExitCode: 0, Reason: api.ExitReasonEvent, ExitEventID: "exit-stale",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), affected, "an exit before the row's fork must not close it")

	// An exit after the fork closes it and stamps exit_event_id.
	affected, err = s.UpdateProcessExit(ctx, mysql.ProcessExitUpdate{
		HostID: "h", PID: 20, ExitTimeNs: 300, ExitIngestedAtNs: 301, ExitCode: 7, Reason: api.ExitReasonEvent, ExitEventID: "exit-real",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), affected)

	got, err := s.GetProcessByPID(ctx, "h", 20, 300)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.ExitEventID)
	assert.Equal(t, "exit-real", *got.ExitEventID)

	applied, err := s.EventAlreadyApplied(ctx, "h", 20, "exit-real")
	require.NoError(t, err)
	assert.True(t, applied, "the closing exit is recognized on replay")
}

// TestStore_UpdateProcessExec_StampsExecEventID pins that the first-exec-after-fork UPDATE records the exec event's id.
func TestStore_UpdateProcessExec_StampsExecEventID(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	_, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 30, ForkTimeNs: 10})
	require.NoError(t, err)

	require.NoError(t, s.UpdateProcessExec(ctx, mysql.ProcessExecUpdate{
		HostID: "h", PID: 30, ExecTimeNs: 20, Path: "/bin/x", ExecEventID: new("exec-30"),
	}))

	got, err := s.GetProcessByPID(ctx, "h", 30, 20)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.ExecEventID)
	assert.Equal(t, "exec-30", *got.ExecEventID)

	applied, err := s.EventAlreadyApplied(ctx, "h", 30, "exec-30")
	require.NoError(t, err)
	assert.True(t, applied)
}

// TestStore_UpdateLastSeenForSnapshot_Monotonic pins that the freshness bump only advances: a later, then an earlier heartbeat leaves
// last_seen_ns at the maximum so a replayed earlier heartbeat cannot regress it.
func TestStore_UpdateLastSeenForSnapshot_Monotonic(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	_, err := s.InsertProcess(ctx, api.Process{
		HostID: "h", PID: 40, ForkTimeNs: 10, ExecTimeNs: new(int64(10)), IsSnapshot: true, LastSeenNs: new(int64(10)),
	})
	require.NoError(t, err)

	require.NoError(t, s.UpdateLastSeenForSnapshot(ctx, "h", 40, 1000)) // advance
	require.NoError(t, s.UpdateLastSeenForSnapshot(ctx, "h", 40, 800))  // backward: must be ignored

	got, err := s.GetProcessByPID(ctx, "h", 40, 1000)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.LastSeenNs)
	assert.Equal(t, int64(1000), *got.LastSeenNs, "a backward heartbeat must not regress last_seen_ns")

	require.NoError(t, s.UpdateLastSeenForSnapshot(ctx, "h", 40, 1500)) // forward: advances
	got, err = s.GetProcessByPID(ctx, "h", 40, 1500)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.LastSeenNs)
	assert.Equal(t, int64(1500), *got.LastSeenNs)
}

// TestStore_ReExec_StampsEventIDs pins that a re-exec generation carries the exec event as both its source and exec event id, so a
// replayed re-exec is recognized rather than fabricating another generation.
func TestStore_ReExec_StampsEventIDs(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	priorID, err := s.InsertProcess(ctx, api.Process{
		HostID: "h", PID: 50, ForkTimeNs: 10, ExecTimeNs: new(int64(11)), SourceEventID: new("fork-50"), ExecEventID: new("exec-50a"),
	})
	require.NoError(t, err)

	newID, reLinked, err := s.ReExec(ctx, priorID, 20, 21, api.Process{
		HostID: "h", PID: 50, ForkTimeNs: 10, ExecTimeNs: new(int64(20)),
		SourceEventID: new("exec-50b"), ExecEventID: new("exec-50b"),
	})
	require.NoError(t, err)
	assert.True(t, reLinked, "the live prior generation is chained")

	got, err := s.GetProcessByPID(ctx, "h", 50, 20)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, newID, got.ID)
	require.NotNil(t, got.SourceEventID)
	assert.Equal(t, "exec-50b", *got.SourceEventID)
	require.NotNil(t, got.PreviousExecID)
	assert.Equal(t, priorID, *got.PreviousExecID)

	applied, err := s.EventAlreadyApplied(ctx, "h", 50, "exec-50b")
	require.NoError(t, err)
	assert.True(t, applied)
}
