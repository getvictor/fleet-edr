package mysql_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestCloseStaleProcess_LeavesLaterGenerationOpen is the named repro for the process-graph half of issue #661.
//
// PID reuse closes a prior generation when a fork takes over its pid, but only a generation that started BEFORE that fork can be the
// one being displaced. When concurrently processed claim batches (issue #535) split a fork/exec pair and deliver the exec's batch
// first, the exec synthesizes its record stamped at the exec time and the fork then arrives with an EARLIER timestamp. Closing that
// record at the fork's timestamp gave it an exit_time_ns before its own fork_time_ns, an impossible lifetime that every point-in-time
// lookup skips: GetProcessByPID's `exit_time_ns IS NULL OR exit_time_ns >= atNs` bound excluded the correctly exec-imaged record and
// returned the bare fork record instead, whose path is only the parent's inherited image. dns_c2_beacon gates on proc.Path, so it
// declined the process and silently dropped a Critical beacon alert with no retry.
//
// spec:server-process-graph-builder/pid-reuse-creates-a-new-generation/a-fork-arrives-after-the-exec-synthesized-record-for-the-same-pid
func TestCloseStaleProcess_LeavesLaterGenerationOpen(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	const host = "h-661"
	const pid = 5107200
	// The scenario's shape: fork at T, exec at T+10ms, connect at T+40ms. The exec's batch landed first, so its record is stamped at
	// the exec time and the fork arrives "earlier".
	const forkNs = int64(1_000_000_000)
	const execNs = forkNs + 10_000_000
	const connectNs = forkNs + 40_000_000

	execTime := execNs
	execRow, err := s.InsertProcess(ctx, api.Process{
		HostID: host, PID: pid, Path: "/tmp/.update", ForkTimeNs: execNs, ExecTimeNs: &execTime,
	})
	require.NoError(t, err)

	// The late fork closes stale generations for this pid.
	require.NoError(t, s.CloseStaleProcess(ctx, host, pid, forkNs))

	got, err := s.GetProcessByPID(ctx, host, pid, connectNs)
	require.NoError(t, err)
	require.NotNil(t, got, "the exec-imaged record must stay resolvable at the connect's timestamp")
	assert.Equal(t, execRow, got.ID, "the exec-synthesized record must not be closed by a fork that predates it")
	assert.Equal(t, "/tmp/.update", got.Path,
		"resolving the bare-fork record instead is what silently dropped the dns_c2_beacon alert (issue #661)")
	assert.Nil(t, got.ExitTimeNs, "a fork earlier than this generation's own fork must not close it")

	// The invariant, stated directly: no record may exit before it forked.
	var impossible int
	require.NoError(t, s.DB().GetContext(ctx, &impossible,
		`SELECT COUNT(*) FROM processes WHERE exit_time_ns IS NOT NULL AND exit_time_ns < fork_time_ns`))
	assert.Zero(t, impossible, "no process record may carry an exit_time_ns earlier than its own fork_time_ns")
}

// TestCloseStaleProcess_ClosesEarlierGeneration keeps the actual PID-reuse path honest: a generation that really did start before the
// incoming fork is still closed at the fork's timestamp.
// spec:server-process-graph-builder/pid-reuse-creates-a-new-generation/a-new-fork-lands-on-a-stale-pid
func TestCloseStaleProcess_ClosesEarlierGeneration(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	const host = "h-reuse"
	const pid = 4242
	const oldForkNs = int64(1_000_000_000)
	const newForkNs = oldForkNs + 5_000_000_000

	oldRow, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: pid, Path: "/old", ForkTimeNs: oldForkNs})
	require.NoError(t, err)

	require.NoError(t, s.CloseStaleProcess(ctx, host, pid, newForkNs))

	got, err := s.GetProcessByPID(ctx, host, pid, oldForkNs+1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, oldRow, got.ID)
	require.NotNil(t, got.ExitTimeNs, "a genuinely stale generation is still closed by the reusing fork")
	assert.Equal(t, newForkNs, *got.ExitTimeNs)
	require.NotNil(t, got.ExitReason)
	assert.Equal(t, api.ExitReasonPIDReuse, *got.ExitReason)
}
