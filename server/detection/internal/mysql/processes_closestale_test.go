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

// TestCloseStaleProcess_OrderingBoundary walks the full ordering relation between an existing generation's fork_time_ns and the
// incoming fork's timestamp. Only a generation that started strictly EARLIER is displaced, so the predicate is `<`, and the equal
// case is the one that decides `<` vs `<=`: two records stamped at the same instant are not a reuse of one another, so the existing
// one stays open. Without the equal case a `<=` regression would pass the other two.
// spec:server-process-graph-builder/pid-reuse-creates-a-new-generation/a-new-fork-lands-on-a-stale-pid
func TestCloseStaleProcess_OrderingBoundary(t *testing.T) {
	t.Parallel()

	const incomingForkNs = int64(6_000_000_000)

	cases := []struct {
		name        string
		existingNs  int64
		wantClosed  bool
		explanation string
	}{
		{
			name:        "earlier generation is displaced",
			existingNs:  incomingForkNs - 5_000_000_000,
			wantClosed:  true,
			explanation: "a genuinely stale generation is still closed by the reusing fork",
		},
		{
			name:        "generation at the same instant stays open",
			existingNs:  incomingForkNs,
			wantClosed:  false,
			explanation: "same-instant records are not a reuse of one another, so the predicate is < and not <=",
		},
		{
			name:        "later generation stays open",
			existingNs:  incomingForkNs + 10_000_000,
			wantClosed:  false,
			explanation: "a record stamped after the fork was merely processed first (issue #661)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestStore(t)
			ctx := t.Context()
			const host = "h-reuse"
			const pid = 4242

			row, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: pid, Path: "/old", ForkTimeNs: tc.existingNs})
			require.NoError(t, err)

			require.NoError(t, s.CloseStaleProcess(ctx, host, pid, incomingForkNs))

			// Read at the record's own fork time so it brackets regardless of which side of the incoming fork it sits on.
			got, err := s.GetProcessByPID(ctx, host, pid, tc.existingNs)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, row, got.ID)

			if tc.wantClosed {
				require.NotNil(t, got.ExitTimeNs, tc.explanation)
				assert.Equal(t, incomingForkNs, *got.ExitTimeNs)
				require.NotNil(t, got.ExitReason)
				assert.Equal(t, api.ExitReasonPIDReuse, *got.ExitReason)
			} else {
				assert.Nil(t, got.ExitTimeNs, tc.explanation)
			}

			// The invariant, restated per case: no record may exit before it forked.
			var impossible int
			require.NoError(t, s.DB().GetContext(ctx, &impossible,
				`SELECT COUNT(*) FROM processes WHERE exit_time_ns IS NOT NULL AND exit_time_ns < fork_time_ns`))
			assert.Zero(t, impossible, "no process record may carry an exit_time_ns earlier than its own fork_time_ns")
		})
	}
}
