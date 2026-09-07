package mysql_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

// spec:server-process-graph-builder/a-process-lookup-at-an-instant-returns-the-image-that-was-running-then/a-parent-that-re-executed-after-the-fork-still-reports-the-forking-image
// spec:server-process-graph-builder/a-process-lookup-at-an-instant-returns-the-image-that-was-running-then/the-adopted-image-is-returned-once-it-is-running
// spec:server-process-graph-builder/a-process-lookup-at-an-instant-returns-the-image-that-was-running-then/a-generation-that-has-not-executed-is-still-resolvable
//
// TestGetProcessByPID_ReturnsTheImageRunningAtTheInstantAsked is issue #799's reproducer, and it is the ordering the existing
// tests never produce: a parent forks a child, then re-executes into a different binary BEFORE the batch is evaluated.
//
// A re-exec preserves the original fork time on every generation of a pid, so both rows satisfied `fork_time_ns <= atTimeNs` and
// `id DESC` handed back whichever was written last. A rule asking what the parent's image was when it forked the child was
// therefore told about a binary that had not run yet.
//
// This is the lookup every parent-image and attribution question goes through, including the eleven corpus rules that read
// ParentImage, so the wrong answer cost both correct attribution and the detection itself: a malicious parent that re-executed
// into something benign before evaluation read as benign.
func TestGetProcessByPID_ReturnsTheImageRunningAtTheInstantAsked(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	const host = "h"
	const pid = 7100

	// One pid, two generations sharing a fork time, which is what a re-exec produces. The first ran /bin/attacker from T1; at T2
	// it replaced its image with /bin/benign. Inserted in chain order so the LATER generation has the higher row id, which is the
	// ordering that produced the wrong answer.
	forkedAt, reExecedAt := int64(1000), int64(2000)
	firstExec, secondExec := forkedAt, reExecedAt
	attacker, err := s.InsertProcess(ctx, api.Process{
		HostID: host, PID: pid, Path: "/bin/attacker", ForkTimeNs: forkedAt, ExecTimeNs: &firstExec,
	})
	require.NoError(t, err)
	benign, err := s.InsertProcess(ctx, api.Process{
		HostID: host, PID: pid, Path: "/bin/benign", ForkTimeNs: forkedAt, ExecTimeNs: &secondExec,
	})
	require.NoError(t, err)
	require.Greater(t, benign, attacker, "the re-exec must be the newer row, or this does not reproduce the bug")

	t.Run("at the instant the child was forked, the forking image is returned", func(t *testing.T) {
		t.Parallel()
		got, err := s.GetProcessByPID(ctx, host, pid, forkedAt)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "/bin/attacker", got.Path,
			"the image running at the fork instant, not the one the process adopted 1us later")
		assert.Equal(t, attacker, got.ID)
	})

	t.Run("between the fork and the re-exec, still the forking image", func(t *testing.T) {
		t.Parallel()
		got, err := s.GetProcessByPID(ctx, host, pid, reExecedAt-1)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "/bin/attacker", got.Path)
	})

	t.Run("at and after the re-exec, the adopted image", func(t *testing.T) {
		t.Parallel()
		for _, at := range []int64{reExecedAt, reExecedAt + 1, reExecedAt + 1_000_000} {
			got, err := s.GetProcessByPID(ctx, host, pid, at)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "/bin/benign", got.Path, "at %d the re-executed image is the running one", at)
		}
	})

	t.Run("before the process existed at all, nothing", func(t *testing.T) {
		t.Parallel()
		got, err := s.GetProcessByPID(ctx, host, pid, forkedAt-1)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("a process is still found between its fork and its FIRST exec", func(t *testing.T) {
		t.Parallel()
		// The regression review caught in the first version of this fix. A first exec updates the fork row in place, so between
		// the fork and that exec there is ONE row whose image start lies in the future. Filtering on the image start excluded it,
		// and the callers this change exists to fix ask at a CHILD's fork time, which can fall in exactly that window: a parent
		// that forked a child before executing anything itself came back as having no record at all.
		const window = 7300
		execAt := int64(2000)
		id, err := s.InsertProcess(ctx, api.Process{
			HostID: host, PID: window, Path: "/bin/preexec", ForkTimeNs: 1000, ExecTimeNs: &execAt,
		})
		require.NoError(t, err)

		got, err := s.GetProcessByPID(ctx, host, window, 1500)
		require.NoError(t, err)
		require.NotNil(t, got, "a process that exists at the instant asked about must be found, image started or not")
		assert.Equal(t, id, got.ID)
	})

	t.Run("a generation that never executed is found by its fork time", func(t *testing.T) {
		t.Parallel()
		// COALESCE falls back to fork_time_ns, which is a pure-fork row's only start instant. Without that fallback this row
		// would be invisible to every lookup.
		const pureForkPID = 7200
		id, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: pureForkPID, Path: "/bin/forked", ForkTimeNs: 500})
		require.NoError(t, err)

		got, err := s.GetProcessByPID(ctx, host, pureForkPID, 500)
		require.NoError(t, err)
		require.NotNil(t, got, "a forked-but-not-executed generation must still be reachable")
		assert.Equal(t, id, got.ID)
	})
}
