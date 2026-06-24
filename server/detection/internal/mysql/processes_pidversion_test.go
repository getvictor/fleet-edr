package mysql_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestGetProcessByPIDVersion exercises the exact-identity process lookup that backs flow-to-process correlation (issue #403):
// a process record persists its kernel PID generation, and a flow tagged with (host, pid, pidversion) resolves to the exact
// generation regardless of fork/exit timing, immune to PID reuse. NULL-pidversion rows (legacy agents) never match the identity
// lookup and remain reachable via the event-time window path.
//
// spec:server-process-graph-builder/process-records-carry-the-kernel-pid-generation/an-exec-event-carrying-pidversion-stores-it-on-the-record
// spec:server-process-graph-builder/process-records-carry-the-kernel-pid-generation/an-exec-event-without-pidversion-still-materializes-a-record
func TestGetProcessByPIDVersion(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	const host = "h"
	const pid = 4200

	// Two lifetimes of the SAME pid with distinct pidversions: gen1 exited at 200, gen2 forked at 300 and is still alive. PID reuse
	// recycles the pid; the kernel hands the second lifetime a higher generation.
	exit := int64(200)
	gen1, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: pid, Path: "/gen1", PIDVersion: new(uint32(7)), ForkTimeNs: 100, ExitTimeNs: &exit})
	require.NoError(t, err)
	gen2, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: pid, Path: "/gen2", PIDVersion: new(uint32(8)), ForkTimeNs: 300})
	require.NoError(t, err)

	// A legacy row carrying no pidversion (older agent, or unavailable token).
	legacyPID := 5000
	legacy, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: legacyPID, Path: "/legacy", ForkTimeNs: 100})
	require.NoError(t, err)

	t.Run("spec:server-process-graph-builder/network-and-dns-events-are-linked-to-the-process-at-event-time/a-flow-with-pidversion-correlates-to-the-exact-generation-across-pid-reuse", func(t *testing.T) {
		t.Parallel()
		// Distinct pidversions mean each identity matches a single generation, so the event time must not change the result: v7
		// resolves to the exited gen1 even at a time long after it exited, and v8 resolves to the alive gen2 even at a time that
		// falls inside gen1's window (identity beats clock skew).
		g1, err := s.GetProcessByPIDVersion(ctx, host, pid, 7, 100_000)
		require.NoError(t, err)
		require.NotNil(t, g1)
		assert.Equal(t, gen1, g1.ID, "pidversion 7 must resolve to gen1 regardless of the event time")
		require.NotNil(t, g1.PIDVersion)
		assert.Equal(t, uint32(7), *g1.PIDVersion)

		g2, err := s.GetProcessByPIDVersion(ctx, host, pid, 8, 150)
		require.NoError(t, err)
		require.NotNil(t, g2)
		assert.Equal(t, gen2, g2.ID, "pidversion 8 must resolve to gen2 even at a time inside gen1's window: identity beats timestamp")
	})

	t.Run("no matching pidversion returns nil", func(t *testing.T) {
		t.Parallel()
		got, err := s.GetProcessByPIDVersion(ctx, host, pid, 999, 150)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("legacy NULL-pidversion row never matches identity but is reachable by window", func(t *testing.T) {
		t.Parallel()
		// A present 0 must not collide with a NULL row.
		got, err := s.GetProcessByPIDVersion(ctx, host, legacyPID, 0, 150)
		require.NoError(t, err)
		assert.Nil(t, got, "a NULL pidversion must not match an identity lookup, including for pidversion 0")

		// The legacy row still resolves through the event-time window path (the fallback correlation uses this).
		win, err := s.GetProcessByPID(ctx, host, legacyPID, 150)
		require.NoError(t, err)
		require.NotNil(t, win)
		assert.Equal(t, legacy, win.ID)
		assert.Nil(t, win.PIDVersion, "legacy row stores NULL pidversion")
	})

	t.Run("spec:server-process-graph-builder/network-and-dns-events-are-linked-to-the-process-at-event-time/a-flow-within-a-re-exec-chain-links-to-the-generation-running-at-the-event-time", func(t *testing.T) {
		t.Parallel()
		// A same-PID re-exec chain shares one pidversion across generations (execve keeps the kernel generation), so the identity
		// matches more than one row. The chain preserves the original fork_time_ns on every generation and records the
		// image-replacement instant in exec_time_ns, so exec_time_ns is the boundary that orders them. The earlier image ran
		// [400, 500); the current image execs at 500 and is still alive. A flow's event time must pick the generation that was the
		// running image then, NOT the live/newest one.
		const chainPID = 6000
		execOld := int64(400)
		reExec := int64(500)
		oldGen, err := s.InsertProcess(ctx, api.Process{
			HostID: host, PID: chainPID, Path: "/old", PIDVersion: new(uint32(42)),
			ForkTimeNs: 400, ExecTimeNs: &execOld, ExitTimeNs: &reExec,
		})
		require.NoError(t, err)
		currentGen, err := s.InsertProcess(ctx, api.Process{
			HostID: host, PID: chainPID, Path: "/current", PIDVersion: new(uint32(42)),
			ForkTimeNs: 400, ExecTimeNs: &reExec, // chain preserves fork_time_ns; exec_time_ns is the re-exec instant
		})
		require.NoError(t, err)

		// A flow during the earlier image's window resolves to that generation, even though a later/live generation shares the pid
		// and pidversion. This is the regression the pre-fix lookup had: it returned the live/newest row by id.
		duringOld, err := s.GetProcessByPIDVersion(ctx, host, chainPID, 42, 450)
		require.NoError(t, err)
		require.NotNil(t, duringOld)
		assert.Equal(t, oldGen, duringOld.ID, "a flow at 450 ran during the earlier image; it must link to that generation")
		assert.Equal(t, "/old", duringOld.Path)

		// A flow after the re-exec resolves to the current image.
		duringCurrent, err := s.GetProcessByPIDVersion(ctx, host, chainPID, 42, 600)
		require.NoError(t, err)
		require.NotNil(t, duringCurrent)
		assert.Equal(t, currentGen, duringCurrent.ID, "a flow at 600 ran during the current image")
		assert.Equal(t, "/current", duringCurrent.Path)
	})
}
