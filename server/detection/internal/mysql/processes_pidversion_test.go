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
		// Identity pins each generation exactly, with no time anchor: v7 -> the exited gen1, v8 -> the alive gen2.
		g1, err := s.GetProcessByPIDVersion(ctx, host, pid, 7)
		require.NoError(t, err)
		require.NotNil(t, g1)
		assert.Equal(t, gen1, g1.ID, "pidversion 7 must resolve to gen1")
		require.NotNil(t, g1.PIDVersion)
		assert.Equal(t, uint32(7), *g1.PIDVersion)

		g2, err := s.GetProcessByPIDVersion(ctx, host, pid, 8)
		require.NoError(t, err)
		require.NotNil(t, g2)
		assert.Equal(t, gen2, g2.ID, "pidversion 8 must resolve to gen2 even though gen1 shares the pid")
	})

	t.Run("no matching pidversion returns nil", func(t *testing.T) {
		got, err := s.GetProcessByPIDVersion(ctx, host, pid, 999)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("legacy NULL-pidversion row never matches identity but is reachable by window", func(t *testing.T) {
		// A present 0 must not collide with a NULL row.
		got, err := s.GetProcessByPIDVersion(ctx, host, legacyPID, 0)
		require.NoError(t, err)
		assert.Nil(t, got, "a NULL pidversion must not match an identity lookup, including for pidversion 0")

		// The legacy row still resolves through the event-time window path (the fallback correlation uses this).
		win, err := s.GetProcessByPID(ctx, host, legacyPID, 150)
		require.NoError(t, err)
		require.NotNil(t, win)
		assert.Equal(t, legacy, win.ID)
		assert.Nil(t, win.PIDVersion, "legacy row stores NULL pidversion")
	})

	t.Run("re-exec chain sharing one pidversion resolves to the current generation", func(t *testing.T) {
		// A same-PID re-exec chain shares one pidversion across generations. The lookup returns the current generation: the
		// live row (exit_time_ns NULL), else the most recently inserted.
		const chainPID = 6000
		chainExit := int64(500)
		_, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: chainPID, Path: "/old", PIDVersion: new(uint32(42)), ForkTimeNs: 400, ExitTimeNs: &chainExit})
		require.NoError(t, err)
		alive, err := s.InsertProcess(ctx, api.Process{HostID: host, PID: chainPID, Path: "/current", PIDVersion: new(uint32(42)), ForkTimeNs: 400})
		require.NoError(t, err)

		got, err := s.GetProcessByPIDVersion(ctx, host, chainPID, 42)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, alive, got.ID, "the live generation of the chain must win")
		assert.Equal(t, "/current", got.Path)
	})
}
