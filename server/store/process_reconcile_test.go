package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconcileStaleProcesses_ForcesExitOnAgedRunningRow(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	// Anchor the clock at a known wall-clock moment so the test is deterministic.
	now := time.Date(2026, 4, 23, 20, 0, 0, 0, time.UTC)
	nowNs := now.UnixNano()

	// One process that forked 7 hours ago and never exited (stale).
	const staleHost = "host-stale"
	staleForkNs := nowNs - int64(7*time.Hour)
	staleIng := staleForkNs
	staleID, err := s.InsertProcess(ctx, Process{
		HostID: staleHost, PID: 100, PPID: 1, Path: "/bin/stale",
		ForkTimeNs: staleForkNs, ForkIngestedAtNs: &staleIng,
	})
	require.NoError(t, err)

	// One process that forked 1 hour ago — fresh; must not be reconciled.
	const freshHost = "host-fresh"
	freshForkNs := nowNs - int64(1*time.Hour)
	freshIng := freshForkNs
	freshID, err := s.InsertProcess(ctx, Process{
		HostID: freshHost, PID: 200, PPID: 1, Path: "/bin/fresh",
		ForkTimeNs: freshForkNs, ForkIngestedAtNs: &freshIng,
	})
	require.NoError(t, err)

	// One process that already exited cleanly via an observed exit event.
	const cleanHost = "host-clean"
	cleanForkNs := nowNs - int64(8*time.Hour)
	cleanID, err := s.InsertProcess(ctx, Process{
		HostID: cleanHost, PID: 300, PPID: 1, Path: "/bin/clean",
		ForkTimeNs: cleanForkNs,
	})
	require.NoError(t, err)
	require.NoError(t, s.UpdateProcessExit(ctx, cleanHost, 300, cleanForkNs+1000, cleanForkNs+2000, 0))

	maxAge := int64(6 * time.Hour)
	cutoff := nowNs - maxAge

	n, err := s.ReconcileStaleProcesses(ctx, cutoff, maxAge)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "exactly the stale row must be reconciled")

	// Query at a point within the reconciled lifetime (just after fork) so
	// the "alive at atTimeNs" predicate returns the row.
	stale, err := s.GetProcessByPID(ctx, staleHost, 100, staleForkNs+1)
	require.NoError(t, err)
	require.NotNil(t, stale)
	require.NotNil(t, stale.ExitTimeNs, "TTL reconciliation must set exit_time_ns")
	require.NotNil(t, stale.ExitReason)
	assert.Equal(t, ExitReasonTTLReconciliation, *stale.ExitReason)
	// exit_time_ns = fork_time_ns + maxAgeNs — keeps tree-range ordering sensible.
	assert.Equal(t, staleForkNs+maxAge, *stale.ExitTimeNs)

	fresh, err := s.GetProcessByPID(ctx, freshHost, 200, nowNs)
	require.NoError(t, err)
	require.NotNil(t, fresh)
	assert.Nil(t, fresh.ExitTimeNs, "fresh row must not be reconciled")
	assert.Nil(t, fresh.ExitReason)

	// Clean row: query within its lifetime (fork < atTime < exit). Exit was
	// set to cleanForkNs+1000, so atTime=cleanForkNs+500 is inside the window.
	clean, err := s.GetProcessByPID(ctx, cleanHost, 300, cleanForkNs+500)
	require.NoError(t, err)
	require.NotNil(t, clean)
	require.NotNil(t, clean.ExitReason, "observed exits get exit_reason=event")
	assert.Equal(t, ExitReasonEvent, *clean.ExitReason)

	// Sanity: unique IDs assigned.
	assert.NotEqual(t, staleID, freshID)
	assert.NotEqual(t, staleID, cleanID)
}

func TestReconcileStaleProcesses_Idempotent(t *testing.T) {
	s := OpenTestStore(t)
	ctx := t.Context()

	nowNs := time.Now().UnixNano()
	forkNs := nowNs - int64(10*time.Hour)
	ing := forkNs
	_, err := s.InsertProcess(ctx, Process{
		HostID: "idem-host", PID: 77, PPID: 1, Path: "/bin/idem",
		ForkTimeNs: forkNs, ForkIngestedAtNs: &ing,
	})
	require.NoError(t, err)

	maxAge := int64(6 * time.Hour)
	cutoff := nowNs - maxAge

	first, err := s.ReconcileStaleProcesses(ctx, cutoff, maxAge)
	require.NoError(t, err)
	assert.Equal(t, int64(1), first)

	second, err := s.ReconcileStaleProcesses(ctx, cutoff, maxAge)
	require.NoError(t, err)
	assert.Equal(t, int64(0), second, "already-exited rows must not be re-reconciled")
}
