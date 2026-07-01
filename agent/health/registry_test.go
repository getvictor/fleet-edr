package health

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedClock(v int64) func() int64 { return func() int64 { return v } }

// seqClock returns start, start+1, start+2, ... on successive calls, so a test can pin exactly when a transition stamp was taken.
func seqClock(start int64) func() int64 {
	n := start - 1
	return func() int64 { n++; return n }
}

func TestNewRegistry_WallClockSeedsAndTransitions(t *testing.T) {
	t.Parallel()
	r := NewRegistry() // exercises the wall-clock constructor
	r.Register(ComponentNetworkExtension, "Network extension")
	seed := r.Snapshot()[0]
	assert.Equal(t, StatusUnhealthy, seed.Status)
	assert.Positive(t, seed.LastTransitionNs, "the seed stamp uses the wall clock")

	r.MarkConnected(ComponentNetworkExtension)
	assert.Equal(t, StatusHealthy, r.Snapshot()[0].Status)
}

// spec:agent-status-reporting/the-agent-distinguishes-never-connected-from-connection-lost-per-extension/a-fresh-install-with-an-unactivated-extension-reports-never-connected
func TestRegistry_SeedsNeverConnected(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(100))
	r.Register(ComponentEndpointSecurityExtension, "Security extension")

	snap := r.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, Component{
		Type:             ComponentEndpointSecurityExtension,
		Status:           StatusUnhealthy,
		Reason:           reasonNeverConnected,
		Message:          "Security extension not activated",
		LastTransitionNs: 100,
	}, snap[0])
}

// spec:agent-status-reporting/the-agent-maintains-a-per-component-health-registry/a-connected-extension-is-healthy
// spec:agent-status-reporting/the-agent-distinguishes-never-connected-from-connection-lost-per-extension/a-dropped-session-reports-connection-lost
func TestRegistry_MarkConnectedThenLost(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(1000))
	r.Register(ComponentNetworkExtension, "Network extension") // stamp 1000

	r.MarkConnected(ComponentNetworkExtension) // stamp 1001
	got := r.Snapshot()[0]
	assert.Equal(t, StatusHealthy, got.Status)
	assert.Equal(t, reasonActivated, got.Reason)
	assert.Equal(t, "Network extension connected", got.Message)
	assert.EqualValues(t, 1001, got.LastTransitionNs)

	r.MarkDisconnected(ComponentNetworkExtension) // stamp 1002
	got = r.Snapshot()[0]
	assert.Equal(t, StatusUnhealthy, got.Status)
	assert.Equal(t, reasonConnectionLost, got.Reason, "a drop after a connect is connection_lost, not never_connected")
	assert.EqualValues(t, 1002, got.LastTransitionNs)
}

func TestRegistry_DisconnectBeforeConnectStaysNeverConnected(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(500))
	r.Register(ComponentEndpointSecurityExtension, "Security extension") // stamp 500, status unhealthy/never_connected

	// A connect-failure path may MarkDisconnected before any session ever succeeds. Status stays unhealthy/never_connected, so the
	// transition stamp must NOT advance (no status change) and nothing should pulse.
	r.MarkDisconnected(ComponentEndpointSecurityExtension)
	got := r.Snapshot()[0]
	assert.Equal(t, reasonNeverConnected, got.Reason)
	assert.EqualValues(t, 500, got.LastTransitionNs, "an unchanged status must not re-stamp the transition time")
	assert.Empty(t, drainChanged(r), "no transition means no Changed pulse")
}

// spec:agent-status-reporting/the-agent-maintains-a-per-component-health-registry/the-last-transition-timestamp-is-stable-across-unchanged-reads
func TestRegistry_StampStableAcrossUnchangedConnect(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(1))
	r.Register(ComponentNetworkExtension, "Network extension") // stamp 1
	r.MarkConnected(ComponentNetworkExtension)                 // stamp 2 (unhealthy -> healthy)
	first := r.Snapshot()[0].LastTransitionNs
	r.MarkConnected(ComponentNetworkExtension) // already healthy: no change
	assert.Equal(t, first, r.Snapshot()[0].LastTransitionNs, "re-connecting an already-healthy component must not re-stamp")
}

func TestRegistry_ChangedPulsesOnceThenCoalesces(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(1))
	r.Register(ComponentNetworkExtension, "Network extension")

	r.MarkConnected(ComponentNetworkExtension)    // transition -> pulse
	r.MarkDisconnected(ComponentNetworkExtension) // transition -> pulse (coalesced into the buffered slot)
	// Buffered capacity-1 channel: the two transitions collapse to a single pending wake-up.
	assert.Len(t, drainChanged(r), 1)
}

func TestRegistry_SnapshotOrderIsRegistrationOrder(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(1))
	r.Register(ComponentEndpointSecurityExtension, "Security extension")
	r.Register(ComponentNetworkExtension, "Network extension")
	snap := r.Snapshot()
	require.Len(t, snap, 2)
	assert.Equal(t, ComponentEndpointSecurityExtension, snap[0].Type)
	assert.Equal(t, ComponentNetworkExtension, snap[1].Type)
}

func TestRegistry_UnknownComponentIsNoOp(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(1))
	r.Register(ComponentNetworkExtension, "Network extension")
	r.MarkConnected("not_registered")
	r.MarkDisconnected("not_registered")
	assert.Len(t, r.Snapshot(), 1, "operations on an unregistered component must not add or panic")
}

func TestRegistry_RegisterTwiceIsNoOp(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(1))
	r.Register(ComponentNetworkExtension, "Network extension")
	r.MarkConnected(ComponentNetworkExtension)
	r.Register(ComponentNetworkExtension, "Network extension AGAIN") // must not reset the live state
	got := r.Snapshot()
	require.Len(t, got, 1)
	assert.Equal(t, StatusHealthy, got[0].Status, "re-registering must not clobber the current condition")
}

// drainChanged non-blockingly collects all currently-pending Changed pulses.
func drainChanged(r *Registry) []struct{} {
	var out []struct{}
	for {
		select {
		case v := <-r.Changed():
			out = append(out, v)
		default:
			return out
		}
	}
}
