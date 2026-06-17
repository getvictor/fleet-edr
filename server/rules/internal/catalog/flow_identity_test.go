package catalog

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/rules/api"
)

// recordingGraphReader is a GraphReader fake that returns configured processes for the identity and window lookups and records
// which were called, so resolveFlowProcess's precedence can be asserted without a database.
type recordingGraphReader struct {
	byPIDVersion    *api.Process // returned by GetProcessByPIDVersion
	byPID           *api.Process // returned by GetProcessByPID
	calledByVersion bool
	calledByPID     bool
}

func (r *recordingGraphReader) GetProcessByPID(_ context.Context, _ string, _ int, _ int64) (*api.Process, error) {
	r.calledByPID = true
	return r.byPID, nil
}

func (r *recordingGraphReader) GetProcessByPIDVersion(_ context.Context, _ string, _ int, _ uint32) (*api.Process, error) {
	r.calledByVersion = true
	return r.byPIDVersion, nil
}

func (r *recordingGraphReader) GetChildProcesses(_ context.Context, _ string, _ int, _ api.TimeRange) ([]api.Process, error) {
	return nil, nil
}

func (r *recordingGraphReader) GetExecChain(_ context.Context, current api.Process) ([]api.Process, error) {
	return []api.Process{current}, nil
}

func (r *recordingGraphReader) GetNetworkEventsForProcess(_ context.Context, _ string, _ int, _ api.TimeRange) ([]api.Event, error) {
	return nil, nil
}

// TestNetworkConnectPayload_PIDVersionRoundTrip is the wire-field round-trip for the optional pidversion added to
// network_connect (issue #403): Unmarshal(Marshal(p)) == p across present and absent values, and an absent JSON key decodes
// to nil (the "no identity, use the window" signal) rather than 0.
func TestNetworkConnectPayload_PIDVersionRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("absent key decodes to nil, not zero", func(t *testing.T) {
		t.Parallel()
		var got networkConnectPayload
		require.NoError(t, json.Unmarshal([]byte(`{"pid":1,"direction":"outbound","remote_address":"1.1.1.1","remote_port":443}`), &got))
		assert.Nil(t, got.PIDVersion, "missing pidversion must decode to nil so correlation uses the window")
	})

	t.Run("present zero is preserved as a valid identity", func(t *testing.T) {
		t.Parallel()
		var got networkConnectPayload
		require.NoError(t, json.Unmarshal([]byte(`{"pid":1,"direction":"outbound","remote_address":"1.1.1.1","remote_port":443,"pidversion":0}`), &got))
		require.NotNil(t, got.PIDVersion)
		assert.Equal(t, uint32(0), *got.PIDVersion, "a present 0 is a legitimate generation, distinct from absent")
	})

	rapid.Check(t, func(rt *rapid.T) {
		in := networkConnectPayload{
			PID:           rapid.IntRange(1, 1<<20).Draw(rt, "pid"),
			Direction:     rapid.SampledFrom([]string{"outbound", "inbound"}).Draw(rt, "dir"),
			RemoteAddress: rapid.StringMatching(`[0-9]{1,3}(\.[0-9]{1,3}){3}`).Draw(rt, "addr"),
			RemotePort:    rapid.IntRange(0, 65535).Draw(rt, "port"),
		}
		if rapid.Bool().Draw(rt, "has_pidversion") {
			in.PIDVersion = new(rapid.Uint32().Draw(rt, "pidversion"))
		}
		b, err := json.Marshal(in)
		require.NoError(rt, err)
		var out networkConnectPayload
		require.NoError(rt, json.Unmarshal(b, &out))
		assert.Equal(rt, in, out)
	})
}

// TestResolveFlowProcess pins the identity-preferred-with-window-fallback contract that backs the server-process-graph-builder
// "Network and DNS events are linked to the process at event time" requirement (issue #403). The exact-identity lookup wins when
// the flow carries a pidversion and a generation matches; otherwise correlation falls back to the event-time window unchanged.
func TestResolveFlowProcess(t *testing.T) {
	t.Parallel()
	const (
		host = "H1"
		pid  = 4200
		atNs = 1_000
	)
	identityProc := &api.Process{ID: 11, PID: pid, PIDVersion: new(uint32(7))}
	windowProc := &api.Process{ID: 22, PID: pid}

	t.Run("spec:server-process-graph-builder/network-and-dns-events-are-linked-to-the-process-at-event-time/a-flow-with-pidversion-correlates-to-the-exact-generation-across-pid-reuse", func(t *testing.T) {
		t.Parallel()
		// pidversion present AND a generation matches: identity wins, the window lookup is never consulted.
		gr := &recordingGraphReader{byPIDVersion: identityProc, byPID: windowProc}
		got, err := resolveFlowProcess(context.Background(), gr, host, pid, new(uint32(7)), atNs)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(11), got.ID, "expected the identity-matched generation")
		assert.True(t, gr.calledByVersion, "identity lookup must be attempted when pidversion is present")
		assert.False(t, gr.calledByPID, "window lookup must not run on an identity hit")
	})

	t.Run("identity miss with pidversion falls back to the window", func(t *testing.T) {
		t.Parallel()
		// pidversion present but no generation matches yet (the exec/fork has not materialised): fall back to the window.
		gr := &recordingGraphReader{byPIDVersion: nil, byPID: windowProc}
		got, err := resolveFlowProcess(context.Background(), gr, host, pid, new(uint32(7)), atNs)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(22), got.ID, "expected the window-matched generation on identity miss")
		assert.True(t, gr.calledByVersion)
		assert.True(t, gr.calledByPID, "window lookup must run when identity misses")
	})

	t.Run("spec:server-process-graph-builder/network-and-dns-events-are-linked-to-the-process-at-event-time/a-flow-without-pidversion-falls-back-to-the-event-time-window", func(t *testing.T) {
		t.Parallel()
		// No pidversion on the flow (legacy agent / unavailable token): identity lookup is skipped entirely.
		gr := &recordingGraphReader{byPIDVersion: identityProc, byPID: windowProc}
		got, err := resolveFlowProcess(context.Background(), gr, host, pid, nil, atNs)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(22), got.ID, "expected the window-matched generation when no pidversion is carried")
		assert.False(t, gr.calledByVersion, "identity lookup must be skipped when pidversion is absent")
		assert.True(t, gr.calledByPID)
	})
}
