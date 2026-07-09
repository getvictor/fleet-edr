package commander

import (
	"encoding/json"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/agent/procgen"
)

// TestRunKill_GenerationGate covers the kill_process generation pin (issue #627): a known mismatch is refused with no signal, while a
// match, an untracked pid, and a payload with no pidversion all fall through to the pid-only kill.
func TestRunKill_GenerationGate(t *testing.T) {
	t.Parallel()
	const pid = 4321
	cases := []struct {
		name       string
		observe    [][]byte // events fed to the registry before the kill
		payload    string   // kill_process payload JSON
		wantStatus string
		wantKilled bool
		wantReason string // substring expected in the result on refusal ("" = none)
	}{
		{
			// spec:agent-command-executor/process-termination-command/kill-proceeds-when-the-selected-generation-still-matches
			name:       "matching generation kills",
			observe:    [][]byte{execBytes(pid, 7)},
			payload:    `{"pid":4321,"pidversion":7}`,
			wantStatus: StatusCompleted,
			wantKilled: true,
		},
		{
			// spec:agent-command-executor/process-termination-command/kill-is-refused-when-the-target-generation-no-longer-matches
			name:       "mismatched generation refuses and sends no signal",
			observe:    [][]byte{execBytes(pid, 8)}, // live generation is 8; the operator selected 7
			payload:    `{"pid":4321,"pidversion":7}`,
			wantStatus: StatusFailed,
			wantKilled: false,
			wantReason: "generation mismatch",
		},
		{
			// spec:agent-command-executor/process-termination-command/kill-falls-back-to-pid-only-when-the-generation-is-unsupplied-or-untracked
			name:       "untracked pid falls back to pid-only kill",
			observe:    nil, // the registry never saw this pid
			payload:    `{"pid":4321,"pidversion":7}`,
			wantStatus: StatusCompleted,
			wantKilled: true,
		},
		{
			// spec:agent-command-executor/process-termination-command/kill-falls-back-to-pid-only-when-the-generation-is-unsupplied-or-untracked
			name:       "no pidversion in payload kills by pid",
			observe:    [][]byte{execBytes(pid, 8)}, // a known-different generation is ignored when the operator sent no pidversion
			payload:    `{"pid":4321}`,
			wantStatus: StatusCompleted,
			wantKilled: true,
		},
		{
			name:       "exit evicts the pid then the kill falls back",
			observe:    [][]byte{execBytes(pid, 7), exitBytes(pid)},
			payload:    `{"pid":4321,"pidversion":7}`,
			wantStatus: StatusCompleted, // pid no longer tracked -> Unknown -> pid-only kill
			wantKilled: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := procgen.NewRegistry()
			for _, ev := range tc.observe {
				reg.ObserveEventBytes(ev)
			}
			var killed bool
			e := NewExecutor(nil, nil, nil)
			e.SetGeneration(reg)
			e.kill = func(int, syscall.Signal) error { killed = true; return nil }
			status, result := e.run(t.Context(), Command{ID: 1, CommandType: "kill_process", Payload: json.RawMessage(tc.payload)})
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantKilled, killed, "kill invoked?")
			if tc.wantReason != "" {
				assert.Contains(t, string(result), tc.wantReason)
			}
		})
	}
}

// TestRunKill_NilRegistryFallsBack pins that a nil registry (the default, e.g. a degraded path or tests that never call SetGeneration)
// never refuses: the kill falls back to pid-only regardless of a supplied pidversion.
func TestRunKill_NilRegistryFallsBack(t *testing.T) {
	t.Parallel()
	var killed bool
	e := NewExecutor(nil, nil, nil) // no SetGeneration -> gen is nil
	e.kill = func(int, syscall.Signal) error { killed = true; return nil }
	status, _ := e.run(t.Context(), Command{ID: 1, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":10,"pidversion":3}`)})
	assert.Equal(t, StatusCompleted, status)
	assert.True(t, killed)
}

// TestKillPayload_JSONRoundTrip is the property-based Marshal-then-Unmarshal identity check the repo requires for a new wire-format field
// (issue #627 added the optional pidversion to the kill_process payload). It pins the json tags and the *uint32 pointer semantics
// (omitempty drops an absent generation; a present one round-trips by value) so a future encoding change cannot silently break
// compatibility across the UI / server / agent boundary.
func TestKillPayload_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := killPayload{PID: rapid.Int().Draw(t, "pid")}
		if rapid.Bool().Draw(t, "hasPidversion") {
			v := rapid.Uint32().Draw(t, "pidversion")
			want.PIDVersion = &v
		}
		b, err := json.Marshal(want)
		require.NoError(t, err)
		var got killPayload
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, want, got)
	})
}

// exitBytes / execBytes here mirror the procgen test builders so the executor test drives the same ObserveEventBytes path. json.Marshal
// of these fixed maps cannot fail, so the error is ignored.
func execBytes(pid int, pidversion uint32) []byte {
	b, _ := json.Marshal(map[string]any{"event_type": "exec", "payload": map[string]any{"pid": pid, "pidversion": pidversion}})
	return b
}

func exitBytes(pid int) []byte {
	b, _ := json.Marshal(map[string]any{"event_type": "exit", "payload": map[string]any{"pid": pid, "exit_code": 0}})
	return b
}
