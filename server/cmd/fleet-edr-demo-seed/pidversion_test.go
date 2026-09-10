package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/test/fakeagent"
)

func env(eventType string, ts int64, payload string) fakeagent.Envelope {
	return fakeagent.Envelope{EventID: eventType + "-" + payload, EventType: eventType, TimestampNs: ts, Payload: json.RawMessage(payload)}
}

// pidVersionOf reads the stamped generation back off an envelope, or reports that none was written.
func pidVersionOf(t *testing.T, e fakeagent.Envelope) (int64, bool) {
	t.Helper()
	var got struct {
		PIDVersion *int64 `json:"pidversion"`
	}
	require.NoError(t, json.Unmarshal(e.Payload, &got))
	if got.PIDVersion == nil {
		return 0, false
	}
	return *got.PIDVersion, true
}

// The counter is system-wide, not per-pid. Measured on a live macOS host running agent v0.5.0-rc.2: events 13940..13952 ran
// consecutively with no gaps across four different pids, one increment per fork and one per exec. A per-pid counter would
// hand two different processes the same generation, which is exactly the collision the (pid, pidversion) pair exists to avoid.
func TestPIDVersionStamper_CounterIsSystemWideAndMonotonic(t *testing.T) {
	t.Parallel()
	envs := []fakeagent.Envelope{
		env("fork", 10, `{"child_pid":100,"parent_pid":1}`),
		env("exec", 20, `{"pid":100,"path":"/bin/zsh"}`),
		env("fork", 30, `{"child_pid":200,"parent_pid":100}`),
		env("exec", 40, `{"pid":200,"path":"/bin/sh"}`),
	}
	require.NoError(t, newPIDVersionStamper().stamp(envs))

	got := make([]int64, 0, len(envs))
	for _, e := range envs {
		v, ok := pidVersionOf(t, e)
		require.True(t, ok, "every fork and exec mints a generation")
		got = append(got, v)
	}
	assert.Equal(t, []int64{pidVersionSeed + 1, pidVersionSeed + 2, pidVersionSeed + 3, pidVersionSeed + 4}, got,
		"consecutive across pids, one per fork and one per exec")
}

// spec:web-ui/host-event-timeline-view/timeline-scopes-to-the-alert-chain
//
// A re-exec is a new generation of the same pid, and it is the case the timeline scope has to tell apart: without the bump both
// generations answer to (pid, v) and the scope sweeps in the wrong one's events.
func TestPIDVersionStamper_ReExecBumpsTheSamePID(t *testing.T) {
	t.Parallel()
	envs := []fakeagent.Envelope{
		env("fork", 10, `{"child_pid":100,"parent_pid":1}`),
		env("exec", 20, `{"pid":100,"path":"/bin/zsh"}`),
		env("exec", 30, `{"pid":100,"path":"/usr/bin/curl"}`),
	}
	require.NoError(t, newPIDVersionStamper().stamp(envs))

	forkGen, _ := pidVersionOf(t, envs[0])
	firstExec, _ := pidVersionOf(t, envs[1])
	reExec, _ := pidVersionOf(t, envs[2])
	assert.Greater(t, firstExec, forkGen, "exec after fork is a new generation")
	assert.Greater(t, reExec, firstExec, "the second exec of the same pid bumps again")
}

func TestPIDVersionStamper_FlowsCarryTheirSourceGeneration(t *testing.T) {
	t.Parallel()
	envs := []fakeagent.Envelope{
		env("exec", 10, `{"pid":100,"path":"/usr/bin/curl"}`),
		env("network_connect", 20, `{"pid":100,"remote_address":"1.2.3.4","remote_port":443}`),
		env("dns_query", 30, `{"pid":100,"query_name":"evil.example"}`),
		// A flow whose source process the capture never started. Real agents omit the field here rather than guessing, and so
		// must this: inventing one would correlate the flow to whichever process later reuses the pid.
		env("network_connect", 40, `{"pid":999,"remote_address":"5.6.7.8","remote_port":80}`),
	}
	require.NoError(t, newPIDVersionStamper().stamp(envs))

	execGen, ok := pidVersionOf(t, envs[0])
	require.True(t, ok)
	connGen, ok := pidVersionOf(t, envs[1])
	require.True(t, ok)
	dnsGen, ok := pidVersionOf(t, envs[2])
	require.True(t, ok)
	assert.Equal(t, execGen, connGen, "the connection carries the generation its process is on")
	assert.Equal(t, execGen, dnsGen, "so does the DNS query")

	_, ok = pidVersionOf(t, envs[3])
	assert.False(t, ok, "a flow from a process this capture never started carries no generation at all")
}

// The captures are NOT stored time-sorted (the same reason pickAttackAnchorPID selects on TimestampNs rather than taking the
// last line). Stamping in slice order would mint a process's exec generation before its own fork and leave the flow correlating
// to a generation that did not exist yet.
func TestPIDVersionStamper_WalksTimestampOrderNotSliceOrder(t *testing.T) {
	t.Parallel()
	// Deliberately out of order in the slice: the exec is stored before the fork that created its pid.
	envs := []fakeagent.Envelope{
		env("exec", 200, `{"pid":100,"path":"/bin/zsh"}`),
		env("fork", 100, `{"child_pid":100,"parent_pid":1}`),
	}
	require.NoError(t, newPIDVersionStamper().stamp(envs))

	execGen, _ := pidVersionOf(t, envs[0])
	forkGen, _ := pidVersionOf(t, envs[1])
	assert.Greater(t, execGen, forkGen, "the earlier-timestamped fork must take the earlier generation")
}

// Re-encoding the payload must not disturb fields this has no business touching. Decoding into map[string]any without
// UseNumber turns every number into a float64, and a nanosecond timestamp round-tripped through one comes back in scientific
// notation or short of its last digits.
func TestPIDVersionStamper_PreservesLargeIntegersExactly(t *testing.T) {
	t.Parallel()
	const bigNs = int64(1788992931082659305)
	envs := []fakeagent.Envelope{
		env("exec", 10, `{"pid":100,"path":"/bin/zsh","start_time_ns":1788992931082659305,"uid":501}`),
	}
	require.NoError(t, newPIDVersionStamper().stamp(envs))

	var got struct {
		StartTimeNs int64 `json:"start_time_ns"`
		UID         int   `json:"uid"`
	}
	require.NoError(t, json.Unmarshal(envs[0].Payload, &got))
	assert.Equal(t, bigNs, got.StartTimeNs, "a nanosecond timestamp survives the round-trip digit for digit")
	assert.Equal(t, 501, got.UID)
	assert.NotContains(t, string(envs[0].Payload), "e+", "no number came back in scientific notation")
}

func TestPIDVersionStamper_LeavesUnrelatedEventTypesAlone(t *testing.T) {
	t.Parallel()
	original := `{"pid":100,"path":"/etc/sudoers"}`
	envs := []fakeagent.Envelope{env("file_write", 10, original)}
	require.NoError(t, newPIDVersionStamper().stamp(envs))
	assert.JSONEq(t, original, string(envs[0].Payload), "an event type the schema declares no pidversion on is untouched")
}
