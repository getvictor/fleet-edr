package fakeagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadScenario_StarterCorpus(t *testing.T) {
	// Walk the shipped scenarios under scenarios/ and assert each loads + validates. Catches regressions where a YAML edit drifts
	// from the schema before any consumer (M4 CI, M10 efficacy) gets there.
	entries, err := os.ReadDir("scenarios")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "starter scenario set must not be empty")

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			s, err := LoadScenario(filepath.Join("scenarios", e.Name()))
			require.NoError(t, err)
			assert.NotEmpty(t, s.Name)
			assert.NotEmpty(t, s.Host.ID)
			assert.NotEmpty(t, s.Timeline)
			for i, ev := range s.Timeline {
				assert.NotEmpty(t, ev.Type, "timeline[%d].type", i)
			}
		})
	}
}

func TestLoadScenario_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing name",
			yaml: "host: {id: h}\ntimeline: [{at: 0ms, type: fork, child_pid: 1, parent_pid: 0}]",
			want: "name is required",
		},
		{
			name: "missing host id",
			yaml: "name: n\nhost: {}\ntimeline: [{at: 0ms, type: fork, child_pid: 1, parent_pid: 0}]",
			want: "host.id is required",
		},
		{
			name: "empty timeline",
			yaml: "name: n\nhost: {id: h}\ntimeline: []",
			want: "timeline must contain at least one event",
		},
		{
			name: "unknown event type",
			yaml: "name: n\nhost: {id: h}\ntimeline: [{at: 0ms, type: bogus}]",
			want: "unknown event_type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "scenario.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.yaml), 0o600))
			_, err := LoadScenario(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoadScenario_FileNotFound(t *testing.T) {
	_, err := LoadScenario(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read ")
}

func TestLoadScenario_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("name: ok\nhost: not-an-object"), 0o600))
	_, err := LoadScenario(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse ")
}

func TestDurationUnmarshal(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{`"10ms"`, 10 * time.Millisecond},
		{`"5s"`, 5 * time.Second},
		{`"1h"`, time.Hour},
		{`0`, 0},
		{`123456789`, 123456789 * time.Nanosecond},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			var d Duration
			require.NoError(t, d.UnmarshalJSON([]byte(tc.in)))
			assert.Equal(t, tc.want, time.Duration(d))
		})
	}
}

func TestDurationUnmarshal_Invalid(t *testing.T) {
	cases := []string{`"not-a-duration"`, `12a`, `"7"`}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			var d Duration
			require.Error(t, d.UnmarshalJSON([]byte(tc)))
		})
	}
}

func TestEnvelopes_DeterministicTimestamps(t *testing.T) {
	s, err := LoadScenario("scenarios/exec-fork-exit.yaml")
	require.NoError(t, err)
	start := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	envs, err := s.Envelopes(WithStartTime(start), WithIDGenerator(seqID()))
	require.NoError(t, err)
	require.Len(t, envs, 3)

	assert.Equal(t, start.UnixNano(), envs[0].TimestampNs)
	assert.Equal(t, start.Add(2*time.Millisecond).UnixNano(), envs[1].TimestampNs)
	assert.Equal(t, start.Add(25*time.Millisecond).UnixNano(), envs[2].TimestampNs)

	// Deterministic ID generator yields predictable event_ids.
	assert.Equal(t, []string{"e-0", "e-1", "e-2"}, []string{envs[0].EventID, envs[1].EventID, envs[2].EventID})
}

func TestEnvelopes_HostIDOverride(t *testing.T) {
	s, err := LoadScenario("scenarios/exec-fork-exit.yaml")
	require.NoError(t, err)

	envs, err := s.Envelopes(WithHostID("override-1"))
	require.NoError(t, err)
	for _, env := range envs {
		assert.Equal(t, "override-1", env.HostID)
	}
}

// spec:endpoint-event-collection/outbound-socket-flow-capture/a-process-opens-an-outbound-tcp-connection
//
// The fakeagent's network_connect row asserts the exact wire contract the spec scenario calls out: a TCP
// outbound connection emits a network_connect envelope whose payload identifies pid, protocol=tcp,
// direction=outbound, remote_address, and remote_port. Optional path/uid/local_address/local_port/
// remote_hostname are documented in schema/events.json as omitted-when-unknown (absent from the JSON
// object, not present with a null value: JSON Schema "optional" is not "nullable" on the wire). The
// fakeagent feeder is the wire-level fixture that the cross-context integration tests use to drive
// realistic event streams; pinning the network_connect shape here means the same contract that the live
// network filter produces is what downstream Go consumers (server detection engine, retention, alert
// pipeline) parse.
func TestEnvelopes_PayloadShapePerEventType(t *testing.T) {
	// One scenario, one event of each supported type. Build envelopes, then unmarshal each payload back into a generic map and
	// assert on the required-fields-per-schema. Catches regressions where buildPayload omits a required field.
	scenario := &Scenario{
		Name: "all-types",
		Host: Host{ID: "h"},
		Timeline: []Event{
			{At: 0, Type: "fork", ChildPID: 11, ParentPID: 1},
			{At: 0, Type: "exec", PID: 11, PPID: 1, Path: "/bin/ls", Args: []string{"ls"}, CWD: "/", UID: 501, GID: 20},
			{At: 0, Type: "exit", PID: 11, ExitCode: 0},
			{At: 0, Type: "open", PID: 11, Path: "/etc/passwd", Flags: 1},
			{At: 0, Type: "network_connect", PID: 11, Protocol: "tcp", Direction: "outbound", RemoteAddress: "10.0.0.1", RemotePort: 443},
			{At: 0, Type: "dns_query", PID: 11, QueryName: "x.y", QueryType: "A"},
			{At: 0, Type: "snapshot_heartbeat", PID: 11},
		},
	}
	require.NoError(t, scenario.Validate())
	envs, err := scenario.Envelopes(WithStartTime(time.Unix(0, 0)))
	require.NoError(t, err)
	require.Len(t, envs, 7)

	required := map[string][]string{
		"fork":               {"child_pid", "parent_pid"},
		"exec":               {"pid", "ppid", "path", "args", "cwd", "uid", "gid"},
		"exit":               {"pid", "exit_code"},
		"open":               {"pid", "path", "flags"},
		"network_connect":    {"pid", "protocol", "direction", "remote_address", "remote_port"},
		"dns_query":          {"pid", "query_name", "query_type"},
		"snapshot_heartbeat": {"pid"},
	}
	for _, env := range envs {
		var payload map[string]any
		require.NoError(t, json.Unmarshal(env.Payload, &payload), env.EventType)
		for _, f := range required[env.EventType] {
			_, ok := payload[f]
			assert.True(t, ok, "%s payload missing required field %q", env.EventType, f)
		}
	}
}

func TestEnvelopes_PreservesTimelineOrder(t *testing.T) {
	// Hand-build a scenario whose At offsets are NOT in ascending order so we know the library emits in timeline order, not sorted.
	scenario := &Scenario{
		Name: "order-test",
		Host: Host{ID: "h"},
		Timeline: []Event{
			{At: Duration(500 * time.Millisecond), Type: "snapshot_heartbeat", PID: 1},
			{At: Duration(100 * time.Millisecond), Type: "snapshot_heartbeat", PID: 2},
			{At: Duration(200 * time.Millisecond), Type: "snapshot_heartbeat", PID: 3},
		},
	}
	envs, err := scenario.Envelopes(WithStartTime(time.Unix(0, 0)))
	require.NoError(t, err)
	got := []int64{envs[0].TimestampNs, envs[1].TimestampNs, envs[2].TimestampNs}
	// Library preserves authoring order even though timestamps are out-of-order.
	want := []int64{
		int64(500 * time.Millisecond),
		int64(100 * time.Millisecond),
		int64(200 * time.Millisecond),
	}
	assert.Equal(t, want, got)

	// Sanity: if a caller wanted ascending-time delivery, they could sort.
	sortedCopy := slices.Clone(got)
	slices.Sort(sortedCopy)
	assert.NotEqual(t, sortedCopy, got, "scenario authored out-of-time-order; library must preserve, not auto-sort")
}

// seqID returns a deterministic event-id generator producing "e-0", "e-1", ... Used by tests that want stable IDs.
func seqID() func() string {
	n := 0
	return func() string {
		id := "e-" + strconv.Itoa(n)
		n++
		return id
	}
}
