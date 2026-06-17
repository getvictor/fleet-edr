package graph

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestExecForkPayload_PIDVersionRoundTrip is the wire-field round-trip for the optional pidversion added to the exec and fork
// payloads (issue #403). It pins that the field survives Marshal/Unmarshal across present and absent values and that an absent
// JSON key decodes to nil (correlation falls back to the window) rather than 0.
func TestExecForkPayload_PIDVersionRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("exec absent key decodes to nil", func(t *testing.T) {
		t.Parallel()
		var got execPayload
		require.NoError(t, json.Unmarshal([]byte(`{"pid":1,"ppid":2,"path":"/bin/ls","args":[],"cwd":"/","uid":0,"gid":0}`), &got))
		assert.Nil(t, got.PIDVersion)
	})

	t.Run("fork present value round-trips", func(t *testing.T) {
		t.Parallel()
		in := forkPayload{ChildPID: 10, ParentPID: 1, PIDVersion: new(uint32(99))}
		b, err := json.Marshal(in)
		require.NoError(t, err)
		var out forkPayload
		require.NoError(t, json.Unmarshal(b, &out))
		assert.Equal(t, in, out)
	})

	rapid.Check(t, func(rt *rapid.T) {
		in := execPayload{
			PID:  rapid.IntRange(1, 1<<20).Draw(rt, "pid"),
			PPID: rapid.IntRange(0, 1<<20).Draw(rt, "ppid"),
			Path: rapid.StringMatching(`/[a-z/]{1,12}`).Draw(rt, "path"),
		}
		if rapid.Bool().Draw(rt, "has_pidversion") {
			in.PIDVersion = new(rapid.Uint32().Draw(rt, "pidversion"))
		}
		b, err := json.Marshal(in)
		require.NoError(rt, err)
		var out execPayload
		require.NoError(rt, json.Unmarshal(b, &out))
		assert.Equal(rt, in.PIDVersion, out.PIDVersion)
	})
}
