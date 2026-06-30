package control_test

import (
	"testing"

	"github.com/fleetdm/edr/internal/control"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"
)

// TestServerFrameRoundTrip pins the wire shape of the command-push frame: for any command, Marshal then Unmarshal is the identity. This
// is the repo's required round-trip property for a new wire-format message (CLAUDE.md), guarding against a field-tag or oneof drift that
// would silently corrupt commands pushed to a host.
func TestServerFrameRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		in := &control.ServerFrame{
			Frame: &control.ServerFrame_Command{
				Command: &control.Command{
					Id:          rapid.Int64().Draw(t, "id"),
					HostId:      rapid.String().Draw(t, "host_id"),
					CommandType: rapid.String().Draw(t, "command_type"),
					Payload:     rapid.SliceOf(rapid.Byte()).Draw(t, "payload"),
				},
			},
		}
		b, err := proto.Marshal(in)
		require.NoError(t, err)
		var out control.ServerFrame
		require.NoError(t, proto.Unmarshal(b, &out))
		require.True(t, proto.Equal(in, &out), "server frame round-trip mismatch:\n in=%v\nout=%v", in, &out)
	})
}

// TestAgentFrameRoundTrip pins the wire shape of the outcome-report frame the same way.
func TestAgentFrameRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		in := &control.AgentFrame{
			Frame: &control.AgentFrame_Outcome{
				Outcome: &control.Outcome{
					Id:     rapid.Int64().Draw(t, "id"),
					Status: rapid.String().Draw(t, "status"),
					Result: rapid.SliceOf(rapid.Byte()).Draw(t, "result"),
				},
			},
		}
		b, err := proto.Marshal(in)
		require.NoError(t, err)
		var out control.AgentFrame
		require.NoError(t, proto.Unmarshal(b, &out))
		require.True(t, proto.Equal(in, &out), "agent frame round-trip mismatch:\n in=%v\nout=%v", in, &out)
	})
}
