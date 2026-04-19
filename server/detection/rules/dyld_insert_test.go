package rules

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func TestDyldInsert_TableDriven(t *testing.T) {
	type fixture struct {
		name        string
		path        string
		args        []string
		wantFinding bool
	}

	cases := []fixture{
		{
			name:        "DYLD_INSERT_LIBRARIES prefix in args fires",
			path:        "/bin/ls",
			args:        []string{"DYLD_INSERT_LIBRARIES=/tmp/inject.dylib", "/bin/ls", "-la"},
			wantFinding: true,
		},
		{
			name:        "DYLD_LIBRARY_PATH prefix in args fires",
			path:        "/usr/bin/env",
			args:        []string{"/usr/bin/env", "DYLD_LIBRARY_PATH=/tmp", "/bin/ls"},
			wantFinding: true,
		},
		{
			name:        "plain ls without env does NOT fire",
			path:        "/bin/ls",
			args:        []string{"/bin/ls", "-la"},
			wantFinding: false,
		},
		{
			name:        "DYLD_FALLBACK_LIBRARY_PATH does NOT fire — not on MVP list",
			path:        "/bin/ls",
			args:        []string{"DYLD_FALLBACK_LIBRARY_PATH=/tmp", "/bin/ls"},
			wantFinding: false,
		},
		{
			name:        "similar but-not-matching arg does NOT fire",
			path:        "/bin/ls",
			args:        []string{"MY_DYLD_INSERT_LIBRARIES=/tmp/inject.dylib", "/bin/ls"},
			wantFinding: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := store.OpenTestStore(t)
			ctx := t.Context()

			payload, _ := json.Marshal(map[string]any{
				"pid": 100, "ppid": 50, "path": tc.path, "args": tc.args,
				"uid": 501, "gid": 20,
			})
			events := []store.Event{
				{EventID: "fork", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
				{EventID: "exec", HostID: "host-a", TimestampNs: 1100, EventType: "exec", Payload: payload},
			}
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			rule := &DyldInsert{}
			findings, err := rule.Evaluate(ctx, events, s)
			require.NoError(t, err)

			if !tc.wantFinding {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Equal(t, "dyld_insert", findings[0].RuleID)
			assert.Equal(t, "high", findings[0].Severity)
			assert.Contains(t, findings[0].Description, "<redacted>",
				"description must not echo the raw dylib path")
			assert.NotContains(t, findings[0].Description, "/tmp/inject.dylib",
				"description must not echo the raw dylib path")
		})
	}
}
