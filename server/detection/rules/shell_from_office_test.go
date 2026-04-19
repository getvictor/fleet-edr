package rules

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func TestShellFromOffice_TableDriven(t *testing.T) {
	type fixture struct {
		name        string
		parentPath  string
		shellPath   string
		wantFinding bool
		wantDesc    string
	}

	cases := []fixture{
		{
			name:        "Word → bash fires",
			parentPath:  "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
			shellPath:   "/bin/bash",
			wantFinding: true,
			wantDesc:    "Microsoft Word → /bin/bash",
		},
		{
			name:        "Excel → zsh fires",
			parentPath:  "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel",
			shellPath:   "/bin/zsh",
			wantFinding: true,
			wantDesc:    "Microsoft Excel → /bin/zsh",
		},
		{
			name:        "PowerPoint → sh fires",
			parentPath:  "/Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint",
			shellPath:   "/bin/sh",
			wantFinding: true,
			wantDesc:    "Microsoft PowerPoint → /bin/sh",
		},
		{
			name:        "Outlook → dash fires",
			parentPath:  "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook",
			shellPath:   "/bin/dash",
			wantFinding: true,
			wantDesc:    "Microsoft Outlook → /bin/dash",
		},
		{
			name:        "Terminal.app → bash does NOT fire — expected",
			parentPath:  "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
			shellPath:   "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "spoofed path name does NOT fire — full-path match",
			parentPath:  "/tmp/Microsoft Word",
			shellPath:   "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "Word → non-shell does NOT fire",
			parentPath:  "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
			shellPath:   "/usr/bin/open",
			wantFinding: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := store.OpenTestStore(t)
			ctx := t.Context()

			parentPayload, _ := json.Marshal(map[string]any{
				"pid": 50, "ppid": 1, "path": tc.parentPath, "args": []string{tc.parentPath},
				"uid": 501, "gid": 20,
			})
			shellPayload, _ := json.Marshal(map[string]any{
				"pid": 100, "ppid": 50, "path": tc.shellPath, "args": []string{tc.shellPath},
				"uid": 501, "gid": 20,
			})
			events := []store.Event{
				{EventID: "fork-parent", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
				{EventID: "exec-parent", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
					Payload: parentPayload},
				{EventID: "fork-shell", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
				{EventID: "exec-shell", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
					Payload: shellPayload},
			}
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			rule := &ShellFromOffice{}
			findings, err := rule.Evaluate(ctx, events, s)
			require.NoError(t, err)

			if !tc.wantFinding {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Equal(t, "shell_from_office", findings[0].RuleID)
			assert.Equal(t, "high", findings[0].Severity)
			assert.Equal(t, tc.wantDesc, findings[0].Description)
		})
	}
}
