package rules

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func TestPersistenceLaunchAgent_TableDriven(t *testing.T) {
	type fixture struct {
		name          string
		args          []string
		path          string
		parentPath    string
		wantFinding   bool
		wantDescHas   string
		allowedPlists map[string]struct{}
	}

	cases := []fixture{
		{
			name:        "user-level LaunchAgent load fires",
			args:        []string{"/bin/launchctl", "load", "/Users/alice/Library/LaunchAgents/com.evil.agent.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: true,
			wantDescHas: "com.evil.agent.plist",
		},
		{
			name:        "system-level LaunchAgent bootstrap fires",
			args:        []string{"/bin/launchctl", "bootstrap", "system", "/Library/LaunchAgents/com.evil.root.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/usr/bin/sudo",
			wantFinding: true,
			wantDescHas: "com.evil.root.plist",
		},
		{
			name:        "launchctl unload does NOT fire — removing persistence is benign",
			args:        []string{"/bin/launchctl", "unload", "/Users/alice/Library/LaunchAgents/com.evil.agent.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "launchctl list does NOT fire — no plist argument",
			args:        []string{"/bin/launchctl", "list"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "non-launchctl binary does NOT fire",
			args:        []string{"/bin/ls", "/Users/alice/Library/LaunchAgents/"},
			path:        "/bin/ls",
			parentPath:  "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "plist outside LaunchAgents dir does NOT fire",
			args:        []string{"/bin/launchctl", "load", "/opt/homebrew/Cellar/postgres/foo.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "allowlisted plist does NOT fire",
			args:        []string{"/bin/launchctl", "load", "/Library/LaunchAgents/com.okta.agent.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
			allowedPlists: map[string]struct{}{
				"/Library/LaunchAgents/com.okta.agent.plist": {},
			},
		},
		{
			name:        "load with -w flag still fires (flag ignored during arg walk)",
			args:        []string{"/bin/launchctl", "load", "-w", "/Users/bob/Library/LaunchAgents/com.stealth.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: true,
			wantDescHas: "com.stealth.plist",
		},
		{
			// Regression: CodeRabbit flagged that `bootstrap gui/501 <plist>` was captured
			// with "gui/501" as the plistPath (first arg containing "/"), so the rule
			// dropped the event. Matching on the LaunchAgents plist regex fixes it.
			name:        "bootstrap with launch-domain specifier still fires",
			args:        []string{"/bin/launchctl", "bootstrap", "gui/501", "/Users/alice/Library/LaunchAgents/com.domain.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: true,
			wantDescHas: "com.domain.plist",
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
			targetPayload, _ := json.Marshal(map[string]any{
				"pid": 100, "ppid": 50, "path": tc.path, "args": tc.args,
				"uid": 501, "gid": 20,
			})
			events := []store.Event{
				{EventID: "fork-parent", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
				{EventID: "exec-parent", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
					Payload: parentPayload},
				{EventID: "fork-target", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
				{EventID: "exec-target", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
					Payload: targetPayload},
			}
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			rule := &PersistenceLaunchAgent{AllowedPlists: tc.allowedPlists}
			findings, err := rule.Evaluate(ctx, events, s)
			require.NoError(t, err)

			if !tc.wantFinding {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Equal(t, "persistence_launchagent", findings[0].RuleID)
			assert.Equal(t, "high", findings[0].Severity)
			assert.Contains(t, findings[0].Description, tc.wantDescHas)
			assert.Contains(t, findings[0].EventIDs, "exec-target")
		})
	}
}
