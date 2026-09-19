package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/an-exclusion-covers-only-what-it-names/an-excluded-candidate-does-not-cover-its-neighbour
// spec:server-detection-rules-engine/an-exclusion-covers-only-what-it-names/every-candidate-excluded-suppresses-the-finding
// spec:server-detection-rules-engine/an-exclusion-covers-only-what-it-names/several-candidates-are-all-named
func TestPersistenceLaunchAgent_TableDriven(t *testing.T) {
	t.Parallel()
	type fixture struct {
		name        string
		args        []string
		path        string
		parentPath  string
		wantFinding bool
		wantDescHas string
		// wantDescLacks is what the description must NOT name. An excluded plist belongs here: an analyst reading the alert
		// should see what the exclusion left behind, not the benign path that was already accounted for (issue #1028).
		wantDescLacks string
		exclusions    *fakeExclusions
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
			name:        "launchctl unload does NOT fire (removing persistence is benign)",
			args:        []string{"/bin/launchctl", "unload", "/Users/alice/Library/LaunchAgents/com.evil.agent.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
		},
		{
			name:        "launchctl list does NOT fire (no plist argument)",
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
			// The bypass issue #1028 closes, in the exact shape the issue describes: dogfood excludes the Logitech plist, and
			// naming it first suppressed whatever was registered alongside it. Planting under /Library/LaunchAgents needs root;
			// this needs none, because the first argument only has to NAME the excluded plist.
			name: "an excluded plist does not cover the one beside it",
			args: []string{
				"/bin/launchctl", "load",
				"/Library/LaunchAgents/com.logi.ghub.plist",
				"/Users/alice/Library/LaunchAgents/evil.plist",
			},
			path:          "/bin/launchctl",
			parentPath:    "/bin/bash",
			wantFinding:   true,
			wantDescHas:   "evil.plist",
			wantDescLacks: "com.logi.ghub.plist",
			exclusions: &fakeExclusions{entries: []fakeExcl{
				{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchPathGlob, value: "/Library/LaunchAgents/com.logi.*.plist"},
			}},
		},
		{
			// Suppressed only when the operator excluded every one of them.
			name: "several plists all excluded does NOT fire",
			args: []string{
				"/bin/launchctl", "load",
				"/Library/LaunchAgents/com.logi.ghub.plist",
				"/Library/LaunchAgents/com.okta.agent.plist",
			},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
			exclusions: &fakeExclusions{entries: []fakeExcl{
				{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchPathGlob, value: "/Library/LaunchAgents/com.logi.*.plist"},
				{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchPathGlob, value: "/Library/LaunchAgents/com.okta.agent.plist"},
			}},
		},
		{
			// With no exclusion at all the description still has to name both, or an analyst reads the alert and never learns
			// the second plist was registered.
			name: "several plists with no exclusion names them all",
			args: []string{
				"/bin/launchctl", "load",
				"/Users/alice/Library/LaunchAgents/com.first.plist",
				"/Users/alice/Library/LaunchAgents/com.second.plist",
			},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: true,
			wantDescHas: "com.second.plist",
		},
		{
			name:        "allowlisted plist does NOT fire",
			args:        []string{"/bin/launchctl", "load", "/Library/LaunchAgents/com.okta.agent.plist"},
			path:        "/bin/launchctl",
			parentPath:  "/bin/bash",
			wantFinding: false,
			exclusions: &fakeExclusions{entries: []fakeExcl{
				{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchPathGlob, value: "/Library/LaunchAgents/com.okta.agent.plist"},
			}},
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
			// Regression: CodeRabbit flagged that `bootstrap gui/501 <plist>` was captured with "gui/501" as the plistPath
			// (first arg containing "/"), so the rule dropped the event. Matching on the LaunchAgents plist regex fixes
			// it.
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
			t.Parallel()
			s := openCatalogStore(t)
			ctx := t.Context()

			parentPayload, _ := json.Marshal(map[string]any{
				"pid": 50, "ppid": 1, "path": tc.parentPath, "args": []string{tc.parentPath},
				"uid": 501, "gid": 20,
			})
			targetPayload, _ := json.Marshal(map[string]any{
				"pid": 100, "ppid": 50, "path": tc.path, "args": tc.args,
				"uid": 501, "gid": 20,
			})
			events := []api.Event{
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

			rule := &PersistenceLaunchAgent{}
			if tc.exclusions != nil {
				rule.Exclusions = tc.exclusions
			}
			findings, err := rule.Evaluate(ctx, events, s.GraphReader())
			require.NoError(t, err)

			if !tc.wantFinding {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Equal(t, "persistence_launchagent", findings[0].RuleID)
			assert.Equal(t, rule.DisplayName(), findings[0].Title, "alert title is the rule's canonical DisplayName (issue #519)")
			assert.Equal(t, "high", findings[0].Severity)
			assert.Contains(t, findings[0].Description, tc.wantDescHas)
			if tc.wantDescLacks != "" {
				assert.NotContains(t, findings[0].Description, tc.wantDescLacks,
					"an excluded plist must not be named: the description is what the exclusion left behind")
			}
			assert.Contains(t, findings[0].EventIDs, "exec-target")
		})
	}
}
