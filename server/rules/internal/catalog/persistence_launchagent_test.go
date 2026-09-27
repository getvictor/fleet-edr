package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

func evaluateLaunchAgent(t *testing.T, excl api.ExclusionResolver, events ...api.Event) []api.Finding {
	t.Helper()
	findings, err := (&PersistenceLaunchAgent{Exclusions: excl}).Evaluate(t.Context(), events, stubGraphReader{})
	require.NoError(t, err)
	return findings
}

var zoomUpdater = &codeSigningJSON{TeamID: "BJ4HAAB9B3", SigningID: "us.zoom.ZoomDaemon"}

// spec:server-detection-rules-engine/launchagent-persistence-judged-on-the-program/an-untrusted-agent-fires-without-launchctl
//
// The registration is the event, so nothing about how the plist became active matters. The fixture has no exec at all, which is
// the shape the launchctl-based rule never saw: a plist written into ~/Library/LaunchAgents and picked up at the next login.
func TestPersistenceLaunchAgent_AnUntrustedAgentFires(t *testing.T) {
	t.Parallel()
	evt := btmRegistrationEvent(t, "agent", "/Users/alice/Library/LaunchAgents/com.evil.plist", "/Users/alice/.cache/evil",
		&codeSigningJSON{SigningID: "a.out"}, false)
	findings := evaluateLaunchAgent(t, nil, evt)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "persistence_launchagent", f.RuleID)
	assert.Equal(t, api.SeverityHigh, f.Severity)
	assert.Contains(t, f.Description, "/Users/alice/.cache/evil")
	assert.Contains(t, f.Description, "/Users/alice/Library/LaunchAgents/com.evil.plist")
	assert.NotContains(t, f.Description, "file://", "the plist is named as a path, the form an operator excludes it by")
	assert.Equal(t, "launchagent:/Users/alice/Library/LaunchAgents/com.evil.plist", f.Subject)
	assert.Zero(t, f.ProcessID, "process-optional: the registered program is not running yet and smd is not the attacker")
	assert.Equal(t, []string{evt.EventID}, f.EventIDs)
}

// spec:server-detection-rules-engine/launchagent-persistence-judged-on-the-program/an-apple-or-managed-agent-does-not-fire
//
// Three of the five benign LaunchAgent alerts on the dogfood deployment were Apple's own (XProtect, MobileDevice). They stop here
// with no configuration at all.
func TestPersistenceLaunchAgent_AppleAndManagedAgentsDoNotFire(t *testing.T) {
	t.Parallel()
	apple := btmRegistrationEvent(t, "agent", "/Library/Apple/System/Library/LaunchAgents/com.apple.XProtect.agent.scan.plist",
		"/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect",
		&codeSigningJSON{SigningID: "com.apple.XProtect", IsPlatformBinary: true}, false)
	managed := btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/com.acme.managed.plist", "/opt/acme/agent",
		&codeSigningJSON{SigningID: "a.out"}, true)
	assert.Empty(t, evaluateLaunchAgent(t, nil, apple, managed))
}

// spec:server-detection-rules-engine/launchagent-persistence-judged-on-the-program/a-vendor-agent-is-waived-by-its-signer
// spec:server-detection-rules-engine/launchagent-persistence-judged-on-the-program/an-ad-hoc-binary-cannot-claim-a-signer
func TestPersistenceLaunchAgent_WaivedBySigner(t *testing.T) {
	t.Parallel()
	byTeam := fakeExcl{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchTeamID, value: "BJ4HAAB9B3"}
	bySigningID := fakeExcl{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchSigningID, value: "BJ4HAAB9B3:us.zoom.ZoomDaemon"}
	bareSigningID := fakeExcl{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchSigningID, value: "us.zoom.ZoomDaemon"}
	claimant := &codeSigningJSON{SigningID: "us.zoom.ZoomDaemon"}

	cases := []struct {
		name  string
		excl  fakeExcl
		cs    *codeSigningJSON
		fires bool
	}{
		{"the vendor's team", byTeam, zoomUpdater, false},
		{"the vendor's qualified signing id", bySigningID, zoomUpdater, false},
		{"an ad-hoc binary claiming the identifier, against the qualified exclusion", bySigningID, claimant, true},
		{"an ad-hoc binary claiming the identifier, against a bare one", bareSigningID, claimant, true},
		{"another vendor's team", fakeExcl{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchTeamID, value: "OTHERTEAM1"},
			zoomUpdater, true},
		{"the same team, saved for the daemon rule", fakeExcl{ruleID: "privilege_launchd_plist_write",
			matchType: api.ExclusionMatchTeamID, value: "BJ4HAAB9B3"}, zoomUpdater, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evt := btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/us.zoom.updater.plist", "/Library/Application Support/zoom/updater",
				tc.cs, false)
			findings := evaluateLaunchAgent(t, &fakeExclusions{entries: []fakeExcl{tc.excl}}, evt)
			assert.Equal(t, tc.fires, len(findings) == 1)
		})
	}
}

// spec:server-detection-rules-engine/launchagent-persistence-judged-on-the-program/a-plist-path-exclusion-keeps-working
//
// A path_glob saved when the rule matched the launchctl command line named the plist as a path. The extension reports the plist as
// a file URL, so matching the URL would have left every such exclusion suppressing nothing after the upgrade.
func TestPersistenceLaunchAgent_APlistPathExclusionKeepsWorking(t *testing.T) {
	t.Parallel()
	excl := &fakeExclusions{entries: []fakeExcl{
		{
			ruleID: "persistence_launchagent", matchType: api.ExclusionMatchPathGlob,
			value: "/Users/jane doe/Library/LaunchAgents/com.logi.ghub.plist",
		},
	}}
	// A space in the path is escaped in the URL (%20) and written plainly in the exclusion, so this fails unless the URL is
	// decoded to a path before matching.
	evt := btmRegistrationEvent(t, "agent", "/Users/jane doe/Library/LaunchAgents/com.logi.ghub.plist",
		"/Applications/lghub.app/Contents/MacOS/lghub_agent", &codeSigningJSON{SigningID: "a.out"}, false)
	require.Contains(t, string(evt.Payload), "jane%20doe", "the fixture carries the escaped URL form a real host sends")
	assert.Empty(t, evaluateLaunchAgent(t, excl, evt))
}

// spec:server-detection-rules-engine/an-exclusion-covers-only-what-it-names/an-excluded-registration-does-not-cover-its-neighbour
// spec:server-detection-rules-engine/an-exclusion-covers-only-what-it-names/every-registration-excluded-suppresses-every-finding
// spec:server-detection-rules-engine/an-exclusion-covers-only-what-it-names/several-registrations-are-each-reported
//
// The bypass #1028 closed on the command-line rule, restated for registrations: `launchctl load benign.plist evil.plist` registers
// two items, and an exclusion for the first must say nothing about the second.
func TestPersistenceLaunchAgent_AnExclusionCoversOnlyWhatItNames(t *testing.T) {
	t.Parallel()
	benign := btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/com.logi.ghub.plist", "/opt/logi/agent",
		&codeSigningJSON{SigningID: "a.out"}, false)
	benign.EventID = "benign"
	evil := btmRegistrationEvent(t, "agent", "/Users/alice/Library/LaunchAgents/evil.plist", "/Users/alice/evil",
		&codeSigningJSON{SigningID: "a.out"}, false)
	evil.EventID = "evil"
	pathExcl := func(plist string) fakeExcl {
		return fakeExcl{ruleID: "persistence_launchagent", matchType: api.ExclusionMatchPathGlob, value: plist}
	}

	t.Run("an excluded registration does not cover its neighbour", func(t *testing.T) {
		t.Parallel()
		findings := evaluateLaunchAgent(t, &fakeExclusions{entries: []fakeExcl{pathExcl("/Library/LaunchAgents/com.logi.ghub.plist")}},
			benign, evil)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0].Description, "evil.plist")
		assert.NotContains(t, findings[0].Description, "com.logi.ghub.plist")
	})
	t.Run("every registration excluded suppresses every finding", func(t *testing.T) {
		t.Parallel()
		excl := &fakeExclusions{entries: []fakeExcl{
			pathExcl("/Library/LaunchAgents/com.logi.ghub.plist"), pathExcl("/Users/alice/Library/LaunchAgents/evil.plist"),
		}}
		assert.Empty(t, evaluateLaunchAgent(t, excl, benign, evil))
	})
	t.Run("several registrations are each reported", func(t *testing.T) {
		t.Parallel()
		findings := evaluateLaunchAgent(t, nil, benign, evil)
		require.Len(t, findings, 2)
		assert.Contains(t, findings[0].Description, "com.logi.ghub.plist")
		assert.Contains(t, findings[1].Description, "evil.plist")
		assert.NotEqual(t, findings[0].Subject, findings[1].Subject, "distinct items dedup separately")
	})
}
