package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

func evaluateLoginItem(t *testing.T, excl api.ExclusionResolver, events ...api.Event) []api.Finding {
	t.Helper()
	findings, err := (&PersistenceLoginItem{Exclusions: excl}).Evaluate(t.Context(), events, stubGraphReader{})
	require.NoError(t, err)
	return findings
}

// loginItemHelper is a helper bundle in the shape captured on a VM (issue #1167): inside the registering app, and signed by the
// agent as a bundle, since BTM reports no executable for a login item.
const loginItemHelper = "/Users/alice/Applications/Tool.app/Contents/Library/LoginItems/ToolHelper.app"

// spec:server-detection-rules-engine/login-item-persistence-judged-on-its-app/an-untrusted-login-item-fires
func TestPersistenceLoginItem_AnUntrustedLoginItemFires(t *testing.T) {
	t.Parallel()
	evt := btmRegistrationEvent(t, "login_item", loginItemHelper, "", &codeSigningJSON{SigningID: "com.example.toolhelper"}, false)
	findings := evaluateLoginItem(t, nil, evt)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "persistence_login_item", f.RuleID)
	assert.Equal(t, api.SeverityMedium, f.Severity)
	assert.Contains(t, f.Description, loginItemHelper)
	assert.NotContains(t, f.Description, "file://", "the helper is named as a path, the form an operator excludes it by")
	assert.Equal(t, "loginitem:"+loginItemHelper, f.Subject)
	assert.Zero(t, f.ProcessID, "process-optional: the helper is not running yet and smd is not the attacker")
	assert.Equal(t, []string{evt.EventID}, f.EventIDs)

	agent := btmRegistrationEvent(t, "agent", "/Users/alice/Library/LaunchAgents/x.plist", "/Users/alice/x",
		&codeSigningJSON{SigningID: "a.out"}, false)
	assert.Empty(t, evaluateLoginItem(t, nil, agent), "a LaunchAgent is persistence_launchagent's to judge")
}

// spec:server-detection-rules-engine/login-item-persistence-judged-on-its-app/an-untrusted-app-added-to-the-login-items-fires
//
// The app shape, captured on a VM from both SMAppService.mainApp and the legacy login-items list: the item is the app bundle,
// reported with a trailing slash, and the agent signs it. The finding and the subject name it without the slash, the way an operator
// writes the path.
func TestPersistenceLoginItem_AnUntrustedAppAddedToTheLoginItemsFires(t *testing.T) {
	t.Parallel()
	evt := btmRegistrationEvent(t, "app", "/Users/alice/Applications/Tool.app/", "", &codeSigningJSON{SigningID: "com.example.tool"}, false)
	findings := evaluateLoginItem(t, nil, evt)

	require.Len(t, findings, 1)
	assert.Equal(t, "Untrusted app /Users/alice/Applications/Tool.app registered as a login item", findings[0].Description)
	assert.Equal(t, "loginitem:/Users/alice/Applications/Tool.app", findings[0].Subject)

	excl := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "persistence_login_item", matchType: api.ExclusionMatchPathGlob, value: "/Users/alice/Applications/Tool.app"},
	}}
	assert.Empty(t, evaluateLoginItem(t, excl, evt), "a path exclusion written without the slash matches")
}

// spec:server-detection-rules-engine/login-item-persistence-judged-on-its-app/an-apple-or-managed-login-item-does-not-fire
func TestPersistenceLoginItem_AppleAndManagedHelpersDoNotFire(t *testing.T) {
	t.Parallel()
	apple := btmRegistrationEvent(t, "login_item", "/System/Applications/Tool.app/Contents/Library/LoginItems/Helper.app", "",
		&codeSigningJSON{SigningID: "com.apple.helper", IsPlatformBinary: true}, false)
	managed := btmRegistrationEvent(t, "login_item", loginItemHelper, "", &codeSigningJSON{SigningID: "a.out"}, true)
	assert.Empty(t, evaluateLoginItem(t, nil, apple, managed))
}

// spec:server-detection-rules-engine/login-item-persistence-judged-on-its-app/a-login-item-with-no-signature-is-skipped
//
// An agent from before issue #1167 sends a login item as BTM reports it: relative to its app and with no signature, since there is
// no executable path to sign. Nothing about it can be judged, and firing on every such registration would be noise.
func TestPersistenceLoginItem_ALoginItemWithNoSignatureIsSkipped(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(map[string]any{
		"item_type": "login_item", "item_path": "Contents/Library/LoginItems/ToolHelper.app", "executable_path": "", "managed": false,
	})
	require.NoError(t, err)
	evt := api.Event{EventID: "legacy", HostID: "fixture-host", TimestampNs: 1, EventType: "btm_launch_item_add", Payload: payload}
	assert.Empty(t, evaluateLoginItem(t, nil, evt))
}

// spec:server-detection-rules-engine/login-item-persistence-judged-on-its-app/a-vendor-login-item-is-waived-by-its-signer-or-path
func TestPersistenceLoginItem_Waived(t *testing.T) {
	t.Parallel()
	const rule = "persistence_login_item"
	vendor := &codeSigningJSON{TeamID: "2BUA8C4S2C", SigningID: "com.1password.1password-launcher"}
	claimant := &codeSigningJSON{SigningID: "com.1password.1password-launcher"}
	cases := []struct {
		name  string
		excl  fakeExcl
		cs    *codeSigningJSON
		fires bool
	}{
		{"the vendor's team", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchTeamID, value: "2BUA8C4S2C"}, vendor, false},
		{"the vendor's qualified signing id", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchSigningID,
			value: "2BUA8C4S2C:com.1password.1password-launcher"}, vendor, false},
		{"an ad-hoc helper claiming the identifier", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchSigningID,
			value: "2BUA8C4S2C:com.1password.1password-launcher"}, claimant, true},
		{"the helper's bundle path", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchPathGlob,
			value: "/Users/alice/Applications/*/Contents/Library/LoginItems/*"}, claimant, false},
		{"the same team, saved for the LaunchAgent rule", fakeExcl{ruleID: "persistence_launchagent",
			matchType: api.ExclusionMatchTeamID, value: "2BUA8C4S2C"}, vendor, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evt := btmRegistrationEvent(t, "login_item", loginItemHelper, "", tc.cs, false)
			findings := evaluateLoginItem(t, &fakeExclusions{entries: []fakeExcl{tc.excl}}, evt)
			assert.Equal(t, tc.fires, len(findings) == 1)
		})
	}
}
