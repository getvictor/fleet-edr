package detectionconfig_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

// fixedClock pins "now" so exclusion-expiry resolution is deterministic.
func fixedClock(sec int64) func() time.Time {
	return func() time.Time { return time.Unix(sec, 0) }
}

func ptrTime(sec int64) *time.Time {
	t := time.Unix(sec, 0)
	return &t
}

func TestSnapshotExcluded(t *testing.T) {
	t.Parallel()
	// host-a is a member of group 7; host-z is not.
	membership := func(hostID string, groupID int64) bool { return hostID == "host-a" && groupID == 7 }
	excl := []api.DetectionExclusion{
		{RuleID: "suspicious_exec", MatchType: api.ExclusionMatchParentPathGlob, Value: "*/claude/versions/*", HostGroupID: api.GlobalScope, Enabled: true},
		{RuleID: "privilege_launchd_plist_write", MatchType: api.ExclusionMatchTeamID, Value: "EQHXZ8M8AV", HostGroupID: api.GlobalScope, Enabled: true},
		{RuleID: "suspicious_exec", MatchType: api.ExclusionMatchParentPathGlob, Value: "/opt/grp/tool", HostGroupID: 7, Enabled: true},
		{RuleID: "suspicious_exec", MatchType: api.ExclusionMatchParentPathGlob, Value: "/opt/expired/tool", HostGroupID: api.GlobalScope, Enabled: true, ExpiresAt: ptrTime(500)},
		{RuleID: "suspicious_exec", MatchType: api.ExclusionMatchParentPathGlob, Value: "/opt/disabled/tool", HostGroupID: api.GlobalScope, Enabled: false},
		{RuleID: "", MatchType: api.ExclusionMatchPathGlob, Value: "*/shared/ok", HostGroupID: api.GlobalScope, Enabled: true},
	}
	s := detectionconfig.NewSnapshot(1, excl, nil, membership, fixedClock(1000))

	cases := []struct {
		name      string
		ruleID    string
		matchType api.ExclusionMatchType
		value     string
		hostID    string
		want      bool
	}{
		{"global glob matches version-stamped path", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/Users/dev/.local/share/claude/versions/2.1.178/claude", "host-z", true},
		{"global team id exact match", "privilege_launchd_plist_write", api.ExclusionMatchTeamID, "EQHXZ8M8AV", "host-z", true},
		{"team id non-match", "privilege_launchd_plist_write", api.ExclusionMatchTeamID, "OTHERTEAM", "host-z", false},
		{"group entry applies to member host", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/opt/grp/tool", "host-a", true},
		{"group entry does not apply to non-member host", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/opt/grp/tool", "host-z", false},
		{"expired entry does not apply", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/opt/expired/tool", "host-z", false},
		{"disabled entry is absent from the snapshot", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/opt/disabled/tool", "host-z", false},
		{"shared (rule_id empty) entry applies to any rule", "sudoers_tamper", api.ExclusionMatchPathGlob, "/a/shared/ok", "host-z", true},
		{"no match for unrelated value", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/usr/bin/python3", "host-z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, s.Excluded(tc.ruleID, tc.matchType, tc.value, tc.hostID))
		})
	}
}

func TestSnapshotModeAndSeverityResolution(t *testing.T) {
	t.Parallel()
	membership := func(hostID string, groupID int64) bool { return hostID == "host-a" && groupID == 7 }
	settings := []api.DetectionRuleSetting{
		{RuleID: "suspicious_exec", HostGroupID: api.GlobalScope, Mode: api.DetectionRuleModeDisabled},
		{RuleID: "suspicious_exec", HostGroupID: 7, Mode: api.DetectionRuleModeAlert, SeverityOverride: "critical"},
		{RuleID: "dyld_insert", HostGroupID: api.GlobalScope, Mode: api.DetectionRuleModeMonitor},
	}
	s := detectionconfig.NewSnapshot(1, nil, settings, membership, fixedClock(1000))

	t.Run("group setting overrides global most-specific-wins", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, api.DetectionRuleModeAlert, s.Mode("suspicious_exec", "host-a"))
		assert.Equal(t, "critical", s.SeverityOverride("suspicious_exec", "host-a"))
	})
	t.Run("non-member host gets the global setting", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, api.DetectionRuleModeDisabled, s.Mode("suspicious_exec", "host-z"))
		assert.Empty(t, s.SeverityOverride("suspicious_exec", "host-z"))
	})
	t.Run("monitor mode resolves at global scope", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, api.DetectionRuleModeMonitor, s.Mode("dyld_insert", "host-z"))
	})
	t.Run("rule with no setting defaults to alert", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, api.DetectionRuleModeAlert, s.Mode("credential_keychain_dump", "host-z"))
	})
}

func TestNilResolverDefaults(t *testing.T) {
	t.Parallel()
	// A nil membership means only global entries apply; an empty snapshot excludes nothing and alerts everything.
	s := detectionconfig.NewSnapshot(0, nil, nil, nil, fixedClock(1000))
	assert.False(t, s.Excluded("suspicious_exec", api.ExclusionMatchParentPathGlob, "/anything", "host-a"))
	assert.Equal(t, api.DetectionRuleModeAlert, s.Mode("suspicious_exec", "host-a"))
	assert.Empty(t, s.SeverityOverride("suspicious_exec", "host-a"))
}
