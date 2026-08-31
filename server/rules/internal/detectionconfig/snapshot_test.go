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
		// spec:server-detection-rules-engine/per-host-resolution-of-exclusions-and-rule-settings/a-global-exclusion-suppresses-the-finding-on-every-host
		{"global glob matches version-stamped path", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/Users/dev/.local/share/claude/versions/2.1.178/claude", "host-z", true},
		{"global team id exact match", "privilege_launchd_plist_write", api.ExclusionMatchTeamID, "EQHXZ8M8AV", "host-z", true},
		{"team id non-match", "privilege_launchd_plist_write", api.ExclusionMatchTeamID, "OTHERTEAM", "host-z", false},
		{"group entry applies to member host", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/opt/grp/tool", "host-a", true},
		// spec:server-detection-rules-engine/per-host-resolution-of-exclusions-and-rule-settings/a-host-group-scoped-exclusion-does-not-affect-other-hosts
		{"group entry does not apply to non-member host", "suspicious_exec", api.ExclusionMatchParentPathGlob, "/opt/grp/tool", "host-z", false},
		// spec:server-detection-rules-engine/durable-detection-configuration-surface/an-expired-exclusion-stops-applying
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

// spec:server-detection-rules-engine/a-rule-declares-the-mode-it-operates-in-absent-configuration/a-rule-declaring-a-default-operates-in-it-when-nothing-is-configured
// spec:server-detection-rules-engine/a-rule-declares-the-mode-it-operates-in-absent-configuration/a-configured-setting-overrides-a-declared-default
//
// TestSnapshotResolvesAgainstTheRulesDeclaredDefault pins that the rule's own default is what applies when no setting does, and
// that a setting always beats it.
//
// The ordering is the whole point of passing the default in rather than baking `alert` into the resolver: an operator who promotes
// an imported rule to alerting must not be overridden by the rule's own opinion of how it should run. The reverse ordering would be
// invisible, because both answers are valid modes.
func TestSnapshotResolvesAgainstTheRulesDeclaredDefault(t *testing.T) {
	t.Parallel()

	settings := []api.DetectionRuleSetting{
		{RuleID: "promoted", HostGroupID: api.GlobalScope, Mode: api.DetectionRuleModeAlert},
		{RuleID: "silenced", HostGroupID: api.GlobalScope, Mode: api.DetectionRuleModeDisabled},
	}
	s := detectionconfig.NewSnapshot(1, nil, settings, nil, fixedClock(1000))

	t.Run("no setting yields the rule's declared default", func(t *testing.T) {
		t.Parallel()
		mode, severity := s.ResolveRuleMode("unconfigured", "host-a", api.DetectionRuleModeMonitor)
		assert.Equal(t, api.DetectionRuleModeMonitor, mode)
		assert.Empty(t, severity, "a severity override is something only a setting can carry")
	})
	t.Run("no setting and no declaration still yields alert", func(t *testing.T) {
		t.Parallel()
		mode, _ := s.ResolveRuleMode("unconfigured", "host-a", api.DetectionRuleModeAlert)
		assert.Equal(t, api.DetectionRuleModeAlert, mode, "every rule behaved this way before defaults existed")
	})
	t.Run("a setting promoting the rule beats a declared monitor default", func(t *testing.T) {
		t.Parallel()
		mode, _ := s.ResolveRuleMode("promoted", "host-a", api.DetectionRuleModeMonitor)
		assert.Equal(t, api.DetectionRuleModeAlert, mode, "the operator's instruction wins over the rule's own opinion")
	})
	t.Run("a setting silencing the rule beats a declared alert default", func(t *testing.T) {
		t.Parallel()
		mode, _ := s.ResolveRuleMode("silenced", "host-a", api.DetectionRuleModeAlert)
		assert.Equal(t, api.DetectionRuleModeDisabled, mode)
	})
}

// spec:server-detection-rules-engine/a-rule-declares-the-mode-it-operates-in-absent-configuration/an-uninterpretable-configured-mode-falls-back-to-the-declared-default
//
// TestSnapshotUninterpretableModeFallsBackToTheDeclaredDefault pins the branch that changed behaviour rather than gained it.
//
// A stored mode this build does not recognise used to resolve to `alert`. That is wrong once rules can declare a default: it takes
// a rule whose author declared monitor and promotes it to alerting on the strength of a value we could not read, which is the one
// outcome declaring a default exists to prevent. An unreadable instruction is not an instruction to alert; it is no instruction.
//
// Reachable in practice during a rolling upgrade, where a newer replica writes a mode this one has never heard of.
func TestSnapshotUninterpretableModeFallsBackToTheDeclaredDefault(t *testing.T) {
	t.Parallel()

	settings := []api.DetectionRuleSetting{
		{RuleID: "written_by_a_newer_build", HostGroupID: api.GlobalScope, Mode: "throttled", SeverityOverride: "low"},
	}
	s := detectionconfig.NewSnapshot(1, nil, settings, nil, fixedClock(1000))

	mode, severity := s.ResolveRuleMode("written_by_a_newer_build", "host-a", api.DetectionRuleModeMonitor)
	assert.Equal(t, api.DetectionRuleModeMonitor, mode, "an unreadable mode must not promote a monitor-default rule")
	assert.Equal(t, "low", severity, "the override is still legible even when the mode is not, so it is still honoured")

	// And a rule that declares nothing keeps the old answer, so nothing about an existing rule changes.
	mode, _ = s.ResolveRuleMode("written_by_a_newer_build", "host-a", api.DetectionRuleModeAlert)
	assert.Equal(t, api.DetectionRuleModeAlert, mode)
}
