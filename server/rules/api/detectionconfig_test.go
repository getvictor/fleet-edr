package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/rules/api"
)

func TestMatchExclusionValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		matchType api.ExclusionMatchType
		entry     string
		candidate string
		want      bool
	}{
		{"path glob crosses separators", api.ExclusionMatchPathGlob, "*/claude/versions/*", "/Users/d/claude/versions/2/claude", true},
		{"path glob literal exact", api.ExclusionMatchPathGlob, "/usr/libexec/sshd-session", "/usr/libexec/sshd-session", true},
		{"parent path glob non-match", api.ExclusionMatchParentPathGlob, "*/lefthook_*", "/usr/bin/python3", false},
		{"team id exact", api.ExclusionMatchTeamID, "EQHXZ8M8AV", "EQHXZ8M8AV", true},
		{"team id mismatch", api.ExclusionMatchTeamID, "EQHXZ8M8AV", "OTHER", false},
		{"command substring", api.ExclusionMatchCommandSubstring, "--allow-net", "node --allow-net app.js", true},
		{"command substring empty entry never matches", api.ExclusionMatchCommandSubstring, "", "anything", false},
		{"domain exact", api.ExclusionMatchDomain, "example.com", "example.com", true},
		{"domain is case-insensitive", api.ExclusionMatchDomain, "example.com", "Example.COM", true},
		{"domain ignores trailing dot", api.ExclusionMatchDomain, "example.com", "example.com.", true},
		{"domain matches subdomain", api.ExclusionMatchDomain, "example.com", "api.example.com", true},
		{"domain does not match suffix-only", api.ExclusionMatchDomain, "example.com", "notexample.com", false},
		{"cdhash exact", api.ExclusionMatchCDHash, "abc123", "abc123", true},
		{"unknown match type never matches", api.ExclusionMatchType("bogus"), "x", "x", false},

		// macOS /private firmlink aliasing: a path-glob exclusion must match regardless of which form (/etc vs /private/etc) the
		// event carried. Covers both directions and all three aliasable prefixes, plus a non-aliasable path (no false match).
		{"etc entry matches private candidate", api.ExclusionMatchPathGlob, "/etc/sudoers", "/private/etc/sudoers", true},
		{"private entry matches etc candidate", api.ExclusionMatchPathGlob, "/private/etc/sudoers", "/etc/sudoers", true},
		{"etc glob matches private candidate", api.ExclusionMatchPathGlob, "/etc/*", "/private/etc/sudoers", true},
		{"var alias", api.ExclusionMatchPathGlob, "/var/db/foo", "/private/var/db/foo", true},
		{"tmp alias parent path glob", api.ExclusionMatchParentPathGlob, "/private/tmp/build/*", "/tmp/build/run.sh", true},
		{"alias does not over-match a different path", api.ExclusionMatchPathGlob, "/etc/sudoers", "/private/etc/passwd", false},
		{"non-aliasable usr path unaffected", api.ExclusionMatchPathGlob, "/usr/bin/python3", "/private/usr/bin/python3", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, api.MatchExclusionValue(tc.matchType, tc.entry, tc.candidate))
		})
	}
}

func TestDetectionRuleModeAndMatchTypeValidators(t *testing.T) {
	t.Parallel()
	assert.True(t, api.IsValidDetectionRuleMode(api.DetectionRuleModeMonitor))
	assert.False(t, api.IsValidDetectionRuleMode("paused"))
	assert.True(t, api.IsValidExclusionMatchType(api.ExclusionMatchTeamID))
	assert.False(t, api.IsValidExclusionMatchType("ip"))
}

// declaringRule is a Rule that declares a default mode, standing in for an imported rule.
type declaringRule struct {
	api.Rule
	mode api.DetectionRuleMode
}

func (r declaringRule) DefaultMode() api.DetectionRuleMode { return r.mode }

// silentRule is a Rule that declares nothing, which is every hand-written rule.
type silentRule struct{ api.Rule }

// spec:server-detection-rules-engine/a-rule-declares-the-mode-it-operates-in-absent-configuration/a-rule-declaring-no-default-alerts
//
// TestDefaultModeOf pins the two answers the helper gives, because the fallback is what makes this change invisible to every rule
// that existed before it: a rule declaring nothing must resolve to alert, exactly as it did.
func TestDefaultModeOf(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rule api.Rule
		want api.DetectionRuleMode
	}{
		{"a rule declaring monitor", declaringRule{mode: api.DetectionRuleModeMonitor}, api.DetectionRuleModeMonitor},
		{"a rule declaring disabled", declaringRule{mode: api.DetectionRuleModeDisabled}, api.DetectionRuleModeDisabled},
		{"a rule declaring alert", declaringRule{mode: api.DetectionRuleModeAlert}, api.DetectionRuleModeAlert},
		{"a rule declaring nothing", silentRule{}, api.DetectionRuleModeAlert},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, api.DefaultModeOf(tc.rule))
		})
	}
}

// TestDefaultModeOf_DoesNotLaunderAnInvalidDeclaration pins that the helper reports what the rule said.
//
// Coercing an invalid declaration to alert here would hide an author error in exchange for nothing: the catalog guard test asserting
// every registered rule's default is valid is what keeps such a rule out of a release, and a helper that silently repaired the value
// would make that guard unfailable.
func TestDefaultModeOf_DoesNotLaunderAnInvalidDeclaration(t *testing.T) {
	t.Parallel()

	got := api.DefaultModeOf(declaringRule{mode: "throttled"})
	assert.Equal(t, api.DetectionRuleMode("throttled"), got)
	assert.False(t, api.IsValidDetectionRuleMode(got), "which is exactly what the catalog guard test looks for")
}
