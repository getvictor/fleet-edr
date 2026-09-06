//go:build integration

package integration

import (
	"log/slog"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

// packRule renders a Sigma document the loader accepts, so the pack under test is real content rather than opaque bytes.
func packRule(id, title, marker string) string {
	return "title: " + title + "\n" +
		"id: " + id + "\n" +
		"status: test\ndescription: pack fixture\nauthor: upstream\n" +
		"logsource:\n    category: process_creation\n    product: macos\n" +
		"detection:\n    selection:\n        Image|endswith: '/" + marker + "'\n    condition: selection\n" +
		"level: medium\n"
}

// spec:rule-content/a-build-installs-its-shipped-rule-content/an-operator-s-tuning-survives
//
// TestRulePackUpgrade_PreservesTuning is the second acceptance criterion of issue #768, and it spans two contexts on purpose: the
// pack is rule CONTENT and the tuning is detection CONFIG, so the claim that one survives the other cannot be verified from either
// side alone.
//
// The reason it holds is structural rather than careful: per-rule mode and severity overrides live in detection_rule_settings
// keyed by rule id, and a pack upgrade rewrites documents. Structural reasons are the ones most worth pinning, because nothing in
// either context announces the dependency and a later change to where tuning lives would break this silently, on upgrade, on a
// deployment that had tuned its rules deliberately.
//
// The tuning is written straight to the table, for the reason TestLongRuleID does the same: the promotion is a precondition here
// rather than the behaviour under test, and the version bump is the cache-invalidation signal a replica reloads on. It is read
// back through the resolver the server itself uses, so what is asserted is what production would resolve.
func TestRulePackUpgrade_PreservesTuning(t *testing.T) {
	t.Parallel()
	stack := Setup(t)
	ctx := t.Context()
	const ruleID = "packed_rule"

	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: stack.DB, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)

	// Replace rather than seed: Setup has already seeded this corpus from the embedded pack, and the seed acts only on an empty
	// one. Starting from a known single-document pack is what makes the upgrade below observable.
	_, err = rc.Replace(ctx, []rulecontentapi.Document{{
		Path:    "imported/process_creation/packed_rule.yml",
		Content: []byte(packRule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Packed Rule", "osascript")),
		Source:  rulecontentapi.SourceVendored,
	}})
	require.NoError(t, err)

	_, err = stack.DB.ExecContext(ctx, `
		INSERT INTO detection_rule_settings (rule_id, host_group_id, mode, severity_override, updated_by)
		VALUES (?, 0, 'alert', 'critical', 'pack-upgrade-test')
		ON DUPLICATE KEY UPDATE mode = VALUES(mode), severity_override = VALUES(severity_override)`, ruleID)
	require.NoError(t, err)
	_, err = stack.DB.ExecContext(ctx, `UPDATE detection_config_meta SET version = version + 1 WHERE id = 1`)
	require.NoError(t, err)

	resolver := stack.Rules.DetectionConfigModeResolver()
	require.Eventually(t, func() bool {
		mode, _ := resolver.ResolveRuleMode(ruleID, "host-a", rulesapi.DetectionRuleModeMonitor)
		return mode == rulesapi.DetectionRuleModeAlert
	}, 30*time.Second, 100*time.Millisecond, "the tuning never reached the config snapshot, so the assertion below would be vacuous")

	// A newer pack ships the same rule with different content.
	upgraded, err := rc.UpgradePackFrom(ctx, fstest.MapFS{
		"imported/process_creation/packed_rule.yml": &fstest.MapFile{
			Data: []byte(packRule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Packed Rule", "osascript-v2")),
		},
	}, ".", nil, rulesbootstrap.RuleIdentityForPath)
	require.NoError(t, err)
	require.True(t, upgraded, "the newer pack must install")

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Contains(t, string(docs[0].Content), "osascript-v2", "the upgrade must have installed the newer pack")

	mode, severity := resolver.ResolveRuleMode(ruleID, "host-a", rulesapi.DetectionRuleModeMonitor)
	assert.Equal(t, rulesapi.DetectionRuleModeAlert, mode,
		"a rule promoted out of monitor must not silently return to it on a pack upgrade")
	assert.Equal(t, "critical", severity, "the severity the operator chose must survive the upgrade")
}
