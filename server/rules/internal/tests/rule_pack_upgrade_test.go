//go:build integration

package tests

import (
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/migrations/runner"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	rulesmigrations "github.com/fleetdm/edr/server/rules/migrations"
	"github.com/fleetdm/edr/server/testdb/full"
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

// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/an-operator-s-tuning-survives
//
// TestRulePackUpgrade_PreservesTuning is the second acceptance criterion of issue #768, and it spans two contexts on purpose:
// the pack is rule CONTENT and the tuning is detection CONFIG, so the claim that one survives the other is exactly the kind of
// cross-context relationship that cannot be verified from either side alone.
//
// The reason it holds is structural rather than careful: per-rule mode, severity overrides and exclusions live in
// detection_rule_settings keyed by rule id, and a pack upgrade rewrites documents. Structural reasons are the ones most worth
// pinning, because nothing in either context announces the dependency and a later change to where tuning lives would break this
// silently, on upgrade, on a deployment that had tuned its rules deliberately.
func TestRulePackUpgrade_PreservesTuning(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := full.Open(t)
	logger := slog.New(slog.DiscardHandler)

	require.NoError(t, runner.Up(ctx, db, rulesmigrations.FS, runner.Options{
		Context:   "rules",
		TableName: "rules_goose_db_version",
	}))

	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err)

	const ruleID = "packed_rule"
	v1 := fstest.MapFS{
		"imported/process_creation/packed_rule.yml": &fstest.MapFile{
			Data: []byte(packRule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Packed Rule", "osascript")),
		},
	}
	seeded, err := rc.SeedFrom(ctx, v1, ".", nil)
	require.NoError(t, err)
	require.True(t, seeded)

	// The operator tunes the rule: promoted out of monitor, with a severity they chose and an exclusion they added.
	settings := detectionconfig.NewStore(db)
	_, err = settings.UpsertRuleSetting(ctx, detectionconfig.UpsertSettingInput{
		RuleID:           ruleID,
		HostGroupID:      rulesapi.GlobalScope,
		Mode:             rulesapi.DetectionRuleModeAlert,
		SeverityOverride: "critical",
		Actor:            "operator",
	})
	require.NoError(t, err)

	// A newer pack ships the same rule with different content.
	v2 := fstest.MapFS{
		"imported/process_creation/packed_rule.yml": &fstest.MapFile{
			Data: []byte(packRule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Packed Rule", "osascript-v2")),
		},
	}
	upgraded, err := rc.UpgradePackFrom(ctx, v2, ".", nil, rulesbootstrap.RuleIdentityForPath)
	require.NoError(t, err)
	require.True(t, upgraded, "the newer pack must install")

	// The content really did move, so the tuning assertions below are about a rule that was actually upgraded.
	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Contains(t, string(docs[0].Content), "osascript-v2", "the upgrade must have installed the newer pack")

	snap, err := settings.LoadSnapshot(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, rulesapi.DetectionRuleModeAlert, snap.Mode(ruleID, "host-a"),
		"a rule promoted out of monitor must not silently return to it on a pack upgrade")
	assert.Equal(t, "critical", snap.SeverityOverride(ruleID, "host-a"),
		"the severity the operator chose must survive the upgrade")

	all, err := settings.ListRuleSettings(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1, "the upgrade must not have dropped or duplicated the operator's tuning")
}

// TestRuleIdentityForPath_IsTheKeyTheLoaderCompares pins the PRODUCTION identity function on the property the pack upgrade relies
// on, and it exists because of where it can live.
//
// The store-level tests supply their own one-line stand-in for this key, and review asked why they do not call this function
// instead. They cannot: arch-go forbids anything under rulecontent from depending on rules at all, deliberately, and the config
// says adding an entry to that list should be read as evaluation leaking back into content. Inverting that to save a line of test
// code would be the wrong trade.
//
// The risk the question points at is real, though: a stand-in that drifted from the real key would make those tests assert a rule
// production does not follow. This closes it from the side where the import IS legal, by pinning what the real function returns.
func TestRuleIdentityForPath_IsTheKeyTheLoaderCompares(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want string
	}{
		{"a stored path reduces to its stem", "imported/process_creation/foo.yml", "foo"},
		{"the directory is not part of the identity", "authored/foo.yml", "foo"},
		{"case is folded, because the columns keyed by this collate that way", "authored/Foo.yml", "foo"},
		{"upper case throughout folds too", "imported/FOO.yml", "foo"},
		{"the extension is dropped", "imported/foo.yaml", "foo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rulesbootstrap.RuleIdentityForPath(tc.path))
		})
	}

	// The property the upgrade actually depends on, stated directly: two documents an operator and a pack could each hold must
	// collide under this key, or the pack installs alongside and the corpus stops loading.
	assert.Equal(t, rulesbootstrap.RuleIdentityForPath("authored/Foo.yml"),
		rulesbootstrap.RuleIdentityForPath("imported/foo.yml"),
		"an operator's rule and a shipped rule differing only in path and case are one rule, and must compare equal")
}
