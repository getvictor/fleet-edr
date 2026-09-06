//go:build integration

package tests

import (
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// packFS renders a build's pack as the loader would read it off disk.
func packFS(docs map[string]string) fstest.MapFS {
	out := make(fstest.MapFS, len(docs))
	for path, content := range docs {
		out[path] = &fstest.MapFile{Data: []byte(content)}
	}
	return out
}

func newRuleContent(t *testing.T) *rulecontentbootstrap.RuleContent {
	t.Helper()
	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: full.Open(t), Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	return rc
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/the-previous-generation-is-restored
//
// TestRollback_RestoresTheGenerationAnUpgradeReplaced is the acceptance criterion #768 states for recovery: a bad pack has to be
// survivable without restoring a database backup.
//
// The upgrade in #880 is one-way. Once a newer pack is in, the generation it replaced is gone, so an operator who finds a rule in
// it noisy or wrong has nothing to go back to. This is the other half.
func TestRollback_RestoresTheGenerationAnUpgradeReplaced(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	v1 := packFS(map[string]string{"imported/a.yml": "a v1", "imported/gone-in-v2.yml": "still here"})
	seeded, err := rc.SeedFrom(ctx, v1, ".", nil)
	require.NoError(t, err)
	require.True(t, seeded)

	v2 := packFS(map[string]string{"imported/a.yml": "a v2", "imported/new-in-v2.yml": "new"})
	upgraded, err := rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	require.True(t, upgraded)

	rolled, err := rc.RollbackPackTo(ctx, v2, ".", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, rolled.Restored)

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	got := make(map[string]string, len(docs))
	for _, d := range docs {
		got[d.Path] = string(d.Content)
	}
	assert.Equal(t, "a v1", got["imported/a.yml"], "the rule the bad pack changed is back to what it was")
	assert.Contains(t, got, "imported/gone-in-v2.yml", "a rule the bad pack dropped is running again")
	assert.NotContains(t, got, "imported/new-in-v2.yml", "a rule the bad pack added is gone")
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-rollback-is-not-undone-by-the-next-restart
//
// TestRollback_SurvivesARestart is what makes rollback more than theatre, and the case is easy to miss because it only shows up
// on the NEXT start.
//
// The upgrade decides by comparing what this build's pack would store against what is stored. After a rollback those differ by
// construction, so without a record of the refusal the very next start reinstalls the pack the operator just rejected, and every
// start after that. Their only way to stay on the older generation would be never to restart.
func TestRollback_SurvivesARestart(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	v1 := packFS(map[string]string{"imported/a.yml": "a v1"})
	_, err := rc.SeedFrom(ctx, v1, ".", nil)
	require.NoError(t, err)

	v2 := packFS(map[string]string{"imported/a.yml": "a v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	_, err = rc.RollbackPackTo(ctx, v2, ".", nil)
	require.NoError(t, err)

	// The restart: the same build, running its startup install again.
	reinstalled, err := rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.False(t, reinstalled, "a declined pack must not be reinstalled on the next start")

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	assert.Equal(t, "a v1", string(docs[0].Content), "the deployment is still on the generation the operator rolled back to")
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-later-pack-still-installs-after-a-rollback
//
// TestRollback_DoesNotLatchOffFutureUpgrades pins that declining is about ONE pack rather than about upgrades in general.
//
// A boolean "do not upgrade" would be the obvious implementation and the wrong one: an operator who rolled back once would have to
// remember to switch upgrades back on, and forgetting is silent. A fleet would sit on old detections with nothing saying why.
func TestRollback_DoesNotLatchOffFutureUpgrades(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1"}), ".", nil)
	require.NoError(t, err)
	v2 := packFS(map[string]string{"imported/a.yml": "a v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	_, err = rc.RollbackPackTo(ctx, v2, ".", nil)
	require.NoError(t, err)

	// The next release ships a different pack. It was never declined, so it installs.
	v3 := packFS(map[string]string{"imported/a.yml": "a v3 with the fix"})
	installed, err := rc.UpgradePackFrom(ctx, v3, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.True(t, installed, "declining one pack must not stop the next release from installing")

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	assert.Equal(t, "a v3 with the fix", string(docs[0].Content))
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/an-operator-s-own-rules-survive-a-rollback
//
// TestRollback_LeavesTheOperatorsOwnRulesAlone states what rolling back a PACK means. It restores the shipped generation; it is
// not an undo of the operator's own edits, which an upgrade never touched in the first place.
func TestRollback_LeavesTheOperatorsOwnRulesAlone(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1"}), ".", nil)
	require.NoError(t, err)
	v2 := packFS(map[string]string{"imported/a.yml": "a v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)

	// Written after the upgrade, so a rollback that reverted "everything since" would lose it.
	version, err := rc.Corpus().Version(ctx)
	require.NoError(t, err)
	_, err = rc.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a v2"), Source: api.SourceVendored},
		{Path: "authored/mine.yml", Content: []byte("mine"), Source: api.SourceAuthored},
	})
	require.NoError(t, err)
	_ = version

	_, err = rc.RollbackPackTo(ctx, v2, ".", nil)
	require.NoError(t, err)

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	got := make(map[string]api.Source, len(docs))
	for _, d := range docs {
		got[d.Path] = d.Source
	}
	require.Contains(t, got, "authored/mine.yml", "rolling back a pack must not remove the operator's own rule")
	assert.Equal(t, api.SourceAuthored, got["authored/mine.yml"])
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/rolling-back-with-nothing-retained-is-reported
//
// TestRollback_WithNothingRetainedIsReported covers the ordinary state of a deployment that has never upgraded: it seeded once and
// is still running what it seeded, so there is no earlier generation.
//
// Reported rather than restoring an empty set, which would leave the deployment detecting nothing while reporting success.
func TestRollback_WithNothingRetainedIsReported(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	v1 := packFS(map[string]string{"imported/a.yml": "a v1"})
	_, err := rc.SeedFrom(ctx, v1, ".", nil)
	require.NoError(t, err)

	_, err = rc.RollbackPackTo(ctx, v1, ".", nil)
	require.ErrorIs(t, err, api.ErrNoPreviousPack)

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, docs, 1, "a refused rollback must leave the corpus alone")
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-second-rollback-is-refused
//
// TestRollback_CannotBeRepeatedPastTheRetainedGeneration pins that only one generation is retained. A second rollback has nothing
// behind the first, and saying so is better than reporting success having restored the content already installed.
func TestRollback_CannotBeRepeatedPastTheRetainedGeneration(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1"}), ".", nil)
	require.NoError(t, err)
	v2 := packFS(map[string]string{"imported/a.yml": "a v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)

	_, err = rc.RollbackPackTo(ctx, v2, ".", nil)
	require.NoError(t, err)
	_, err = rc.RollbackPackTo(ctx, v2, ".", nil)
	require.ErrorIs(t, err, api.ErrNoPreviousPack)
}

// spec:rule-content/a-deployment-reports-which-shipped-rule-content-it-is-running/the-rules-that-differ-are-named
//
// TestPackStatus_ReportsWhatDiffersByRule is the "installed versus available" half of #768.
//
// The differences are named by rule IDENTITY rather than by path, because that is what an operator recognises and what their
// per-rule tuning is keyed on. A rule that moved between directories upstream is the same rule to them, and reporting it as one
// removed plus one added would be noise dressed as a change.
func TestPackStatus_ReportsWhatDiffersByRule(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{
		"imported/unchanged.yml": "same",
		"imported/edited.yml":    "before",
		"imported/dropped.yml":   "going away",
	}), ".", nil)
	require.NoError(t, err)

	available := packFS(map[string]string{
		"imported/unchanged.yml": "same",
		"imported/edited.yml":    "after",
		"imported/brand-new.yml": "new",
	})
	status, err := rc.PackStatusFrom(ctx, available, ".", nil, stemIdentity)
	require.NoError(t, err)

	assert.False(t, status.Current(), "the deployment is not running this build's pack")
	assert.Equal(t, []string{"brand-new"}, status.Added)
	assert.Equal(t, []string{"dropped"}, status.Removed)
	assert.Equal(t, []string{"edited"}, status.Changed)
	assert.NotContains(t, status.Changed, "unchanged")
}

// spec:rule-content/a-deployment-reports-which-shipped-rule-content-it-is-running/a-current-deployment-reports-no-difference
//
// TestPackStatus_OnACurrentDeploymentReportsNoDifference is the state most deployments are in, and it has to be reported as
// current rather than as an empty diff that a reader has to interpret.
func TestPackStatus_OnACurrentDeploymentReportsNoDifference(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	pack := packFS(map[string]string{"imported/a.yml": "a", "imported/b.yml": "b"})
	_, err := rc.SeedFrom(ctx, pack, ".", nil)
	require.NoError(t, err)

	status, err := rc.PackStatusFrom(ctx, pack, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.True(t, status.Current(), "a deployment holding this build's pack is current")
	assert.Empty(t, status.Added)
	assert.Empty(t, status.Removed)
	assert.Empty(t, status.Changed)
}

// spec:rule-content/a-deployment-reports-which-shipped-rule-content-it-is-running/their-own-rules-do-not-make-a-deployment-look-out-of-date
//
// TestPackStatus_IgnoresTheOperatorsOwnRules keeps their rules out of the comparison. Adding one must not make a deployment look
// out of date, which is the same property the pack digest carries and for the same reason.
func TestPackStatus_IgnoresTheOperatorsOwnRules(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	pack := packFS(map[string]string{"imported/a.yml": "a"})
	_, err := rc.SeedFrom(ctx, pack, ".", nil)
	require.NoError(t, err)
	_, err = rc.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a"), Source: api.SourceVendored},
		{Path: "authored/mine.yml", Content: []byte("mine"), Source: api.SourceAuthored},
	})
	require.NoError(t, err)

	status, err := rc.PackStatusFrom(ctx, pack, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.Empty(t, status.Removed, "the operator's own rule is not a rule the pack dropped")
	assert.True(t, status.Current(), "writing their own rule must not make the deployment look out of date")
}
