//go:build integration

package tests

import (
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/jmoiron/sqlx"
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
	rc, _ := newRuleContentWithDB(t)
	return rc
}

func newRuleContentWithDB(t *testing.T) (*rulecontentbootstrap.RuleContent, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	return rc, db
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

	rolled, err := rc.RollbackPackTo(ctx, stemIdentity)
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
	_, err = rc.RollbackPackTo(ctx, stemIdentity)
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
	_, err = rc.RollbackPackTo(ctx, stemIdentity)
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

	_, err = rc.RollbackPackTo(ctx, stemIdentity)
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

	_, err = rc.RollbackPackTo(ctx, stemIdentity)
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

	_, err = rc.RollbackPackTo(ctx, stemIdentity)
	require.NoError(t, err)
	_, err = rc.RollbackPackTo(ctx, stemIdentity)
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

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-rule-the-operator-took-over-is-not-taken-back
//
// TestRollback_DoesNotTakeBackARuleTheOperatorNowOwns is the failure review caught, and it has two shapes with the same cause.
//
// A rollback restores the retained shipped documents. If the operator has taken over one of those rules SINCE the upgrade, then
// at the same path the insert is a duplicate-key failure that aborts the whole rollback, and at a different path with the same
// identity it stores two documents for one rule, which makes the corpus refuse to load and takes every rule on the deployment
// down. It is the hazard the install path already filters for, arriving from the other direction.
func TestRollback_DoesNotTakeBackARuleTheOperatorNowOwns(t *testing.T) {
	t.Parallel()

	t.Run("at the same path", func(t *testing.T) {
		t.Parallel()
		rc := newRuleContent(t)
		ctx := t.Context()

		_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "shipped v1"}), ".", nil)
		require.NoError(t, err)
		_, err = rc.UpgradePackFrom(ctx, packFS(map[string]string{"imported/a.yml": "shipped v2"}), ".", nil, stemIdentity)
		require.NoError(t, err)

		// The operator writes their own version, at the path the retained generation also holds.
		version, err := rc.Corpus().Version(ctx)
		require.NoError(t, err)
		_, err = rc.Replace(ctx, []api.Document{
			{Path: "imported/a.yml", Content: []byte("my version"), Source: api.SourceAuthored},
		})
		require.NoError(t, err)
		_ = version

		rolled, err := rc.RollbackPackTo(ctx, stemIdentity)
		require.NoError(t, err, "a rollback must not fail because the operator took over one of the rules")

		docs, err := rc.Corpus().Documents(ctx)
		require.NoError(t, err)
		require.Len(t, docs, 1)
		assert.Equal(t, "my version", string(docs[0].Content), "their rule wins, as it does on the way in")
		assert.Equal(t, api.SourceAuthored, docs[0].Source)
		assert.Contains(t, rolled.Withheld, "imported/a.yml", "they are told which shipped rule was not restored")
	})

	t.Run("at a different path with the same identity", func(t *testing.T) {
		t.Parallel()
		rc := newRuleContent(t)
		ctx := t.Context()

		_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "shipped v1"}), ".", nil)
		require.NoError(t, err)
		_, err = rc.UpgradePackFrom(ctx, packFS(map[string]string{"imported/b.yml": "shipped v2"}), ".", nil, stemIdentity)
		require.NoError(t, err)

		// Their own rule whose identity collides with the retained "a", under a path of their choosing.
		_, err = rc.Replace(ctx, []api.Document{
			{Path: "imported/b.yml", Content: []byte("shipped v2"), Source: api.SourceVendored},
			{Path: "authored/a.yml", Content: []byte("mine"), Source: api.SourceAuthored},
		})
		require.NoError(t, err)

		_, err = rc.RollbackPackTo(ctx, stemIdentity)
		require.NoError(t, err)

		docs, err := rc.Corpus().Documents(ctx)
		require.NoError(t, err)
		seen := make(map[string]string, len(docs))
		for _, d := range docs {
			id := stemIdentity(d.Path)
			if prior, dup := seen[id]; dup {
				t.Fatalf("two documents share the identity %q (%s and %s), so this corpus does not load", id, prior, d.Path)
			}
			seen[id] = d.Path
		}
		assert.Contains(t, seen, "a", "their rule keeps the identity")
		assert.Equal(t, "authored/a.yml", seen["a"], "and the restore did not add a second document for it")
	})
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-corpus-predating-pack-identity-offers-a-rollback
//
// TestRollback_IsOfferedOnACorpusThatPredatesPackIdentity is the inconsistency review found between the two halves of this
// feature, and mutation testing then showed the fix was unpinned.
//
// A corpus stored before pack identity was recorded carries an EMPTY pack_digest, deliberately: it holds some generation and
// nothing wrote down which. Retaining by copying that value left the first upgrade on such a deployment storing the rows while
// recording no identity for them, so the status surface reported no rollback available while a rollback would in fact have
// worked. Deriving the identity from the snapshot closes it, and this is what says so.
func TestRollback_IsOfferedOnACorpusThatPredatesPackIdentity(t *testing.T) {
	t.Parallel()
	rc, db := newRuleContentWithDB(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1"}), ".", nil)
	require.NoError(t, err)

	// The state migration 00002 leaves a populated pre-provenance corpus in: content stored, identity unrecorded.
	_, err = db.ExecContext(ctx, "UPDATE rule_corpus_meta SET pack_digest = '' WHERE id = 1")
	require.NoError(t, err)

	v2 := packFS(map[string]string{"imported/a.yml": "a v2"})
	upgraded, err := rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	require.True(t, upgraded)

	status, err := rc.PackStatusFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	require.NotEmpty(t, status.Previous,
		"the retained generation must have an identity, or the status surface reports no rollback while one would work")

	// And the two halves agree: what status offers, rollback delivers.
	_, err = rc.RollbackPackTo(ctx, stemIdentity)
	require.NoError(t, err)
	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	assert.Equal(t, "a v1", string(docs[0].Content))
}

// TestPackLifecycle_RefusesAnUnreadableStoredSource covers the read every path here shares. A row written by a version that knew
// a provenance this one does not must stop the operation rather than be interpreted as one of today's two values, and that has to
// hold for reading status and for rolling back as well as for installing, which is where it was already pinned.
func TestPackLifecycle_RefusesAnUnreadableStoredSource(t *testing.T) {
	t.Parallel()

	corrupt := func(t *testing.T) (*rulecontentbootstrap.RuleContent, fstest.MapFS) {
		t.Helper()
		rc, db := newRuleContentWithDB(t)
		ctx := t.Context()
		pack := packFS(map[string]string{"imported/a.yml": "a"})
		_, err := rc.SeedFrom(ctx, pack, ".", nil)
		require.NoError(t, err)
		// An upgrade first, so a generation is retained and the rollback below gets past its own emptiness check.
		_, err = rc.UpgradePackFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v2"}), ".", nil, stemIdentity)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, "UPDATE rule_corpus_documents SET source = ? WHERE path = ?", "community", "imported/a.yml")
		require.NoError(t, err)
		return rc, pack
	}

	t.Run("reading pack status", func(t *testing.T) {
		t.Parallel()
		rc, pack := corrupt(t)
		_, err := rc.PackStatusFrom(t.Context(), pack, ".", nil, stemIdentity)
		require.ErrorIs(t, err, api.ErrUnknownSource)
	})

	t.Run("rolling back", func(t *testing.T) {
		t.Parallel()
		rc, _ := corrupt(t)
		_, err := rc.RollbackPackTo(t.Context(), stemIdentity)
		require.ErrorIs(t, err, api.ErrUnknownSource)
	})
}

// TestPackStatusFrom_ARootThatDoesNotExistIsAnError pins that the bootstrap surfaces a bad walk rather than reporting a
// deployment current against a pack it could not read. Reporting "current" there would be the worst available answer: it is the
// one an operator would act on by doing nothing.
func TestPackStatusFrom_ARootThatDoesNotExistIsAnError(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	_, err := rc.PackStatusFrom(t.Context(), fstest.MapFS{}, "no-such-root", nil, stemIdentity)
	require.Error(t, err)
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-generation-with-no-shipped-rules-is-still-restorable
//
// TestRollback_CanUndoAnUpgradeOntoAnAuthoredOnlyCorpus covers the case counting rows gets wrong.
//
// A corpus holding only the operator's rules retains a generation with ZERO shipped documents when a pack is first installed onto
// it. That generation exists and has an identity (the digest of nothing, which is a real value rather than empty), so counting
// retained rows reports it as "never upgraded" and refuses the one rollback that would undo the upgrade. The recorded digest is
// what distinguishes the two, which is what the column is for.
func TestRollback_CanUndoAnUpgradeOntoAnAuthoredOnlyCorpus(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	// An authored-only corpus: their rules, no shipped content at all.
	_, err := rc.Replace(ctx, []api.Document{
		{Path: "authored/mine.yml", Content: []byte("mine"), Source: api.SourceAuthored},
	})
	require.NoError(t, err)

	installed, err := rc.UpgradePackFrom(ctx, packFS(map[string]string{"imported/a.yml": "a"}), ".", nil, stemIdentity)
	require.NoError(t, err)
	require.True(t, installed, "the pack must install onto a corpus that held no shipped content")

	rolled, err := rc.RollbackPackTo(ctx, stemIdentity)
	require.NoError(t, err, "the generation retained was empty, not absent, so this rollback must be possible")
	assert.NotEmpty(t, rolled.Restored, "an empty generation still has an identity")

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	require.Len(t, docs, 1, "the shipped rule the upgrade added is gone again")
	assert.Equal(t, "authored/mine.yml", docs[0].Path, "and their own rule is what remains")
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-rollback-holds-against-a-build-differing-in-an-override
//
// TestRollback_HoldsAgainstAPackDifferingOnlyInAnOverriddenRule is the way a restart could undo a rollback, which review found.
//
// Declining on the pack AS SHIPPED looks equivalent to declining on what it would store, and is not. On a deployment holding an
// override those two digests differ, so a build whose pack differs from the declined one ONLY in the overridden rule does not
// match the recorded decline: it installs the rest of itself and the rollback is undone on the next start, silently. The
// comparison has to be like-for-like against what an install would actually store.
func TestRollback_HoldsAgainstAPackDifferingOnlyInAnOverriddenRule(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1", "imported/b.yml": "b v1"}), ".", nil)
	require.NoError(t, err)

	// The operator takes over rule "a", then a newer pack lands and is rolled back.
	_, err = rc.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("mine"), Source: api.SourceAuthored},
		{Path: "imported/b.yml", Content: []byte("b v1"), Source: api.SourceVendored},
	})
	require.NoError(t, err)

	v2 := packFS(map[string]string{"imported/a.yml": "a v2", "imported/b.yml": "b v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	_, err = rc.RollbackPackTo(ctx, stemIdentity)
	require.NoError(t, err)

	// A build whose pack differs from the declined one only in the rule the operator owns. It would store exactly what the
	// declined pack would store, so it must not be installed.
	v2b := packFS(map[string]string{"imported/a.yml": "a v2 tweaked", "imported/b.yml": "b v2"})
	reinstalled, err := rc.UpgradePackFrom(ctx, v2b, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.False(t, reinstalled, "a pack that would store the declined content must not undo the rollback")

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	for _, d := range docs {
		if d.Path == "imported/b.yml" {
			assert.Equal(t, "b v1", string(d.Content), "the deployment is still on the generation it rolled back to")
		}
	}
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-rollback-holds-after-the-operator-edits-shipped-content
//
// TestRollback_HoldsAfterTheOperatorEditsShippedContent is the third way a restart could undo a rollback, and the last of a set
// worth stating together because each looked like the obvious answer and each was reachable.
//
// The decline has to name the generation the UPGRADE installed. Three narrower answers each fail: the pack a build carries
// differs from what gets stored on a deployment holding an override; the running process's own pack is wrong when a rollback is
// served by an older replica mid-deployment; and the corpus's current digest is recomputed by operator edits, so deleting a
// shipped rule between the upgrade and the rollback records a decline describing content no build ever shipped. This covers the
// third: the deletion must not let the rejected generation come back.
func TestRollback_HoldsAfterTheOperatorEditsShippedContent(t *testing.T) {
	t.Parallel()
	rc := newRuleContent(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1", "imported/b.yml": "b v1"}), ".", nil)
	require.NoError(t, err)

	v2 := packFS(map[string]string{"imported/a.yml": "a v2", "imported/b.yml": "b v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)

	// The operator deletes one of the shipped rules the bad pack brought, which recomputes the corpus digest.
	_, err = rc.Replace(ctx, []api.Document{
		{Path: "imported/a.yml", Content: []byte("a v2"), Source: api.SourceVendored},
	})
	require.NoError(t, err)

	_, err = rc.RollbackPackTo(ctx, stemIdentity)
	require.NoError(t, err)

	reinstalled, err := rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.False(t, reinstalled,
		"an edit between the upgrade and the rollback must not let the rejected generation reinstall")

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	for _, d := range docs {
		assert.NotContains(t, string(d.Content), "v2", "%s came from the generation the operator rejected", d.Path)
	}
}

// spec:rule-content/a-replaced-generation-of-shipped-rule-content-can-be-restored/a-deployment-with-no-recorded-generation-records-one-on-start
//
// TestUpgradePack_RecordsTheInstalledGenerationOnANoOpStart covers the deployment that upgraded before its installed generation
// was recorded at all, and mutation testing is what surfaced it: the conditional write on the no-op path looked like an
// optimisation and is load-bearing.
//
// Such a deployment holds this build's content with nothing saying which generation that is. A start that changes no documents
// still has to write it down, because otherwise a rollback has no name for what it is declining, the decline is recorded empty,
// and the next start reinstalls the generation the operator rejected. That is the original defect, reached by a different route.
func TestUpgradePack_RecordsTheInstalledGenerationOnANoOpStart(t *testing.T) {
	t.Parallel()
	rc, db := newRuleContentWithDB(t)
	ctx := t.Context()

	_, err := rc.SeedFrom(ctx, packFS(map[string]string{"imported/a.yml": "a v1"}), ".", nil)
	require.NoError(t, err)
	v2 := packFS(map[string]string{"imported/a.yml": "a v2"})
	_, err = rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)

	// The state a deployment that upgraded under an older build is in: content installed, generation unrecorded.
	_, err = db.ExecContext(ctx, "UPDATE rule_corpus_meta SET installed_pack_digest = '' WHERE id = 1")
	require.NoError(t, err)

	// A start that moves no documents. It must still record which generation is installed.
	changed, err := rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	require.False(t, changed, "the content already matches, so nothing should move")

	var installed string
	require.NoError(t, db.GetContext(ctx, &installed, "SELECT installed_pack_digest FROM rule_corpus_meta WHERE id = 1"))
	require.NotEmpty(t, installed, "a start must record the generation it finds installed, or a rollback cannot name it")

	// And the consequence that matters: the rollback now declines something, so a restart does not undo it.
	_, err = rc.RollbackPackTo(ctx, stemIdentity)
	require.NoError(t, err)
	reinstalled, err := rc.UpgradePackFrom(ctx, v2, ".", nil, stemIdentity)
	require.NoError(t, err)
	assert.False(t, reinstalled, "the rejected generation must not reinstall")
}
