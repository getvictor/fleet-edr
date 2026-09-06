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

// shippedDoc is one document as a pack ships it.
func shippedDoc(path, content string) api.Document {
	return api.Document{Path: path, Content: []byte(content), Source: api.SourceVendored}
}

// pathsOf returns the stored paths mapped to their source, for asserting what an upgrade left behind.
func pathsOf(t *testing.T, docs []api.Document) map[string]api.Source {
	t.Helper()
	out := make(map[string]api.Source, len(docs))
	for _, d := range docs {
		out[d.Path] = d.Source
	}
	return out
}

// contentAt returns the stored content at one path.
func contentAt(t *testing.T, docs []api.Document, path string) string {
	t.Helper()
	for _, d := range docs {
		if d.Path == path {
			return string(d.Content)
		}
	}
	t.Fatalf("no document stored at %s", path)
	return ""
}

// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/a-newer-pack-replaces-the-shipped-content
// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/an-operator-s-own-rule-survives
//
// TestUpgradePack_ReplacesTheShippedHalfOnly is the acceptance criterion issue #768 leads with, stated as the property that makes
// upgrading safe: a newer pack must be installable without costing an operator the rules they wrote.
//
// The seed cannot do this. It acts only on an EMPTY corpus, deliberately, because a seed that ran on every boot would overwrite an
// operator's work on the next restart. That leaves a seeded deployment holding its first generation of shipped rules forever, so
// the upgrade is a separate operation with a narrower blast radius: the shipped half, and nothing else.
func TestUpgradePack_ReplacesTheShippedHalfOnly(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	version, err := s.Replace(ctx, []api.Document{
		shippedDoc("imported/a.yml", "a v1"),
		shippedDoc("imported/gone.yml", "removed upstream"),
	})
	require.NoError(t, err)

	// The operator's own rule, stored the way the authoring surface stores one.
	_, err = s.PutDocument(ctx, api.Document{Path: "authored/mine.yml", Content: []byte("mine")}, version)
	require.NoError(t, err)

	upgraded, _, err := s.UpgradeVendoredTo(ctx, []api.Document{
		shippedDoc("imported/a.yml", "a v2"),
		shippedDoc("imported/new.yml", "new detection"),
	})
	require.NoError(t, err)
	require.True(t, upgraded)

	stored, err := s.Documents(ctx)
	require.NoError(t, err)
	got := pathsOf(t, stored)

	assert.Equal(t, api.SourceVendored, got["imported/a.yml"], "a rule the new pack still ships stays shipped")
	assert.Equal(t, "a v2", contentAt(t, stored, "imported/a.yml"), "and carries the new pack's content")
	assert.Equal(t, api.SourceVendored, got["imported/new.yml"], "a rule the new pack adds is installed")
	assert.NotContains(t, got, "imported/gone.yml", "a rule the new pack drops is removed, not left running")

	// The one that matters most: an upgrade is not a licence to discard the operator's work.
	require.Contains(t, got, "authored/mine.yml", "the operator's own rule must survive a pack upgrade")
	assert.Equal(t, api.SourceAuthored, got["authored/mine.yml"], "and must still be theirs")
	assert.Equal(t, "mine", contentAt(t, stored, "authored/mine.yml"))
}

// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/a-path-the-operator-has-taken-over-stays-theirs
//
// TestUpgradePack_LeavesAPathTheOperatorTookOver covers the case the path rule in #874 creates. Writing over a shipped rule makes
// that document the operator's, so a pack that still ships the same path must not quietly take it back: they would lose the rule
// they wrote, and the credit on it would revert to the upstream project that did not write it.
func TestUpgradePack_LeavesAPathTheOperatorTookOver(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	version, err := s.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "shipped v1")})
	require.NoError(t, err)

	// The operator writes their own version of a shipped rule. It keeps the path, and the row becomes theirs.
	_, err = s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("my version")}, version)
	require.NoError(t, err)

	_, _, err = s.UpgradeVendoredTo(ctx, []api.Document{shippedDoc("imported/a.yml", "shipped v2")})
	require.NoError(t, err)

	stored, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Equal(t, "my version", contentAt(t, stored, "imported/a.yml"),
		"a path the operator took over stays theirs across an upgrade")
	assert.Equal(t, api.SourceAuthored, pathsOf(t, stored)["imported/a.yml"])
}

// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/installing-the-same-content-again-changes-nothing
// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/installing-is-unaffected-by-an-operator-s-override
//
// TestUpgradePack_IsIdempotent is what keeps this off the critical path of an ordinary restart, and the case it protects is not
// the obvious one.
//
// Comparing the BUILD's pack digest against the recorded one would look equivalent and is not: the recorded digest describes the
// shipped content actually held, so on a deployment that has overridden one shipped rule it can never equal the build's own pack
// digest. Triggering on that comparison would reinstall on every boot, bump the version each time, and make every replica reload a
// corpus that did not change. The comparison is therefore between what this pack WOULD store and what is stored.
func TestUpgradePack_IsIdempotent(t *testing.T) {
	t.Parallel()

	t.Run("re-installing the same pack writes nothing", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		ctx := t.Context()
		pack := []api.Document{shippedDoc("imported/a.yml", "a"), shippedDoc("imported/b.yml", "b")}

		_, _, err := s.UpgradeVendoredTo(ctx, pack)
		require.NoError(t, err)
		versionAfterFirst, err := s.Version(ctx)
		require.NoError(t, err)

		upgraded, _, err := s.UpgradeVendoredTo(ctx, pack)
		require.NoError(t, err)
		assert.False(t, upgraded, "the same pack must not reinstall")

		versionAfterSecond, err := s.Version(ctx)
		require.NoError(t, err)
		assert.Equal(t, versionAfterFirst, versionAfterSecond,
			"a no-op upgrade must not bump the version, or every replica reloads a corpus that did not change")
	})

	t.Run("and still writes nothing when the operator has overridden a shipped rule", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		ctx := t.Context()
		pack := []api.Document{shippedDoc("imported/a.yml", "a"), shippedDoc("imported/b.yml", "b")}

		version, err := s.Replace(ctx, pack)
		require.NoError(t, err)
		_, err = s.PutDocument(ctx, api.Document{Path: "imported/a.yml", Content: []byte("mine")}, version)
		require.NoError(t, err)
		before, err := s.Version(ctx)
		require.NoError(t, err)

		// This is the boot loop the naive comparison would produce: the stored digest cannot equal the build's pack digest here.
		upgraded, _, err := s.UpgradeVendoredTo(ctx, pack)
		require.NoError(t, err)
		assert.False(t, upgraded, "an override must not make the same pack look like a newer one")

		after, err := s.Version(ctx)
		require.NoError(t, err)
		assert.Equal(t, before, after, "an overridden deployment must not reinstall on every boot")
	})
}

// TestUpgradePack_RecordsWhatItInstalled keeps the recorded identity honest after an upgrade, the same claim the seed and the
// whole-corpus replace already carry: what is recorded is the digest of the shipped content actually stored.
func TestUpgradePack_RecordsWhatItInstalled(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	_, _, err := s.UpgradeVendoredTo(ctx, []api.Document{shippedDoc("imported/a.yml", "a")})
	require.NoError(t, err)

	recorded, err := s.PackDigest(ctx)
	require.NoError(t, err)
	stored, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Equal(t, api.PackDigest(api.VendoredDocuments(stored)), recorded,
		"the recorded identity must be the digest of the shipped content actually installed")
}

// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/a-pack-declaring-authored-content-is-refused
//
// TestUpgradePack_RefusesAPackClaimingAuthoredContent guards the one input that would let an upgrade launder provenance. A pack is
// shipped content by definition, so a document in one declaring itself the operator's is a contradiction rather than an edge case,
// and accepting it would let a build install rows that no operator wrote but that carry no upstream credit.
func TestUpgradePack_RefusesAPackClaimingAuthoredContent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	_, err := s.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "a")})
	require.NoError(t, err)

	_, _, err = s.UpgradeVendoredTo(ctx, []api.Document{
		{Path: "imported/b.yml", Content: []byte("b"), Source: api.SourceAuthored},
	})
	require.ErrorIs(t, err, api.ErrUnknownSource)

	stored, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, stored, 1, "a refused upgrade must not have changed the corpus")
}

// spec:rule-content/the-shipped-rule-content-in-a-build-is-installed-over-the-stored-shipped-content/a-build-carrying-no-shipped-content-leaves-the-corpus-alone
//
// TestUpgradePackFrom_ABuildWithNoRulesLeavesTheStoredPackAlone covers the input where the safe reading differs from seeding's.
//
// The seed treats an empty source as a legitimately empty corpus, and can, because there is nothing to lose. Here there is: an
// empty pack read as an instruction would delete every shipped rule the deployment is running, leaving it detecting nothing while
// reporting a successful start. The only safe reading is that this build's embedded content is wrong.
func TestUpgradePackFrom_ABuildWithNoRulesLeavesTheStoredPackAlone(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := full.Open(t)
	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)

	_, err = rc.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "a"), shippedDoc("imported/b.yml", "b")})
	require.NoError(t, err)

	upgraded, err := rc.UpgradePackFrom(ctx, fstest.MapFS{}, ".", nil)
	require.NoError(t, err, "an empty build is not an error, it is a build that has nothing to install")
	assert.False(t, upgraded)

	docs, err := rc.Corpus().Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, docs, 2, "an empty pack must not be read as an instruction to delete every shipped rule")
}
