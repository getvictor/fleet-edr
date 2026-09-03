package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:rule-content/rule-content-is-stored-and-is-the-source-the-catalog-loads-from/the-catalog-loads-the-stored-content
//
// TestLoadCorpus_MatchesTheEmbeddedLoad is the parse half of the runtime-corpus claim (issue #766).
//
// The corpus can now come from storage instead of the binary, and the whole change is only worth making if loading it that way
// yields the same detections. This pins the equivalence at the seam that actually differs: a supplied fs.FS versus the package's
// embedded one. Storage losslessness is proven separately in the rulecontent context, so between the two there is no untested gap.
//
// Compared on rule IDS and their ORDER, not just the count. Order is observable: it is what the operator-facing catalog and the
// generated rule reference list rules in, so a corpus that loaded the same rules in a different order would make those surfaces
// depend on how the corpus was stored.
func TestLoadCorpus_MatchesTheEmbeddedLoad(t *testing.T) {
	t.Parallel()

	supplied, rejected, err := LoadCorpus(ImportedCorpusFS(), CorpusRoot)
	require.NoError(t, err, "the vendored corpus must load through the injectable path too")

	embedded := MustLoadImported()
	require.NotEmpty(t, embedded, "a corpus of zero rules would make this assertion vacuous")

	assert.Equal(t, ruleIDsOf(embedded), ruleIDsOf(supplied),
		"a supplied FS must yield the same rules in the same order as the embedded load")
	assert.Len(t, rejected, len(ImportedRejections()),
		"and must refuse the same upstream rules, so a refusal is not lost by going through storage")
}

// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/content-that-fails-to-load-does-not-stop-detection
//
// TestLoadCorpus_ReportsAFailureRatherThanPanicking pins the difference between the two loaders.
//
// The embedded path panics, correctly: a malformed vendored file is a build mistake and failing at start-up is what catches it
// before an operator does. A STORED corpus is different in kind. It can be changed without a release, so a malformed one is a
// runtime condition, and the decision about it (keep serving the previous good set) belongs to the caller rather than to a panic
// inside the loader.
func TestLoadCorpus_ReportsAFailureRatherThanPanicking(t *testing.T) {
	t.Parallel()

	// A directory that holds no rule files at all: the loader has nothing to read under the root it was given.
	empty, rejected, err := LoadCorpus(ImportedCorpusFS(), "does-not-exist")

	require.Error(t, err, "an unreadable corpus root must be returned, not panicked, so a caller can fall back")
	assert.Empty(t, empty)
	assert.Empty(t, rejected)
}

func ruleIDsOf(rules []api.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID())
	}
	return out
}
