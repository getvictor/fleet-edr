package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVendoredCorpus_NoRuleDiscriminatesNothing is what keeps the undiscriminating-rule warning worth having.
//
// A warning that fires on content the product already ships teaches operators to ignore it, and then it reports nothing on the
// day someone really does store a rule matching everything. So the claim under test is not about the predicate's logic (that is
// covered where the predicate lives) but about its precision against real content: none of the rules this repository vendors
// trips it.
//
// It also guards the direction a future change is most likely to break. Broadening the predicate to catch "obviously too broad"
// shapes is the tempting edit, and this test is what says whether that broadening has started reporting rules an author wrote
// deliberately.
func TestVendoredCorpus_NoRuleDiscriminatesNothing(t *testing.T) {
	t.Parallel()

	rules, _, err := LoadCorpus(ImportedCorpusFS(), CorpusRoot)
	require.NoError(t, err)
	require.NotEmpty(t, rules, "an empty corpus would make this pass by having nothing to check")

	inspected := 0
	for _, r := range rules {
		imported, ok := r.(*importedRule)
		if !ok || imported.detection == nil {
			continue
		}
		inspected++
		assert.Empty(t, imported.detection.UndiscriminatingSearches(),
			"vendored rule %s has a search that matches everything, so the warning would fire on shipped content", imported.id)
	}
	require.NotZero(t, inspected, "no rule was actually inspected, so this test proved nothing")
}
