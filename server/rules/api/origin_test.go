package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/rules/api"
)

// The attribution constants are pinned to their literals on purpose (issue #765).
//
// Normally a test that restates a constant is a change-detector worth deleting. This one is not, because the value IS the
// artifact: the imported corpus ships under the Detection Rule License, whose attribution requirement is satisfied by the exact
// string a reader sees next to a match. A test comparing OriginOf's output against the constant cannot notice the constant
// becoming wrong, which is precisely how a mutation of ProjectOrigin to "SigmaHQ" survived the catalog-level assertions: every
// caller moved with it. Pinning the literal here is the one place that mutation is visible, so changing either value should be a
// deliberate edit to this file rather than a silent consequence of a rename.
func TestAttributionConstantsArePinned(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "Fleet EDR", api.ProjectOrigin, "the credit shown for every rule this project wrote")
	assert.Equal(t, "unknown upstream", api.UnknownOrigin, "the credit shown for a rule that declares a source but names nobody")

	// The two populations have to stay distinguishable by their attribution, which is the job the value does on the alert view.
	// Naming ourselves after an upstream project would satisfy every "is it non-empty" assertion while crediting the wrong party.
	assert.NotEqual(t, api.ProjectOrigin, api.UnknownOrigin)
	assert.NotContains(t, api.ProjectOrigin, "SigmaHQ", "our own credit must not be confusable with the vendored corpus's")
}

// spec:server-detection-rules-engine/an-alert-credits-the-author-of-the-rule-that-raised-it/a-rule-declaring-an-upstream-but-naming-no-author-is-not-claimed-as-ours
//
// TestOriginOf covers the three shapes a rule can present, since the difference between them is a licence question rather than a
// formatting one: crediting ourselves for someone else's rule is the failure that matters.
func TestOriginOf(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rule api.Rule
		want string
	}{
		// silentRule is the package's existing "declares nothing optional" stub, which is exactly a hand-written rule.
		{"a rule declaring no source is ours", silentRule{}, api.ProjectOrigin},
		{"a rule naming an upstream keeps it", creditingRule{origin: "SigmaHQ, by Someone"}, "SigmaHQ, by Someone"},
		{"a rule declaring a source but naming nobody is not claimed as ours", creditingRule{origin: ""}, api.UnknownOrigin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, api.OriginOf(tc.rule))
		})
	}
}

// creditingRule is a Rule that names where it came from, standing in for a rule from the imported corpus.
type creditingRule struct {
	api.Rule
	origin string
}

func (r creditingRule) Origin() string { return r.origin }
