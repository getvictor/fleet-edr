//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"

	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

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
