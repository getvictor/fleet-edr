package catalog

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// Regression fixtures for the whole catalog (issue #773).
//
// At twelve hand-written rules a reviewer could hold the catalog in their head. At seventy-eight they cannot, and a rule that
// quietly stops matching looks exactly like a rule nothing tripped. The fixtures are what turn that silence into a failure: each
// one is a committed event sequence with the finding it must produce, replayed through the real decode / graph / evaluate path.
//
// Three tests, deliberately separate, because they fail for different reasons and a reader should be able to tell which happened:
//
//   - TestEveryCatalogRuleHasARegressionFixture is the COVERAGE gate. It answers "does every rule have one".
//   - TestCatalogFixturesStillFire is the REGRESSION gate. It answers "does every fixture still produce what it claims".
//   - TestNoOrphanFixtureDirectories is the HYGIENE gate. It answers "does every fixture directory still name a rule".
//
// Folding them together would report a brand-new rule with no fixture and a shipped rule that broke as the same failure.

// fixtureResolver is the exclusion resolver every rule is built with here.
//
// One resolver for the whole catalog rather than a bespoke one per rule, because these fixtures are replayed by a loop over
// New() and a rule cannot be handed its own construction from inside that loop. The entries below are therefore a published part
// of the fixture contract: a fixture that wants to prove the exclusion path suppresses a finding uses one of these values, and
// its rule's own doc names it.
func fixtureResolver() api.ExclusionResolver {
	return &fakeExclusions{entries: []fakeExcl{
		// sudoers_tamper/negative_writer_allowlisted.json writes to sudoers from this path and must stay silent.
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/usr/local/bin/fixture-allowed-writer"},
		// privilege_launchd_plist_write/negative_allowlisted_team.json is signed by this synthetic team.
		{ruleID: "privilege_launchd_plist_write", matchType: api.ExclusionMatchTeamID, value: "FIXTURE-ALLOW"},
	}}
}

// pendingFixtures is EMPTY, and that is the point of issue #773: every rule the server registers has a positive regression
// fixture, so the acceptance criterion is now a property the gate asserts rather than a list of exceptions.
//
// It is kept as an empty slice rather than deleted so the gate below keeps the same shape: if a rule ever has to be exempted, the
// exemption is a visible entry in a list that CI compares exactly, not a skip nobody sees. Adding one should be argued for in the
// PR that does it.
var pendingFixtures = []string{}

// TestEveryCatalogRuleHasARegressionFixture is the coverage half: every rule the server registers carries at least one fixture
// that says it fires, or is on the shrinking pending list.
func TestEveryCatalogRuleHasARegressionFixture(t *testing.T) {
	t.Parallel()

	var missing []string
	for _, r := range New(fixtureResolver()) {
		if !hasPositiveFixture(t, r.ID()) {
			missing = append(missing, r.ID())
		}
	}
	// ElementsMatch rather than Equal, because Equal separates a nil slice from an empty one: with the list emptied, a run where
	// nothing is missing produced nil and failed against []string{}. A gate that only works while it still has exceptions in it
	// would have broken for whoever struck off the last rule, which is the moment it most needs to keep working.
	assert.ElementsMatch(t, pendingFixtures, missing,
		"rules without a positive regression fixture changed. A rule ADDED here needs fixtures/<rule_id>/positive_*.json; a rule "+
			"REMOVED from the pending list needs striking off it. Do not grow the list.")
}

// spec:server-detection-rules-engine/a-converted-rule-carries-its-logic-in-its-file/a-converted-rule-detects-what-it-detected-before
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-suspicious-process-resolves-a-domain-and-connects-to-the-resolved-address
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-browser-resolving-and-connecting-to-an-ordinary-domain-does-not-fire
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-suspicious-process-that-connects-to-an-address-it-never-resolved-does-not-fire
//
// TestCatalogFixturesStillFire is the regression half: every fixture that exists still produces exactly the findings it records.
//
// Driven off the catalog rather than off the fixture directories, so a fixture directory named after a rule that no longer exists
// is caught as a stale directory rather than silently skipped.
//
// The scenario markers above moved here from the per-rule replay tests this loop replaced, ALL of them: leaving any behind would
// attach a fixture scenario to whichever test happened to follow it, which for the DNS rule was its ATT&CK mapping test. Each
// still holds, and the first holds wider, since the converted-rule scenario is now asserted for every converted rule rather than
// for one. The three beacon scenarios are carried by the positive and two negative fixtures under fixtures/dns_c2_beacon/, which
// this loop replays. Replay lives in exactly one place so a rule cannot be built two different ways against the same fixtures.
func TestCatalogFixturesStillFire(t *testing.T) {
	t.Parallel()

	for _, r := range New(fixtureResolver()) {
		dir := filepath.Join("fixtures", r.ID())
		if _, err := os.Stat(dir); err != nil {
			continue // covered by the coverage gate above; not this test's failure to report.
		}
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			detectiontestkit.Replay(t, r, dir)
		})
	}
}

// TestNoOrphanFixtureDirectories catches the reverse of the coverage gate: a fixture directory whose rule is gone.
//
// Without this a renamed or deleted rule leaves its fixtures behind, and they stop being replayed by anything while still looking
// like coverage to a reader browsing the tree.
func TestNoOrphanFixtureDirectories(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("fixtures")
	require.NoError(t, err, "read fixtures dir")

	known := map[string]bool{}
	for _, r := range New(nil) {
		known[r.ID()] = true
	}
	for _, e := range entries {
		if !e.IsDir() {
			// A JSON file sitting at the root of fixtures/ belongs to no rule, so nothing replays it, yet FixturePaths("fixtures")
			// hands it to the dispatch-equivalence gate. That asymmetry is a place a fixture can hide: it looks like corpus, it
			// counts as corpus for one gate, and no rule is ever asserted against it.
			assert.NotEqualf(t, ".json", filepath.Ext(e.Name()),
				"fixtures/%s belongs to no rule and is replayed by nothing: move it under fixtures/<rule_id>/", e.Name())
			continue
		}
		assert.True(t, known[e.Name()],
			"fixtures/%s names no rule in the catalog: delete it, or rename it to the rule it belongs to", e.Name())
	}
}

// hasPositiveFixture reports whether the rule has at least one fixture asserting it FIRES.
//
// A directory of only negative cases is not coverage: it proves the rule stays quiet, which a rule that has stopped working
// entirely also does. The positive case is the one that fails when a rule silently dies, which is the whole point of #773.
func hasPositiveFixture(t *testing.T, ruleID string) bool {
	t.Helper()

	// Discovery and decoding come from the replay harness itself, so the coverage gate can only ever look at exactly the files
	// the regression gate runs. When this walked its own way, a nested fixture was replayed while being reported as uncovered.
	paths, err := detectiontestkit.FixturePaths(filepath.Join("fixtures", ruleID))
	if errors.Is(err, fs.ErrNotExist) {
		return false // no directory at all: uncovered, which is the coverage gate's business to report.
	}
	require.NoError(t, err)

	// Every path is scanned rather than returning at the first positive, because the naming assertion below has to see all of
	// them. Short-circuiting checked at most one file, so `positive_top.json` followed by `z/negative_misnamed.json` left the
	// second one unexamined even though it expects findings.
	found := false
	for _, path := range paths {
		c, err := detectiontestkit.LoadFixture(path)
		require.NoError(t, err)
		if len(c.ExpectedFindings) == 0 {
			// The inverse of the check below, and the more dangerous half: a positive_* that expects nothing is silently a
			// negative, and if the rule has another positive every gate stays green while the case that file was written to
			// prove has quietly stopped proving it.
			assert.Falsef(t, strings.HasPrefix(filepath.Base(path), "positive_"),
				"%s is named positive_* but expects no findings", path)
			continue
		}
		found = true
		// The naming convention is not load-bearing (the coverage assertion is), but a positive case named negative_* is a
		// mistake worth catching at the point where someone is most likely to make it: a reader scanning the directory reads
		// the prefix, not the JSON.
		assert.Falsef(t, strings.HasPrefix(filepath.Base(path), "negative_"),
			"%s expects findings but is named negative_*", path)
	}
	return found
}
