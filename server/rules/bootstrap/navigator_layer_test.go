package bootstrap_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

// repoRoot ascends from the test's working directory (the bootstrap package dir under `go test`) until it finds the module's
// go.mod, so the drift test can locate the repo-root docs/ artifact regardless of where the test binary runs.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "ascended to the filesystem root without finding go.mod")
		dir = parent
	}
}

// TestNavigatorLayerArtifactInSync is the CI drift gate for the committed ATT&CK Navigator layer. It rebuilds the layer from the
// live rule catalog with the same builder and marshaler the generator (tools/gen-attack-layer) uses, then byte-compares against
// the checked-in docs/attack-navigator-layer.json. Adding, removing, or re-mapping a rule's techniques without regenerating the
// file fails here. This test lives in server/rules/ rather than the tool package because CI's Go test job globs ./server/... and
// does not descend into ./tools/...; placing the gate here is what makes it actually run on every PR.
func TestNavigatorLayerArtifactInSync(t *testing.T) {
	t.Parallel()

	layer := rulesapi.BuildNavigatorLayer(rulesbootstrap.CatalogOnly().List())
	want, err := rulesapi.MarshalNavigatorLayerIndented(layer)
	require.NoError(t, err)

	path := filepath.Join(repoRoot(t), "docs", "attack-navigator-layer.json")
	got, err := os.ReadFile(path) //nolint:gosec // test-controlled path under the repo
	require.NoError(t, err, "read committed Navigator layer; run `task docs:attack-layer` to generate it")

	require.Equal(t, string(want), string(got),
		"docs/attack-navigator-layer.json is stale: run `task docs:attack-layer` and commit the result")
}

// techniqueTablePath is the vendored ATT&CK extract the Coverage page renders names and tactic grouping from.
const techniqueTablePath = "ui/src/components/attack-techniques.generated.ts"

// generatedTechniqueIDs returns the technique ids the vendored table defines, and the ATT&CK version it was cut from.
func generatedTechniqueIDs(t *testing.T) (ids map[string]bool, version string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), techniqueTablePath)) //nolint:gosec // test-controlled path under the repo
	require.NoError(t, err, "read the vendored ATT&CK table; regenerate with `task attack:table`")

	ids = map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s{2}"(T\d{4}(?:\.\d{3})?)":`).FindAllStringSubmatch(string(raw), -1) {
		ids[m[1]] = true
	}
	if v := regexp.MustCompile(`ATTACK_VERSION = "([^"]+)"`).FindStringSubmatch(string(raw)); v != nil {
		version = v[1]
	}
	return ids, version
}

// TestTechniqueTableCoversEveryMappedTechnique is the drift gate the hand-maintained catalog never had.
//
// That catalog held 12 entries while the rule corpus referenced 65 techniques, so 53 rendered on the Coverage page as
// "Unmapped" with the raw id for a name. Nothing failed; the file's own comment called the fallback "a loud-but-not-broken
// hint that this file needs an update", and it went unnoticed for as long as it took someone to read the page. A rule that
// starts covering a technique the table does not define now fails here instead.
func TestTechniqueTableCoversEveryMappedTechnique(t *testing.T) {
	t.Parallel()

	layer := rulesapi.BuildNavigatorLayer(rulesbootstrap.CatalogOnly().List())
	require.NotEmpty(t, layer.Techniques, "a table gate over an empty layer would pass without checking anything")

	table, _ := generatedTechniqueIDs(t)
	require.NotEmpty(t, table, "the vendored table parsed to nothing, so this gate would pass vacuously")

	var missing []string
	for _, tech := range layer.Techniques {
		if !table[tech.TechniqueID] {
			missing = append(missing, tech.TechniqueID)
		}
	}
	require.Empty(t, missing,
		"these techniques are covered by a rule but absent from %s, so the Coverage page renders them as Unmapped; "+
			"regenerate the table with `task attack:table`", techniqueTablePath)
}

// TestTechniqueTableMatchesTheLayerATTACKVersion keeps the two halves of the same claim from drifting apart. The exported
// Navigator layer declares an ATT&CK version, and the table the UI renders from is cut from one; if they disagree, the page
// names techniques and tactics from a different ATT&CK than the layer says it is. v19 renamed enough (Defense Evasion became
// Stealth and Defense Impairment) that a version skew is not cosmetic.
func TestTechniqueTableMatchesTheLayerATTACKVersion(t *testing.T) {
	t.Parallel()

	layer := rulesapi.BuildNavigatorLayer(rulesbootstrap.CatalogOnly().List())
	layerVersion := layer.Versions["attack"]
	require.NotEmpty(t, layerVersion, "the layer must declare the ATT&CK version it is built against")

	_, tableVersion := generatedTechniqueIDs(t)
	require.NotEmpty(t, tableVersion, "the vendored table must record the ATT&CK version it was cut from")

	// The layer pins the major ("19"); the table records the exact release it was generated from ("19.2"). Comparing the
	// major is what keeps a v20 table from shipping under a layer still claiming v19.
	major, _, _ := strings.Cut(tableVersion, ".")
	require.Equal(t, layerVersion, major,
		"the vendored table is ATT&CK v%s but the layer declares v%s", tableVersion, layerVersion)
}
