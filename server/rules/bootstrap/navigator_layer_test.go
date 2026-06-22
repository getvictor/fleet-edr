package bootstrap_test

import (
	"os"
	"path/filepath"
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
