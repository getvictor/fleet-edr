package apidocs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canonicalSpecPath is the OpenAPI spec of record, relative to this package's directory.
//
// The embedded copy beside it is not a second source: it exists only because a go:embed pattern cannot reach outside its own
// package directory, so the file the server serves at /api/openapi.yaml has to physically live here.
const canonicalSpecPath = "../../docs/api/openapi.yaml"

// TestEmbeddedSpecMatchesCanonical fails the build when the served spec has fallen behind the spec of record.
//
// The copy was kept current by an undocumented `go generate` that someone had to remember, and the failure of remembering is
// silent and one-directional: the canonical file moves ahead, the served file does not, and the API documentation an operator
// reads quietly understates the API. Issue #781 measured 49 lines of exactly that, including a query parameter the served spec
// did not mention at all.
//
// This test lives under server/ deliberately. CI runs `./server/... ./internal/... ./test/integration/... ./test/scale/...` and
// does NOT run ./tools/..., which is how the rule-pack drift guard came to be written somewhere it never executed (#780). A drift
// check that only runs locally is not a check, it is a suggestion.
func TestEmbeddedSpecMatchesCanonical(t *testing.T) {
	t.Parallel()

	canonical, err := os.ReadFile(canonicalSpecPath)
	require.NoError(t, err, "the canonical spec must exist at %s", canonicalSpecPath)
	require.NotEmpty(t, canonical, "an empty canonical spec would make this test pass by comparing nothing")

	embedded, err := assets.ReadFile("embed/openapi.yaml")
	require.NoError(t, err, "the embedded spec must exist; run `task sync:openapi-embed`")

	assert.Equal(t, string(canonical), string(embedded),
		"the embedded OpenAPI spec has drifted from docs/api/openapi.yaml, so the server serves documentation that is not the "+
			"spec in the repo. Run `task sync:openapi-embed` and commit the result.")
}

// TestServedSpecIsTheEmbeddedOne closes the gap the test above cannot see on its own: that the bytes compared there are the bytes
// a caller actually receives.
//
// It goes through the real route rather than reading the asset a second time, and review caught the first version doing exactly
// that. Comparing `assets.ReadFile(...)` with `specBytes` compares one asset with itself, since specBytes IS that asset read at
// init, so the handler could serve anything at all and both tests would still pass. That is the same failure this file exists to
// prevent, an assertion about the wrong artifact, committed inside the test written to prevent it.
func TestServedSpecIsTheEmbeddedOne(t *testing.T) {
	t.Parallel()

	embedded, err := assets.ReadFile("embed/openapi.yaml")
	require.NoError(t, err)

	mux := http.NewServeMux()
	RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, string(embedded), rec.Body.String(),
		"the route must serve the embedded spec, or comparing that file to the canonical one proves nothing about the API")
}
