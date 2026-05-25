package operator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/service"

	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// allowAllAuthZ pins the HTTPGate allow branch so the coverage-handler tests in this file isolate the no-rules code path
// without dragging in the role-matrix surface (covered exhaustively in server/identity/internal/authz/engine_test.go).
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

// spec:server-admin-surface/att-ck-coverage-layer-endpoint/coverage-with-no-rules
//
// Pins the spec's "Coverage with no rules" clause: a server constructed with zero registered rules MUST still respond
// 200 to GET /api/attack-coverage and the returned Navigator layer MUST carry an empty `techniques` array, NOT a nil or
// error. The integration suite in server/rules/internal/tests/ always seeds the full catalog via rulesbootstrap.New, so
// the no-rules path has no path through the bootstrap helper. This focused unit test constructs the service directly with
// an empty rule slice + an allow-all authz stub and drives the handler over httptest, bypassing the catalog seed.
//
// Why a unit test rather than a bootstrap option: service.New already accepts an empty rule slice (it normalises nil to
// []api.Rule{}), so no production-code change is required to exercise the contract. Adding a bootstrap option that callers
// could pass to override the catalog would widen the public surface for one test; the focused construction here is cheaper
// and equally tight.
func TestHandler_ATTACKCoverage_NoRules(t *testing.T) {
	t.Parallel()
	svc := service.New([]rulesapi.Rule{}, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/attack-coverage", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "no-rules server MUST still serve 200, not 500 / nil")
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json",
		"response MUST be JSON so the Navigator import path stays the same as the with-rules case")

	var layer struct {
		Techniques []any `json:"techniques"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&layer))
	assert.NotNil(t, layer.Techniques, "techniques field MUST be present (empty array), not omitted")
	assert.Empty(t, layer.Techniques, "with zero registered rules, the coverage layer MUST carry zero techniques")
}
