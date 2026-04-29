package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/store"
)

type stubCatalog struct {
	rules []RuleMetadata
}

func (c *stubCatalog) Catalog() []RuleMetadata { return c.rules }

func TestHandleATTACKCoverage_EmitsNavigatorLayer(t *testing.T) {
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	ps := policy.New(s.DB())

	catalog := &stubCatalog{rules: []RuleMetadata{
		{ID: "alpha", Techniques: []string{"T1059", "T1105"}},
		{ID: "beta", Techniques: []string{"T1059"}},      // same technique as alpha — exercises dedup
		{ID: "gamma", Techniques: []string{"T1574.006"}}, // sub-technique
		{ID: "delta", Techniques: nil},                   // rule without a mapping — must not crash
	}}
	h := New(es, ps, s, catalog, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/attack-coverage", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Name       string            `json:"name"`
		Versions   map[string]string `json:"versions"`
		Domain     string            `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
			Comment     string `json:"comment"`
		} `json:"techniques"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "enterprise-attack", body.Domain)
	assert.NotEmpty(t, body.Name)
	assert.NotEmpty(t, body.Versions["attack"], "Navigator needs the attack version")

	byTechnique := map[string]string{}
	for _, tech := range body.Techniques {
		byTechnique[tech.TechniqueID] = tech.Comment
		assert.Equal(t, 1, tech.Score)
	}
	assert.Contains(t, byTechnique, "T1059")
	assert.Contains(t, byTechnique, "T1105")
	assert.Contains(t, byTechnique, "T1574.006")
	// T1059 is covered by both alpha and beta — the comment should name
	// both so an analyst can jump from a heatmap cell to the rules.
	assert.Contains(t, byTechnique["T1059"], "alpha")
	assert.Contains(t, byTechnique["T1059"], "beta")
}

func TestHandleATTACKCoverage_IsDeterministic(t *testing.T) {
	// Same catalog, many calls — the body must be byte-identical across
	// requests so the endpoint is ETag-friendly and snapshot-testable.
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	ps := policy.New(s.DB())
	catalog := &stubCatalog{rules: []RuleMetadata{
		{ID: "z_rule", Techniques: []string{"T1105", "T1059"}},
		{ID: "a_rule", Techniques: []string{"T1059"}},
		{ID: "m_rule", Techniques: []string{"T1574.006"}},
	}}
	h := New(es, ps, s, catalog, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	fetch := func() []byte {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			srv.URL+"/api/v1/attack-coverage", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return b
	}
	first := fetch()
	for range 5 {
		assert.Equal(t, string(first), string(fetch()),
			"Navigator layer must be byte-identical across requests")
	}
}

func TestHandleATTACKCoverage_EmptyCatalogStillReturnsLayer(t *testing.T) {
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	ps := policy.New(s.DB())

	h := New(es, ps, s, nil, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/attack-coverage", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
		} `json:"techniques"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "enterprise-attack", body.Domain)
	assert.Empty(t, body.Techniques, "nil catalog → empty technique list, not 500")
}
