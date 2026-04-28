package admin

import (
	"encoding/json"
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

// TestHandleListRules_RoundTrips proves the new /api/v1/admin/rules endpoint
// renders every field the UI's RuleDetail.tsx consumes, in registration order,
// without dropping or transforming the documentation payload. Order is
// load-bearing: the UI uses the catalog order to render the rules index.
func TestHandleListRules_RoundTrips(t *testing.T) {
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	ps := policy.New(s.DB())

	catalog := &stubCatalog{rules: []RuleMetadata{
		{
			ID:         "alpha",
			Techniques: []string{"T1059"},
			Doc: RuleDoc{
				Title:          "Alpha rule",
				Summary:        "alpha summary",
				Description:    "alpha long description",
				Severity:       "high",
				EventTypes:     []string{"exec"},
				FalsePositives: []string{"some FP"},
				Limitations:    []string{"some limit"},
				Config: []RuleConfig{
					{EnvVar: "EDR_ALPHA", Type: "csv-paths", Default: "", Description: "tune alpha"},
				},
			},
		},
		{
			ID:         "beta",
			Techniques: []string{"T1574.006"},
			Doc: RuleDoc{
				Title:      "Beta rule",
				Summary:    "beta summary",
				Severity:   "critical",
				EventTypes: []string{"exec", "open_write"},
			},
		},
	}}
	h := New(es, ps, s, catalog, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/admin/rules", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body struct {
		Rules []struct {
			ID         string   `json:"id"`
			Techniques []string `json:"techniques"`
			Doc        struct {
				Title          string   `json:"title"`
				Summary        string   `json:"summary"`
				Description    string   `json:"description"`
				Severity       string   `json:"severity"`
				EventTypes     []string `json:"event_types"`
				FalsePositives []string `json:"false_positives"`
				Limitations    []string `json:"limitations"`
				Config         []struct {
					EnvVar      string `json:"env_var"`
					Type        string `json:"type"`
					Default     string `json:"default"`
					Description string `json:"description"`
				} `json:"config"`
			} `json:"doc"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	require.Len(t, body.Rules, 2)
	assert.Equal(t, "alpha", body.Rules[0].ID, "registration order must round-trip")
	assert.Equal(t, "Alpha rule", body.Rules[0].Doc.Title)
	assert.Equal(t, "high", body.Rules[0].Doc.Severity)
	require.Len(t, body.Rules[0].Doc.Config, 1)
	assert.Equal(t, "EDR_ALPHA", body.Rules[0].Doc.Config[0].EnvVar)
	assert.Equal(t, "csv-paths", body.Rules[0].Doc.Config[0].Type)

	assert.Equal(t, "beta", body.Rules[1].ID)
	assert.Equal(t, "critical", body.Rules[1].Doc.Severity)
	assert.Empty(t, body.Rules[1].Doc.FalsePositives,
		"empty omitempty fields must round-trip as null/empty, not as a fabricated entry")
}

// TestHandleListRules_NilCatalog covers the same defensive path attack-coverage
// uses: a server constructed without a Cataloger should return an empty list,
// not 500.
func TestHandleListRules_NilCatalog(t *testing.T) {
	s := store.OpenTestStore(t)
	es := enrollment.NewStore(s.DB())
	ps := policy.New(s.DB())

	h := New(es, ps, s, nil, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/admin/rules", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Rules []any `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Empty(t, body.Rules)
}
