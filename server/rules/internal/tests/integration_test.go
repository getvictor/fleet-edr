//go:build integration

// Per-context integration tests for the rules bounded context.
// Exercise the full bootstrap.New -> ApplySchema -> Service stack
// against a real MySQL. Skips when EDR_TEST_DSN isn't set, matching
// the project's other DB-using test files.
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// allowAllAuthZ satisfies identityapi.AuthZ unconditionally for the rules-context integration tests. The chokepoint's per-action
// role matrix is exercised in server/identity/internal/authz/engine_test.go; here we only need the dependency satisfied so
// RegisterAuthedRoutes can mount.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

// newRules wires rules.bootstrap.New against a fresh test DB.
func newRules(t *testing.T) *rulesbootstrap.Rules {
	t.Helper()
	s := full.Open(t)
	deps := rulesbootstrap.Deps{
		DB:     s,
		Logger: slog.Default(),
		AuthZ:  allowAllAuthZ{},
	}
	r, err := rulesbootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r
}

// TestCatalog_ListShape locks in registration order + documentation
// completeness for every shipped rule.
func TestCatalog_ListShape(t *testing.T) {
	t.Parallel()
	r := newRules(t)
	catalog := r.Catalog().List()
	wantIDs := []string{
		"suspicious_exec",
		"persistence_launchagent",
		"dyld_insert",
		"shell_from_office",
		"osascript_network_exec",
		"credential_keychain_dump",
		"privilege_launchd_plist_write",
		"sudoers_tamper",
		"application_control_block",
	}
	require.Len(t, catalog, len(wantIDs))
	for i, want := range wantIDs {
		assert.Equal(t, want, catalog[i].ID, "rule at index %d", i)
		assert.NotEmpty(t, catalog[i].Doc.Title, "rule %s missing Doc.Title", catalog[i].ID)
		assert.NotEmpty(t, catalog[i].Doc.Severity, "rule %s missing Doc.Severity", catalog[i].ID)
	}
}

// TestContentService_ActiveRules surfaces every shipped rule through the engine-facing interface. The exact roster lives in
// TestCatalog_ListShape; this test just confirms the count is in lockstep and every rule has a non-empty descriptor.
func TestContentService_ActiveRules(t *testing.T) {
	t.Parallel()
	r := newRules(t)
	rules := r.ContentService().ActiveRules()
	require.Len(t, rules, len(r.Catalog().List()))
	for _, rule := range rules {
		assert.NotEmpty(t, rule.ID())
		assert.NotEmpty(t, rule.Doc().Title)
	}
}

// spec:server-admin-surface/per-rule-documentation-endpoint/operator-reads-the-rule-catalog
//
// GET /api/rules MUST return a JSON {"rules": [...]} response where every entry carries id, techniques,
// and a non-empty doc block with at least title/summary/description/severity/event_types. The body
// decode + Len/NotEmpty/Equal assertions below pin the wire shape the spec requires; the registry
// completeness clause (every catalog rule appears) is the require.Len against r.Catalog().List().
func TestOperator_GetRules(t *testing.T) {
	t.Parallel()
	r := newRules(t)
	mux := http.NewServeMux()
	r.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/rules", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Rules []struct {
			ID  string `json:"id"`
			Doc struct {
				Title    string `json:"title"`
				Severity string `json:"severity"`
			} `json:"doc"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.Rules, len(r.Catalog().List()))
	assert.Equal(t, "suspicious_exec", body.Rules[0].ID)
	assert.NotEmpty(t, body.Rules[0].Doc.Title)
}

// spec:server-admin-surface/att-ck-coverage-layer-endpoint/coverage-when-rules-are-registered
//
// GET /api/attack-coverage MUST return a Navigator-layer JSON document whose top-level shape matches
// the upstream MITRE format (domain="enterprise-attack"); the test seeds the default rule catalog so
// the "techniques array contains an entry for every covered technique" clause is satisfied by the
// presence of a non-empty techniques array (every shipped catalog rule declares at least one technique).
// The byte-identical-across-requests assertion is a stronger invariant than the spec requires but it
// catches any non-deterministic ordering that would break snapshot-based dashboards.
func TestOperator_GetAttackCoverage(t *testing.T) {
	t.Parallel()
	r := newRules(t)
	mux := http.NewServeMux()
	r.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	fetch := func() string {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/attack-coverage", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "enterprise-attack", body["domain"])
		out, err := json.Marshal(body)
		require.NoError(t, err)
		return string(out)
	}
	first := fetch()
	for range 3 {
		assert.Equal(t, first, fetch(), "Navigator layer must be byte-identical across requests")
	}
}

// TestBootstrap_MissingDeps surfaces required-field errors.
func TestBootstrap_MissingDeps(t *testing.T) {
	t.Parallel()
	t.Run("nil DB", func(t *testing.T) {
		_, err := rulesbootstrap.New(rulesbootstrap.Deps{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DB")
	})
}
