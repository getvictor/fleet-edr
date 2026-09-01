package operator

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
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
//
// Test structure: status / content-type / payload-shape are split into t.Run subtests so a regression on one dimension
// (e.g., the handler starts emitting text/plain on the no-rules path) is named in the failure output and not lost in a
// flat test body.
func TestHandler_ATTACKCoverage_NoRules(t *testing.T) {
	t.Parallel()
	svc := service.New([]rulesapi.Rule{}, nil, slog.Default())
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

	// Read + decode the body up front so the payload-shape subtest doesn't depend on subtest scheduling order under
	// t.Parallel (the body would otherwise be drained by the first subtest that touches it).
	var layer struct {
		Techniques []any `json:"techniques"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&layer))

	t.Run("status is 200", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "no-rules server MUST still serve 200, not 500 / nil")
	})

	t.Run("content-type is application/json", func(t *testing.T) {
		t.Parallel()
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json",
			"response MUST be JSON so the Navigator import path stays the same as the with-rules case")
	})

	t.Run("payload techniques array is present and empty", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, layer.Techniques, "techniques field MUST be present (empty array), not omitted")
		assert.Empty(t, layer.Techniques, "with zero registered rules, the coverage layer MUST carry zero techniques")
	})
}

// TestHandler_ListRules_SupportedExclusionMatchTypes pins that GET /api/rules surfaces each rule's supported exclusion match types
// (issue #520), the field the admin UI's exclusion editor uses to offer only the match types a rule consults. A consuming rule
// carries its declared list; a rule that consults no exclusions MUST carry an empty array (never null) so the UI can iterate without
// a nil guard.
//
// spec:server-detection-rules-engine/durable-detection-configuration-surface/the-rule-catalog-exposes-per-rule-supported-exclusion-match-types
func TestHandler_ListRules_SupportedExclusionMatchTypes(t *testing.T) {
	t.Parallel()
	svc := service.New(catalog.New(nil), nil, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
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
			ID                           string   `json:"id"`
			SupportedExclusionMatchTypes []string `json:"supported_exclusion_match_types"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	byID := map[string][]string{}
	for _, r := range body.Rules {
		assert.NotNilf(t, r.SupportedExclusionMatchTypes, "rule %q MUST carry an array, not null", r.ID)
		byID[r.ID] = r.SupportedExclusionMatchTypes
	}
	assert.Equal(t, []string{"parent_path_glob", "team_id", "signing_id", "cdhash"}, byID["suspicious_exec"])
	assert.Equal(t, []string{"path_glob"}, byID["sudoers_tamper"])
	assert.Empty(t, byID["dns_c2_beacon"], "a rule that consults no exclusions offers an empty set")
}

// spec:server-detection-rules-engine/registered-rule-catalog/rule-metadata-reports-target-platforms
//
// GET /api/rules surfaces each rule's target platforms (ADR-0018) so operators can see which operating systems a rule applies to. Every
// current catalog rule targets darwin; the field is always a JSON array (never null) so the UI can iterate without a nil guard.
func TestHandler_ListRules_Platforms(t *testing.T) {
	t.Parallel()
	svc := service.New(catalog.New(nil), nil, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
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
			ID        string   `json:"id"`
			Platforms []string `json:"platforms"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	require.NotEmpty(t, body.Rules)
	for _, r := range body.Rules {
		assert.NotNilf(t, r.Platforms, "rule %q MUST carry a platforms array, not null", r.ID)
		assert.Equalf(t, []string{"darwin"}, r.Platforms, "rule %q targets darwin", r.ID)
	}
}

// spec:server-detection-rules-engine/a-rule-declares-the-mode-it-operates-in-absent-configuration/a-declared-default-is-listed-on-the-rule-catalog
//
// spec:server-detection-rules-engine/the-vendored-upstream-corpus-is-registered-and-does-not-alert-until-promoted/a-vendored-rule-is-attributed-on-the-operator-facing-catalog
//
// TestHandler_ListRules_DefaultMode pins that GET /api/rules reports the mode each rule runs in absent configuration.
//
// It is asserted over the real catalog rather than a stub because the value has to be a MODE for every rule, never the empty string:
// a consumer reading "" would have to know what the server's default is to interpret it, which is exactly the knowledge this field
// exists to publish.
func TestHandler_ListRules_DefaultMode(t *testing.T) {
	t.Parallel()
	svc := service.New(catalog.New(nil), nil, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
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
			ID          string `json:"id"`
			DefaultMode string `json:"default_mode"`
			Origin      string `json:"origin"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	require.NotEmpty(t, body.Rules)
	modes := map[string]int{}
	for _, r := range body.Rules {
		assert.Truef(t, rulesapi.IsValidDetectionRuleMode(rulesapi.DetectionRuleMode(r.DefaultMode)),
			"rule %q reports default_mode %q, which is not a mode", r.ID, r.DefaultMode)
		modes[r.DefaultMode]++
	}

	// Both kinds are present and the endpoint tells them apart, which is the whole reason the field exists: a rule sitting at its
	// own monitor default appears on no other surface, so without this an operator cannot see that it raises nothing.
	assert.Positive(t, modes["alert"], "the rules this project authored alert by default")
	assert.Positive(t, modes["monitor"], "the vendored corpus ships in monitor mode (issue #764)")
	assert.Equal(t, len(body.Rules), modes["alert"]+modes["monitor"], "every rule reports one of the two, never an empty string")

	// Attribution rides the same response. A vendored rule is rendered exactly like an authored one on every surface built from
	// this payload, so the origin is what lets a reader tell them apart, and it is how the corpus licence's attribution reaches
	// the reader of our documentation rather than only the reader of the rule file.
	var credited, uncredited int
	for _, r := range body.Rules {
		if r.Origin == "" {
			uncredited++
			assert.Equal(t, "alert", r.DefaultMode, "rule %q names no source, so it should be one we wrote and alerts", r.ID)
			continue
		}
		credited++
		assert.Contains(t, r.Origin, "SigmaHQ", "rule %q credits an unexpected source %q", r.ID, r.Origin)
	}
	assert.Positive(t, credited, "the vendored rules credit their upstream")
	assert.Positive(t, uncredited, "the rules this project wrote claim no upstream")
}

// TestHandler_ExportRule serves one detection as its declarative rule file (issue #757). The response IS the artifact, so it is
// YAML rather than a JSON envelope the caller would have to unwrap before the bytes were useful.
func TestHandler_ExportRule(t *testing.T) {
	t.Parallel()
	svc := service.New(catalog.New(nil), nil, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/rules/credential_keychain_dump/export", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/yaml; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Content-Disposition"), `filename="credential_keychain_dump.yml"`)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "title: Keychain credential dump")
	assert.Contains(t, string(body), "rule_id: credential_keychain_dump")
	assert.Contains(t, string(body), "type: sigma")
}

// TestHandler_ExportRule_NotFound covers both absences with one status, deliberately. A non-detection and a rule id that names
// nothing are equally absent from the catalog, and a distinct status for the former would leak the existence of rules the catalog
// does not describe (#775).
func TestHandler_ExportRule_NotFound(t *testing.T) {
	t.Parallel()
	svc := service.New(catalog.New(nil), nil, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, id := range []string{"application_control_block", "sensor_recovery_failed", "no_such_rule"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/rules/"+id+"/export", nil)
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}

// spec:server-detection-rules-engine/the-vendored-upstream-corpus-is-registered-and-does-not-alert-until-promoted/exporting-a-vendored-rule-returns-the-upstream-file
//
// TestHandler_ExportRule_VendoredRuleServesTheUpstreamFile pins that exporting an imported rule hands back the file this repository
// vendored, byte for byte, rather than a re-rendering of it.
//
// Two things depend on this. An operator comparing what runs here against SigmaHQ needs the upstream bytes to diff, and the pack on
// disk deliberately omits these rules so that one rule has one authoritative description; if this endpoint rendered its own version
// instead, that second description would exist after all, just served rather than committed.
func TestHandler_ExportRule_VendoredRuleServesTheUpstreamFile(t *testing.T) {
	t.Parallel()
	svc := service.New(catalog.New(nil), nil, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	const id = "proc_creation_macos_xattr_gatekeeper_bypass"
	want, vendored := catalog.VendoredSource(id)
	require.True(t, vendored, "fixture rule must be one of the vendored ones")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/rules/"+id+"/export", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got), "the exported bytes are the vendored file, not a rendering of it")
	assert.Contains(t, string(got), "title:", "and it is still the upstream Sigma document")
}

// spec:server-detection-rules-engine/operator-toggling-of-individual-rules/an-operator-disables-a-noisy-rule-for-their-environment
// spec:server-detection-rules-engine/operator-toggling-of-individual-rules/the-catalog-reports-the-mode-a-rule-runs-in-not-only-the-one-it-declares
//
// TestHandler_ListRules_ReportsTheModeInForce asserts the requirement clause that a rule an operator has disabled stays listed by
// GET /api/rules "with its mode indicated".
//
// That clause read as covered and was not (issue #810): two tests carried the disable scenario's marker and neither looked at
// /api/rules, because spectrace gates on a scenario having a marker rather than on the test exercising every clause of it. This
// asserts the wire field, on the endpoint the clause names.
func TestHandler_ListRules_ReportsTheModeInForce(t *testing.T) {
	t.Parallel()

	rules := catalog.New(nil)
	require.NotEmpty(t, rules)
	silenced := rules[0].ID()

	svc := service.New(rules, stubGlobalModes{silenced: {
		Mode: rulesapi.DetectionRuleModeDisabled, Source: rulesapi.RuleModeSourceSetting,
	}}, slog.Default())
	h := New(svc, allowAllAuthZ{}, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
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
			ID          string `json:"id"`
			Mode        string `json:"mode"`
			ModeSource  string `json:"mode_source"`
			DefaultMode string `json:"default_mode"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	var found bool
	for _, r := range body.Rules {
		if r.ID != silenced {
			assert.Equalf(t, "default", r.ModeSource, "rule %q has no setting", r.ID)
			assert.Equalf(t, r.DefaultMode, r.Mode, "with no setting, rule %q runs in the mode it declares", r.ID)
			continue
		}
		found = true
		assert.Equal(t, "disabled", r.Mode, "the disabled rule is still listed, marked disabled")
		assert.Equal(t, "setting", r.ModeSource)
		assert.NotEqual(t, "disabled", r.DefaultMode,
			"the declaration is reported alongside, so the two remain distinguishable")
	}
	assert.True(t, found, "a disabled rule stays in the catalog rather than being removed from it")
}

// stubGlobalModes resolves a canned global mode per rule id, and reports the rule's own default for any id it does not name.
type stubGlobalModes map[string]rulesapi.GlobalRuleMode

func (m stubGlobalModes) GlobalRuleMode(ruleID string, ruleDefault rulesapi.DetectionRuleMode) rulesapi.GlobalRuleMode {
	if got, ok := m[ruleID]; ok {
		return got
	}
	return rulesapi.GlobalRuleMode{Mode: ruleDefault, Source: rulesapi.RuleModeSourceDefault}
}
