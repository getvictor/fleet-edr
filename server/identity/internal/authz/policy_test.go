package authz_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
)

// TestPolicy_ActionsParity locks the action enumeration in three
// places to one canonical set: the Go constants, the embedded
// actions.json bundle, and the role-grant lists in roles.json. Any
// drift between Go and the policy bundle would let the chokepoint
// silently grant or deny on actions one side doesn't know about.
//
// The Engine constructor runs the same parity check at boot so a
// misconfigured deployment fails fast; this test surfaces the same
// regression at PR time.
func TestPolicy_ActionsParity(t *testing.T) {
	bundlePath := filepath.Join("policy", "data", "actions.json")
	bundleBytes, err := os.ReadFile(bundlePath) //nolint:gosec // path is a fixed test fixture
	require.NoError(t, err, "read actions.json fixture")

	var bundle struct {
		Actions []string `json:"actions"`
	}
	require.NoError(t, json.Unmarshal(bundleBytes, &bundle))

	bundleSet := toStringSet(bundle.Actions)
	goSet := make(map[string]struct{}, len(api.RegisteredActions()))
	for _, a := range api.RegisteredActions() {
		goSet[string(a)] = struct{}{}
	}

	missingFromBundle := setDifference(goSet, bundleSet)
	missingFromGo := setDifference(bundleSet, goSet)

	assert.Empty(t, missingFromBundle, "actions registered in Go but missing from policy bundle")
	assert.Empty(t, missingFromGo, "actions in policy bundle but not registered in Go")

	// Every action a role grants must also appear in the actions list,
	// otherwise the bundle has a typo or a stale grant.
	rolesPath := filepath.Join("policy", "data", "roles.json")
	rolesBytes, err := os.ReadFile(rolesPath) //nolint:gosec // path is a fixed test fixture
	require.NoError(t, err)
	var roles struct {
		Roles map[string]struct {
			Grants []string `json:"grants"`
		} `json:"roles"`
	}
	require.NoError(t, json.Unmarshal(rolesBytes, &roles))

	for roleID, role := range roles.Roles {
		for _, grant := range role.Grants {
			if grant == "*" {
				continue
			}
			_, ok := bundleSet[grant]
			assert.Truef(t, ok,
				"role %q grants action %q which is not in actions.json", roleID, grant)
		}
	}
}

// TestPolicy_RegoTestSuite runs the Rego-side correctness suite
// (policy/edr_test.rego) via the OPA Go library. Equivalent to
// `opa test policy/`; using the library means CI does not need the
// opa CLI on PATH and `go test` exercises both engine + policy
// correctness in a single command.
//
// Asserts: every test in edr_test.rego passes AND the suite is not
// empty (`require.Positive(count)`). A numeric coverage threshold
// is intentionally NOT enforced here; the (role, action) matrix in
// edr_test.rego plus the engine-side TestAllow_RoleActionMatrix in
// engine_test.go is the wave-1 correctness floor. A future
// enhancement may wire `tester.NewRunner().SetCoverageQueryTracer`
// to a real tracer and gate at a percentage; today the runner is
// initialised with `SetCoverageQueryTracer(nil)` (coverage off) and
// the comment matches the code.
func TestPolicy_RegoTestSuite(t *testing.T) {
	ctx := context.Background()

	// Load every .rego file under policy/ (both the policy module and the test module). ast.NewModuleLoader-equivalent path: read files,
	// parse, hand to tester.Runner.
	regoFiles := []string{
		filepath.Join("policy", "edr.rego"),
		filepath.Join("policy", "edr_test.rego"),
	}
	modules := make(map[string]*ast.Module, len(regoFiles))
	for _, path := range regoFiles {
		data, err := os.ReadFile(path) //nolint:gosec // path is a fixed test fixture
		require.NoErrorf(t, err, "read %s", path)
		mod, err := ast.ParseModule(path, string(data))
		require.NoErrorf(t, err, "parse %s", path)
		modules[path] = mod
	}

	// The test runner needs the role-grant data the policy reads from data.roles. Load roles.json into the in-memory store so the suite
	// evaluates against the production grant matrix, not a stub.
	dataObj := loadDataForRegoTests(t)
	store := inmem.NewFromObject(dataObj)

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	require.False(t, compiler.Failed(), "compile rego modules: %v", compiler.Errors)

	runner := tester.NewRunner().
		SetCompiler(compiler).
		SetStore(store).
		SetCoverageQueryTracer(nil).
		EnableTracing(false)

	results, err := runner.RunTests(ctx, nil)
	require.NoError(t, err)

	var failures []string
	count := 0
	for r := range results {
		count++
		if r.Fail {
			failures = append(failures, r.Package+"."+r.Name)
		} else if r.Error != nil {
			failures = append(failures, r.Package+"."+r.Name+": "+r.Error.Error())
		}
	}
	require.Positive(t, count, "rego test suite must contain at least one test")
	assert.Empty(t, failures, "rego test failures: %v", failures)
}

// loadDataForRegoTests parses roles.json + actions.json into the shape the Rego policy reads from data.* . Mirrors loadDataBundle in
// engine.go, kept private to the test package so the production path stays the single source of truth.
func loadDataForRegoTests(t *testing.T) map[string]any {
	t.Helper()
	rolesBytes, err := os.ReadFile(filepath.Join("policy", "data", "roles.json")) //nolint:gosec // path is a fixed test fixture
	require.NoError(t, err)
	actionsBytes, err := os.ReadFile(filepath.Join("policy", "data", "actions.json")) //nolint:gosec // path is a fixed test fixture
	require.NoError(t, err)

	var rolesWrapper struct {
		Roles map[string]struct {
			Grants []string `json:"grants"`
		} `json:"roles"`
	}
	require.NoError(t, json.Unmarshal(rolesBytes, &rolesWrapper))
	rolesData := make(map[string]any, len(rolesWrapper.Roles))
	for id, r := range rolesWrapper.Roles {
		rolesData[id] = map[string]any{"grants": stringsToInterface(r.Grants)}
	}

	var actionsWrapper struct {
		Actions []string `json:"actions"`
	}
	require.NoError(t, json.Unmarshal(actionsBytes, &actionsWrapper))

	return map[string]any{
		"actions": stringsToInterface(actionsWrapper.Actions),
		"roles":   rolesData,
	}
}

func stringsToInterface(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func toStringSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[s] = struct{}{}
	}
	return out
}

func setDifference(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Compile-time guard against a stray import this file would otherwise miss; keeps `strings` from being a dead import if a future
// rewrite drops the diff helper.
var _ = strings.Builder{}
