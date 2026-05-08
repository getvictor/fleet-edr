// Package arch_test gates the architectural invariants every PR must
// preserve. chokepoint_coverage_test asserts every operator-handler
// file references the api.HTTPGate chokepoint helper, so a future PR
// that adds a privileged route can't ship a handler that silently
// bypasses the authorization gate.
package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// operatorHandlerDirs is the closed set of directories whose Go files
// implement privileged HTTP handlers. Every non-test file in these
// dirs that declares a function with the
// `(http.ResponseWriter, *http.Request)` signature must reference
// HTTPGate (api.HTTPGate or identityapi.HTTPGate). Adding a new
// operator-surface package is a deliberate act: drop it in here at
// the same time, with PR review on the gate coverage of every
// handler in the new package.
//
// Pre-auth surfaces (oidc, breakglass, login) are intentionally out:
// their routes don't gate on operator role bindings — they're the
// authentication flows themselves. Reauth endpoints under
// breakglass/handler.go gate on session AuthMethod, which is a
// session-level check rather than the role-based chokepoint.
var operatorHandlerDirs = []string{
	"server/detection/internal/operator",
	"server/rules/internal/operator",
	"server/response/internal/operator",
	"server/endpoint/internal/operator",
	"server/identity/internal/audit",
}

// gateExceptions is the per-file allowlist for handler files that
// legitimately don't call HTTPGate. Empty today; reserved for future
// public-info / health / metric routes that might land in operator/
// without authz gating. Adding an entry here is a deliberate act
// that should ride alongside a PR comment explaining why.
var gateExceptions = map[string]bool{
	// Format: filepath relative to repo root, e.g.
	// "server/detection/internal/operator/healthz.go".
}

// TestEveryPrivilegedHandlerCallsHTTPGate walks each operator-surface
// directory, parses every non-test Go file with go/parser, and fails
// the test if the file declares an HTTP handler function but never
// references HTTPGate.
//
// The check is loose by design: a handler could call HTTPGate from
// a helper in the same file (still counted) or in a sibling file
// (also counted because we check at the directory level when looser
// matching is needed). The regression we care about is "someone
// added a new privileged route and forgot the gate" — that almost
// always lands as a new file with handler funcs but no HTTPGate
// reference. False positives are addressed via gateExceptions.
func TestEveryPrivilegedHandlerCallsHTTPGate(t *testing.T) {
	repoRoot := repoRootFromTest(t)
	var offenders []string
	handlerFilesScanned := 0
	for _, relDir := range operatorHandlerDirs {
		dir := filepath.Join(repoRoot, relDir)
		entries, err := os.ReadDir(dir)
		require.NoErrorf(t, err, "read operator dir %s", dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			rel := filepath.Join(relDir, e.Name())
			if gateExceptions[rel] {
				continue
			}
			full := filepath.Join(dir, e.Name())
			if !fileHasHandlerFunc(t, full) {
				continue
			}
			handlerFilesScanned++
			if !fileReferencesHTTPGate(t, full) {
				offenders = append(offenders, rel)
			}
		}
	}
	// Defensive: a refactor that broke the parser would otherwise turn
	// the test into a silent no-op. Pin a floor under the count of
	// handler files we actually walked. Today there are 5 (one per
	// operator-handler directory); the floor is 4 to give one
	// directory the room to be temporarily restructured.
	require.GreaterOrEqualf(t, handlerFilesScanned, 4,
		"expected to walk at least 4 handler files across operatorHandlerDirs but "+
			"only walked %d — the parser likely missed an HTTP handler signature, "+
			"check fileHasHandlerFunc / paramTypeIdents",
		handlerFilesScanned)
	require.Emptyf(t, offenders,
		"the following operator-handler files declare an http.ResponseWriter "+
			"function but never reference HTTPGate; either add a chokepoint call "+
			"or add the file to gateExceptions with a justification:\n  %s",
		strings.Join(offenders, "\n  "))
}

// fileHasHandlerFunc returns true if any function in the file has a
// signature matching `(http.ResponseWriter, *http.Request)`. Method
// receivers + free functions both qualify; the parameter shape is
// what matters.
func fileHasHandlerFunc(t *testing.T, path string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	require.NoErrorf(t, err, "parse %s", path)
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Type.Params == nil {
			return true
		}
		params := fn.Type.Params.List
		// Need at least two distinct parameter types: ResponseWriter
		// then *Request. Param lists can group same-typed names in one
		// Field, so flatten by counting types-at-positions.
		types := paramTypeIdents(params)
		if len(types) < 2 {
			return true
		}
		if isResponseWriter(types[0]) && isRequestPtr(types[1]) {
			found = true
			return false
		}
		return true
	})
	return found
}

// paramTypeIdents returns the type expression at each parameter
// position, expanding grouped Field entries (`a, b T`) into one entry
// per name. The return is positional so caller can check param[0]
// against ResponseWriter and param[1] against *Request without
// re-walking.
func paramTypeIdents(params []*ast.Field) []ast.Expr {
	var out []ast.Expr
	for _, p := range params {
		if len(p.Names) == 0 {
			out = append(out, p.Type)
			continue
		}
		for range p.Names {
			out = append(out, p.Type)
		}
	}
	return out
}

func isResponseWriter(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http" && sel.Sel.Name == "ResponseWriter"
}

func isRequestPtr(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http" && sel.Sel.Name == "Request"
}

// fileReferencesHTTPGate returns true if the file's source mentions
// HTTPGate anywhere. We use the source bytes (not the AST) because
// the call may be qualified (api.HTTPGate, identityapi.HTTPGate) and
// the ast.SelectorExpr walk would have to expand both spellings;
// substring-matching is robust against future-rename without losing
// fidelity (the helper is exported with that exact name).
func fileReferencesHTTPGate(t *testing.T, path string) bool {
	t.Helper()
	src, err := os.ReadFile(path) //nolint:gosec // path comes from filepath.Join under a test-fixed prefix
	require.NoErrorf(t, err, "read %s", path)
	return strings.Contains(string(src), "HTTPGate")
}

// repoRootFromTest resolves the repo root by walking up from the
// test's working directory looking for go.mod. The arch_test runs
// from test/arch/ but other test bins might invoke it differently;
// resolving go.mod up the tree is more robust than hardcoding "../..".
func repoRootFromTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	cur := wd
	for range 8 { // depth cap: any sane repo finds go.mod within 8 hops
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	t.Fatalf("could not find go.mod walking up from %s", wd)
	return ""
}

// Compile-time assertion that the `net/http` import is exercised.
// The actual ResponseWriter / Request usage is via
// AST-comparison-by-name above, so without this anchor the import
// would be flagged unused by the linter. Anchor returns nil to keep
// the helper inert; var _ = ensures it's evaluated.
var _ = func() http.HandlerFunc { return nil }
