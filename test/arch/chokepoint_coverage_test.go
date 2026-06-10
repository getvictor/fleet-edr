// Package arch_test gates the architectural invariants every PR must preserve. chokepoint_coverage_test asserts every operator-handler
// file references the api.HTTPGate chokepoint helper, so a future PR that adds a privileged route can't ship a handler that silently
// bypasses the authorization gate.
package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
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
// their routes don't gate on operator role bindings: they're the
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

// gateExceptions is the per-file allowlist for handler files that legitimately don't call HTTPGate. Empty today; reserved for future
// public-info / health / metric routes that might land in operator/ without authz gating. Adding an entry here is a deliberate act
// that should ride alongside a PR comment explaining why.
var gateExceptions = map[string]bool{
	// Format: filepath relative to repo root, e.g.
	// "server/detection/internal/operator/healthz.go".
}

// TestEveryPrivilegedHandlerCallsHTTPGate walks each operator-surface
// directory, parses every non-test Go file with go/parser, and fails
// the test if the file declares an HTTP handler function but never
// makes a real call to HTTPGate. The check is per-file (any handler
// in the file is "covered" if anywhere in the same file emits an
// HTTPGate call expression), not per-handler-function. Handlers in
// these files share the same Handler struct and the same gating
// pattern, so file-level coverage matches the convention.
//
// Detection is AST-based: we look for ast.CallExpr nodes whose
// function expression resolves to an identifier named HTTPGate
// (matching api.HTTPGate, identityapi.HTTPGate, or any future
// import alias). String-matching the source would let a file pass
// by mentioning HTTPGate in a comment or a string literal: that
// would weaken the architectural lock the test exists to enforce.
// False positives are addressed via gateExceptions.
func TestEveryPrivilegedHandlerCallsHTTPGate(t *testing.T) {
	repoRoot := repoRootFromTest(t)
	var offenders []string
	handlerFilesScanned := 0
	for _, relDir := range operatorHandlerDirs {
		dir := filepath.Join(repoRoot, relDir)
		entries, err := os.ReadDir(dir)
		require.NoErrorf(t, err, "read operator dir %s", dir)
		for _, e := range entries {
			scanned, offender := scanHandlerEntry(t, relDir, dir, e)
			if scanned {
				handlerFilesScanned++
			}
			if offender != "" {
				offenders = append(offenders, offender)
			}
		}
	}
	// Defensive: a refactor that broke the parser would otherwise turn the test into a silent no-op. Pin a floor under the count of
	// handler files we actually walked. Today there are 5 (one per operator-handler directory); the floor is 4 to give one directory the
	// room to be temporarily restructured.
	require.GreaterOrEqualf(t, handlerFilesScanned, 4,
		"expected to walk at least 4 handler files across operatorHandlerDirs but "+
			"only walked %d: the parser likely missed an HTTP handler signature, "+
			"check fileHasHandlerFunc / paramTypeIdents",
		handlerFilesScanned)
	require.Emptyf(t, offenders,
		"the following operator-handler files declare an http.ResponseWriter "+
			"function but never reference HTTPGate; either add a chokepoint call "+
			"or add the file to gateExceptions with a justification:\n  %s",
		strings.Join(offenders, "\n  "))
}

// scanHandlerEntry classifies a single dirent under an operator-handler directory. Returns (scanned, offender): scanned=true when the
// entry is a non-test .go file that declares at least one HTTP-handler function (i.e., it counted toward the floor); offender holds
// the rel-path when the file declares a handler but never references the HTTPGate chokepoint (offender="" means clean).
func scanHandlerEntry(t *testing.T, relDir, dir string, e os.DirEntry) (bool, string) {
	t.Helper()
	if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
		return false, ""
	}
	rel := filepath.Join(relDir, e.Name())
	if gateExceptions[rel] {
		return false, ""
	}
	full := filepath.Join(dir, e.Name())
	if !fileHasHandlerFunc(t, full) {
		return false, ""
	}
	if !fileReferencesHTTPGate(t, full) {
		return true, rel
	}
	return true, ""
}

// fileHasHandlerFunc returns true if any function in the file has a signature matching `(http.ResponseWriter, *http.Request)`.
// Method receivers + free functions both qualify; the parameter shape is what matters.
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
		// Need at least two distinct parameter types: ResponseWriter then *Request. Param lists can group same-typed names in one Field,
		// so flatten by counting types-at-positions.
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

// paramTypeIdents returns the type expression at each parameter position, expanding grouped Field entries (`a, b T`) into one entry
// per name. The return is positional so caller can check param[0] against ResponseWriter and param[1] against *Request without
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

// fileReferencesHTTPGate returns true if the file makes a real call to a function named HTTPGate (matching api.HTTPGate,
// identityapi.HTTPGate, or any other import-alias spelling). We walk the AST and look for ast.CallExpr nodes whose function expression
// resolves to that identifier. String-matching the raw source would let comments, doc strings, or unrelated names trip the check and
// silently weaken the architectural lock.
func fileReferencesHTTPGate(t *testing.T, path string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	require.NoErrorf(t, err, "parse %s", path)
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if calleeName(call.Fun) == "HTTPGate" {
			found = true
			return false
		}
		return true
	})
	return found
}

// calleeName returns the rightmost identifier of a call's function expression: for `api.HTTPGate(…)` the SelectorExpr resolves to
// "HTTPGate"; for a bare `HTTPGate(…)` (same-package) the Ident itself resolves to "HTTPGate". Any other shape (dynamic dispatch via
// interface, function literal, etc.) returns "": operator handlers don't use those, and matching them would risk false positives on
// unrelated calls.
func calleeName(fn ast.Expr) string {
	switch v := fn.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.Ident:
		return v.Name
	}
	return ""
}

// repoRootFromTest resolves the repo root by walking up from the test's working directory looking for go.mod. The arch_test runs from
// test/arch/ but other test bins might invoke it differently; resolving go.mod up the tree is more robust than hardcoding "../..".
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
