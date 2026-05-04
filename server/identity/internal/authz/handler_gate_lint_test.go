package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrivilegedHandlersGateOnAllow is the build-time gate the spec
// calls for in §"Architecture lint": every privileged handler
// registered on a session-authed mux MUST funnel through the AuthZ
// chokepoint before performing its side effect. The test parses each
// operator package's handler.go and asserts that every method
// referenced by `mux.HandleFunc(...)` reaches an .Allow(...) call —
// directly or via a same-file helper.
//
// A privileged route registered without a chokepoint call is the
// exact regression Phase 6's audit dashboard cannot recover from
// post-flip; "you forgot the Allow call" must fail at PR time, not
// in production.
//
// Scope: this lint runs against the wave-1 operator surface
// (identity audit, detection, rules, response, endpoint operator
// handlers). New operator packages SHALL be added to
// privilegedHandlerFiles.
func TestPrivilegedHandlersGateOnAllow(t *testing.T) {
	repoRoot := repoRootFromAuthzPackage(t)
	for _, file := range privilegedHandlerFiles {
		t.Run(filepath.Base(filepath.Dir(file)), func(t *testing.T) {
			path := filepath.Join(repoRoot, file)
			fset := token.NewFileSet()
			astFile, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
			require.NoError(t, err, "parse %s", path)

			gatedFns := functionsCallingAllow(astFile)
			handlers := registeredHandlerMethods(astFile)
			require.NotEmpty(t, handlers, "no mux.HandleFunc registrations found in %s; "+
				"the lint expects at least one privileged route per operator handler "+
				"file (and would otherwise pass vacuously, masking a regression)", file)

			for handler, route := range handlers {
				assert.True(t, callsAllowTransitive(astFile, handler, gatedFns),
					"%s: handler %q (registered for %q) must reach .Allow() either directly "+
						"or via a same-file helper (e.g. h.authzGate)",
					filepath.Base(path), handler, route)
			}
		})
	}
}

// privilegedHandlerFiles lists every file the lint asserts is a
// privileged operator handler. Adding a new operator package without
// adding it here is itself a regression; add the path AND the
// chokepoint call together.
var privilegedHandlerFiles = []string{
	"server/identity/internal/audit/handler.go",
	"server/detection/internal/operator/handler.go",
	"server/rules/internal/operator/handler.go",
	"server/response/internal/operator/handler.go",
	"server/endpoint/internal/operator/handler.go",
}

// repoRootFromAuthzPackage returns an absolute path to the repository
// root, derived from the test binary's working directory. Go runs
// package tests in the package directory, so we can walk up from
// server/identity/internal/authz to the repo root by stripping that
// suffix.
func repoRootFromAuthzPackage(t *testing.T) string {
	t.Helper()
	wd := mustGetwd(t)
	const suffix = "/server/identity/internal/authz"
	if !strings.HasSuffix(wd, suffix) {
		t.Fatalf("unexpected working directory %q; lint expects to run from the authz package", wd)
	}
	return strings.TrimSuffix(wd, suffix)
}

// functionsCallingAllow returns the set of function names declared in
// astFile whose body contains a call expression of the form
// `<expr>.Allow(...)`. The AuthZ chokepoint helper (e.g. authzGate)
// is included because handlers that delegate to it transitively
// reach .Allow.
func functionsCallingAllow(astFile *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, decl := range astFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Allow" {
				out[fn.Name.Name] = true
			}
			return true
		})
	}
	return out
}

// callsAllowTransitive reports whether `handlerName`'s body either
// (a) directly calls `<x>.Allow(...)` or
// (b) calls a function declared in the same file whose body satisfies
//
//	(a) — i.e., a same-file authz helper. One level of indirection is
//
// enough for the wave-1 helper pattern (`h.authzGate -> h.authz.Allow`);
// deeper chains would let the chokepoint hide behind layers of
// abstraction the next reviewer cannot see at the handler call site.
func callsAllowTransitive(astFile *ast.File, handlerName string, gatedFns map[string]bool) bool {
	var fn *ast.FuncDecl
	for _, decl := range astFile.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name.Name == handlerName {
			fn = fd
			break
		}
	}
	if fn == nil || fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			// Direct .Allow(...) call OR a method on the receiver
			// known to call .Allow (e.g. h.authzGate).
			if f.Sel.Name == "Allow" {
				found = true
				return false
			}
			if gatedFns[f.Sel.Name] {
				found = true
				return false
			}
		case *ast.Ident:
			// Bare-call helper in the same file.
			if gatedFns[f.Name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// registeredHandlerMethods walks the file looking for
// `mux.HandleFunc("PATTERN", h.handlerMethod)` calls and returns a
// map of method name -> route pattern. The pattern is captured for
// the failure message so a violation surfaces "GET /api/policy
// (handler: handleGetPolicy)" without forcing the maintainer to grep.
func registeredHandlerMethods(astFile *ast.File) map[string]string {
	out := map[string]string{}
	ast.Inspect(astFile, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
			return true
		}
		if len(call.Args) != 2 {
			return true
		}
		pattern := stringLit(call.Args[0])
		if pattern == "" {
			return true
		}
		methodName := selectorMethodName(call.Args[1])
		if methodName == "" {
			return true
		}
		out[methodName] = pattern
		return true
	})
	return out
}

// stringLit extracts the literal value from a string-literal AST node.
// Returns "" if the node is anything else (e.g., a variable reference);
// the lint refuses to assert correctness for routes registered with
// computed patterns because the pattern's value isn't visible here.
func stringLit(expr ast.Expr) string {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return ""
	}
	return strings.Trim(bl.Value, `"`)
}

// selectorMethodName extracts the method name from a `recv.Method`
// selector expression passed as an HTTP handler reference. Returns ""
// for anything else (a closure, a top-level function, a higher-order
// expression); those forms aren't used by any wave-1 operator handler
// and would need their own lint shape.
func selectorMethodName(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return sel.Sel.Name
}
