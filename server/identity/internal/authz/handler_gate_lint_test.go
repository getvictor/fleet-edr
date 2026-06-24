package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrivilegedHandlersGateOnAllow is the build-time gate the spec
// calls for in §"Architecture lint": every privileged handler
// registered on a session-authed mux MUST funnel through the AuthZ
// chokepoint before performing its side effect. The test parses each
// operator package's handler.go and asserts that every method
// referenced by `mux.HandleFunc(...)` reaches an `.Allow(...)` call
// (directly, via a same-file helper, or via the shared
// identityapi.HTTPGate wrapper).
//
// A privileged route registered without a chokepoint call is the
// exact regression the audit dashboard cannot recover from post-flip;
// "you forgot the Allow call" must fail at PR time, not in production.
//
// Scope: this lint runs against the wave-1 operator surface
// (identity audit, detection, rules, response, endpoint operator
// handlers). New operator packages SHALL be added to
// privilegedHandlerFiles.
func TestPrivilegedHandlersGateOnAllow(t *testing.T) {
	t.Parallel()
	repoRoot := repoRoot(t)
	for _, file := range privilegedHandlerFiles {
		t.Run(filepath.Base(filepath.Dir(file)), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(repoRoot, file)
			fset := token.NewFileSet()
			astFile, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
			require.NoError(t, err, "parse %s", path)

			gatedFns := functionsCallingChokepoint(astFile)
			handlers := registeredHandlerMethods(astFile)
			require.NotEmpty(t, handlers, "no mux.HandleFunc registrations found in %s; "+
				"the lint expects at least one privileged route per operator handler "+
				"file (and would otherwise pass vacuously, masking a regression)", file)

			for handler, route := range handlers {
				assert.True(t, handlerReachesChokepoint(astFile, handler, gatedFns),
					"%s: handler %q (registered for %q) must reach the AuthZ chokepoint "+
						"(.Allow / identityapi.HTTPGate) directly or via a same-file helper",
					filepath.Base(path), handler, route)
			}
		})
	}
}

// privilegedHandlerFiles lists every file the lint asserts is a privileged operator handler. Adding a new operator package without
// adding it here is itself a regression; add the path AND the chokepoint call together.
var privilegedHandlerFiles = []string{
	"server/identity/internal/audit/handler.go",
	"server/detection/internal/operator/handler.go",
	"server/rules/internal/operator/handler.go",
	"server/response/internal/operator/handler.go",
	"server/endpoint/internal/operator/handler.go",
}

// chokepointSelectors enumerates the selector method names that count as the AuthZ chokepoint. `Allow` is the AuthZ interface's
// method; `HTTPGate` is the shared wrapper in identity/api/authzhttp.go. Any expansion of the helper surface should be reflected here.
var chokepointSelectors = map[string]struct{}{
	"Allow":    {},
	"HTTPGate": {},
}

// repoRoot returns the absolute path of the repository root by deriving it from this source file's location at compile time. Using
// runtime.Caller (instead of os.Getwd-based path-suffix matching) keeps the lint correct under test runners that change the working
// directory and on filesystems with non-/-separators (#119 review).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must report this file's path")
	// This file lives at server/identity/internal/authz/<name>_test.go;
	// the repo root is four directories up.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

// functionsCallingChokepoint returns the set of function names declared in astFile whose body contains a call to a chokepoint
// selector. The helper that delegates to it (e.g. authzGate calling .Allow) is included so a same-file delegation chain still
// satisfies the lint.
func functionsCallingChokepoint(astFile *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, decl := range astFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if bodyCallsChokepoint(fn.Body, nil) {
			out[fn.Name.Name] = true
		}
	}
	return out
}

// handlerReachesChokepoint reports whether handlerName's body either calls a chokepoint selector directly or delegates to a same-file
// helper that does. One level of indirection is enough for the wave-1 helper pattern; deeper chains would let the chokepoint hide
// behind layers of abstraction the next reviewer cannot see at the handler call site.
func handlerReachesChokepoint(astFile *ast.File, handlerName string, gatedFns map[string]bool) bool {
	fn := findFuncDecl(astFile, handlerName)
	if fn == nil || fn.Body == nil {
		return false
	}
	return bodyCallsChokepoint(fn.Body, gatedFns)
}

// bodyCallsChokepoint walks node looking for a call expression that either matches a chokepoint selector directly, or invokes a
// same-file helper recorded in gatedFns. Returns true on the first match. Pass gatedFns=nil to skip the same-file-helper check (used
// when computing the gated-function set itself).
func bodyCallsChokepoint(node ast.Node, gatedFns map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isChokepointCall(call, gatedFns) {
			found = true
			return false
		}
		return true
	})
	return found
}

// isChokepointCall reports whether call is either a chokepoint
// selector (Allow / HTTPGate) or a call to a same-file gated helper.
func isChokepointCall(call *ast.CallExpr, gatedFns map[string]bool) bool {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		if _, ok := chokepointSelectors[f.Sel.Name]; ok {
			return true
		}
		if gatedFns[f.Sel.Name] {
			return true
		}
	case *ast.Ident:
		if gatedFns[f.Name] {
			return true
		}
	}
	return false
}

// findFuncDecl returns the FuncDecl whose Name matches name, or nil.
func findFuncDecl(astFile *ast.File, name string) *ast.FuncDecl {
	for _, decl := range astFile.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// registeredHandlerMethods walks the file looking for `mux.HandleFunc("PATTERN", h.handlerMethod)` calls and returns a map of
// method name -> route pattern. The pattern is captured for the failure message so a violation surfaces "GET /api/policy (handler:
// handleGetPolicy)" without forcing the maintainer to grep.
func registeredHandlerMethods(astFile *ast.File) map[string]string {
	out := map[string]string{}
	ast.Inspect(astFile, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		method, pattern, ok := extractRouteRegistration(call)
		if !ok {
			return true
		}
		out[method] = pattern
		return true
	})
	return out
}

// extractRouteRegistration returns (handlerMethodName, routePattern, true) when call is a `mux.HandleFunc(pattern, h.method)`
// expression with both arguments shaped as expected. Anything else (computed patterns, closure handlers) returns ok=false because the
// lint cannot assert correctness for those forms without symbolic analysis.
func extractRouteRegistration(call *ast.CallExpr) (string, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
		return "", "", false
	}
	if len(call.Args) != 2 {
		return "", "", false
	}
	pattern, ok := stringLitValue(call.Args[0])
	if !ok {
		return "", "", false
	}
	method, ok := selectorMethodName(call.Args[1])
	if !ok {
		return "", "", false
	}
	return method, pattern, true
}

// stringLitValue extracts the literal value from a string-literal AST node. Returns ok=false for anything else: the lint refuses to
// assert correctness for routes registered with computed patterns because the pattern's value isn't visible at AST time.
func stringLitValue(expr ast.Expr) (string, bool) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	// Strip surrounding quotes; raw + interpreted both have one byte
	// of quote on each end.
	raw := bl.Value
	if len(raw) < 2 {
		return "", false
	}
	return raw[1 : len(raw)-1], true
}

// selectorMethodName extracts the method name from a `recv.Method` selector expression passed as an HTTP handler reference. Returns
// ok=false for anything else (a closure, a top-level function, a higher-order expression); those forms aren't used by any wave-1
// operator handler and would need their own lint shape.
func selectorMethodName(expr ast.Expr) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	return sel.Sel.Name, true
}
