package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/catchup"
	"github.com/fleetdm/edr/server/response/api"
)

// declaredStatuses reads every Status constant out of this package's own source.
//
// Parsed rather than listed, and that is the point of the test. A hand-written list is only as current as whoever last remembered to
// add to it: a new Status would leave the list green while Catchup fell through to the empty string, and the shared catch-up leaves a
// status it does not recognize alone, so the sweep would silently stop resending to every host holding a command in that status.
// Making the source authoritative means adding a constant without mapping it fails here.
func declaredStatuses(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, perr)
		files = append(files, file)
	}
	require.NotEmpty(t, files, "no source files were found; the parser is looking in the wrong place")

	out := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				ident, ok := vs.Type.(*ast.Ident)
				if !ok || ident.Name != "Status" || len(vs.Names) != len(vs.Values) {
					continue
				}
				for i, name := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					require.NoError(t, err)
					out[name.Name] = value
				}
			}
		}
	}
	require.NotEmpty(t, out, "no Status constants were found; the parser is looking in the wrong place")
	return out
}

// Every Status this package declares maps onto one the shared catch-up decision knows. A case missing from Status.Catchup fails here
// rather than quietly taking one host's commands, or the whole fleet's, out of the sweep.
func TestStatus_CatchupMapsEveryDeclaredStatus(t *testing.T) {
	t.Parallel()
	known := map[catchup.Status]bool{
		catchup.StatusPending: true, catchup.StatusAcked: true, catchup.StatusCompleted: true,
		catchup.StatusFailed: true, catchup.StatusExpired: true, catchup.StatusCancelled: true,
	}
	declared := declaredStatuses(t)
	// The six the command lifecycle has today. Pinned so a constant being REMOVED is also visible here, which the parse alone cannot
	// tell from a constant that never existed.
	assert.Len(t, declared, 6, "the command lifecycle gained or lost a status: %v", declared)

	for name, value := range declared {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := api.Status(value).Catchup()
			assert.True(t, known[got], "api.%s (%q) maps to %q, which the shared catch-up decision does not know", name, value, got)
		})
	}
}

// A status no version of this package declares maps to nothing, which is what makes the catch-up leave a newer replica's command
// alone rather than fight it.
func TestStatus_CatchupLeavesAnUnknownStatusUnmapped(t *testing.T) {
	t.Parallel()
	assert.Empty(t, api.Status("quarantined").Catchup())
	assert.Empty(t, api.Status("").Catchup())
	assert.False(t, strings.EqualFold(string(api.StatusPending), "quarantined"))
}
