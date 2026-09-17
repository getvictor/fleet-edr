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

// Every Status this package declares maps onto the right one of the shared catch-up vocabulary.
//
// Two halves, deliberately. The expectation below is written out, because only a person can say that a failed command should be
// treated as failed: asserting merely that the result is one of the six would pass a mapping that sent StatusFailed to
// catchup.StatusPending, which turns a six-hour retry into never retrying. The set it is checked against is parsed from this
// package's source, because only the compiler knows what statuses exist: a hand-written list would go stale the moment one is added,
// leaving the new status unmapped and its hosts out of the sweep.
func TestStatus_CatchupMapsEveryDeclaredStatus(t *testing.T) {
	t.Parallel()
	want := map[string]catchup.Status{
		"StatusPending":   catchup.StatusPending,
		"StatusAcked":     catchup.StatusAcked,
		"StatusCompleted": catchup.StatusCompleted,
		"StatusFailed":    catchup.StatusFailed,
		"StatusExpired":   catchup.StatusExpired,
		"StatusCancelled": catchup.StatusCancelled,
	}
	declared := declaredStatuses(t)

	// Both directions. A status this package declares with no expectation is one nobody has decided the catch-up meaning of; an
	// expectation for a status that no longer exists is a stale test pretending to cover something.
	for name := range declared {
		assert.Contains(t, want, name, "api.%s is declared but this test says nothing about how it should be treated", name)
	}
	for name := range want {
		assert.Contains(t, declared, name, "this test expects api.%s, which this package no longer declares", name)
	}

	for name, value := range declared {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want[name], api.Status(value).Catchup(), "api.%s (%q) is not treated as %q by the catch-up",
				name, value, want[name])
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
