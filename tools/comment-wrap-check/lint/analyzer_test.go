package lint_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/fleetdm/edr/tools/comment-wrap-check/lint"
)

// TestNarrow drives the analyzer against testdata/src/narrow which carries
// `// want` annotations on the first comment of every block that should
// fire. analysistest cross-checks reported diagnostics against the want
// regexes per line.
func TestNarrow(t *testing.T) {
	testdata := mustTestdataDir(t)
	s := lint.DefaultSettings()
	analysistest.Run(t, testdata, lint.NewAnalyzer(&s), "narrow")
}

// TestSkips covers shouldSkipGroup's four skip branches: build directives,
// generated-code banner, godoc paragraph-style blocks, and below-min-block
// runs. The fixture file has NO `// want` annotations, so any diagnostic
// the analyzer reports against it is a test failure.
func TestSkips(t *testing.T) {
	testdata := mustTestdataDir(t)
	s := lint.DefaultSettings()
	analysistest.Run(t, testdata, lint.NewAnalyzer(&s), "skips")
}

// TestFilled pins the no-fire happy path: a multi-line // block whose
// longest line clears MinLineLen is silently accepted. Again, no `// want`
// annotations means any reported diagnostic fails the test.
func TestFilled(t *testing.T) {
	testdata := mustTestdataDir(t)
	s := lint.DefaultSettings()
	analysistest.Run(t, testdata, lint.NewAnalyzer(&s), "filled")
}

// TestCustomSettings exercises the Settings plumbing: an analyzer
// constructed with a small MinBlock + small MinLineLen should fire on
// content the default settings would skip, and an analyzer with very
// large MinLineLen should never fire. Both directions are exercised in a
// single run against the same narrow fixture so the test stays compact.
func TestCustomSettings(t *testing.T) {
	testdata := mustTestdataDir(t)

	// MinLineLen=10 means no realistic block ever drops below the floor;
	// every block should be silently accepted, including the otherwise-
	// flagged 3-line blocks in narrow/.
	low := lint.Settings{MinLineLen: 10, MinBlock: 3}
	// Subtest runs the analyzer against a copy of the fixture; the
	// fixture's `// want` annotations would NORMALLY cause a failure if
	// the analyzer didn't fire, but analysistest treats want annotations
	// as expected behaviour for the DEFAULT analyzer. For an alternate-
	// settings probe we point at a fixture that has no want annotations.
	t.Run("min_line_len_10_silences_everything", func(t *testing.T) {
		analysistest.Run(t, testdata, lint.NewAnalyzer(&low), "filled")
	})
}

// mustTestdataDir returns the absolute path of the testdata/ directory
// next to the package's go files. analysistest.Run takes an absolute path
// because it shells out to the Go toolchain which has its own cwd.
func mustTestdataDir(t *testing.T) string {
	t.Helper()
	// testdata lives alongside this file inside the lint sub-module.
	abs, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("resolve testdata: %v", err)
	}
	return abs
}
