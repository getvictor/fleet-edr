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
// constructed with a very small MinLineLen must NOT fire on content the
// default settings WOULD fire on. The narrow_silent fixture is a copy of
// narrow with the `// want` annotations stripped; if the custom Settings
// argument were ignored, the default 120-column floor would kick in and
// the analyzer would fire on those 3-line blocks, producing diagnostics
// that analysistest treats as unexpected and fails on. A clean run is
// only possible if the low MinLineLen actually silences the linter.
func TestCustomSettings(t *testing.T) {
	testdata := mustTestdataDir(t)
	// MinLineLen=1 means no realistic block ever fires (every // line is at least 2 chars wide), so the analyzer
	// stays silent regardless of how narrow the source comments are. The default-settings analyzer WOULD fire on
	// these blocks (their longest line is 4 chars, well below the 120-column default).
	low := lint.Settings{MinLineLen: 1, MinBlock: 3}
	t.Run("low_min_line_len_silences_narrow_blocks", func(t *testing.T) {
		analysistest.Run(t, testdata, lint.NewAnalyzer(&low), "narrow_silent")
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
