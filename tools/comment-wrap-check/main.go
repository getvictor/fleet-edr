// comment-wrap-check is the standalone CLI form of the comment-wrap linter
// (issue #149). It runs the analyzer defined in the tools/comment-wrap-
// check/lint package via golang.org/x/tools/go/analysis/singlechecker so
// `go run ./tools/comment-wrap-check ./...` works without needing the
// custom golangci-lint binary built.
//
// In CI and in `task lint:go`, the analyzer runs inside the custom
// golangci-lint binary that `task lint:install` produces from the
// repo-root .custom-gcl.yml; the plugin entry point lives at
// tools/comment-wrap-check/lint/plugin.go. Both paths share the same
// *analysis.Analyzer so the heuristic, defaults, and diagnostic output
// stay in lockstep.
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/fleetdm/edr/tools/comment-wrap-check/lint"
)

func main() {
	s := lint.DefaultSettings()
	singlechecker.Main(lint.NewAnalyzer(&s))
}
