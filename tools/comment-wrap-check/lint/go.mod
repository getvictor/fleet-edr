// Sub-module for the commentwrap golangci-lint v2 plugin. golangci-lint's
// `custom` command expects each plugin to be its own Go module (with its
// own go.mod), so this directory lives one logical level below the parent
// repo module. The parent's go.mod has a `replace` directive that points
// this module's import path back to the on-disk source so the parent's
// standalone CLI at tools/comment-wrap-check/main.go can import it
// without publishing.
//
// External deps are intentionally minimal: just the analysis interface
// and the golangci-lint plugin registrar.
module github.com/fleetdm/edr/tools/comment-wrap-check/lint

go 1.26.3

require (
	github.com/golangci/plugin-module-register v0.1.2
	golang.org/x/tools v0.44.0
)

require (
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
)
