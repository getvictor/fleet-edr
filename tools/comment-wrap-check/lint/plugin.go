// Plugin entry point for golangci-lint v2's module-plugin machinery.
//
// How this is wired:
//
//   - This package is imported by the custom golangci-lint binary that
//     `golangci-lint custom` builds from .custom-gcl.yml. The import
//     triggers init() below, which registers "commentwrap" in golangci-
//     lint's global plugin registry under the standard contract:
//     `New(settings any) (register.LinterPlugin, error)`.
//   - golangci-lint reads .golangci.yml's `linters.settings.custom.
//     commentwrap.settings` block, hands it to New, gets a LinterPlugin
//     back, then calls BuildAnalyzers() to obtain the analyzer(s) the
//     plugin contributes.
//   - LoadModeSyntax is what we ask for: the analyzer needs AST + source
//     bytes, no type information. Syntax-only mode is faster and keeps
//     the plugin out of the type-checking critical path.
//
// The plugin is a thin shell over NewAnalyzer; the actual heuristic lives
// in analyzer.go. The standalone CLI at tools/comment-wrap-check/main.go
// uses NewAnalyzer directly without going through this plugin shim.
package lint

import (
	"fmt"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
)

func init() {
	register.Plugin("commentwrap", New)
}

// New is the factory golangci-lint's plugin loader calls. Settings is the
// YAML body from .golangci.yml's `linters.settings.custom.commentwrap.
// settings` block, decoded by golangci-lint into a Go map; we round-trip
// it through register.DecodeSettings into the typed Settings struct.
func New(settings any) (register.LinterPlugin, error) {
	s, err := register.DecodeSettings[Settings](settings)
	if err != nil {
		return nil, fmt.Errorf("commentwrap: decode settings: %w", err)
	}
	// Apply defaults for any zero-valued field; an operator who configures
	// only one of the two knobs gets the project default for the other.
	// Reject negative values so a typo like `min-line-len: -120` fails at
	// load time with a clear error rather than silently disabling the
	// linter (every block's longest line is >= 0, so a negative floor
	// means the analyzer never fires).
	if s.MinLineLen == 0 {
		s.MinLineLen = DefaultMinLineLen
	}
	if s.MinBlock == 0 {
		s.MinBlock = DefaultMinBlock
	}
	if s.MinLineLen < 1 {
		return nil, fmt.Errorf("commentwrap: min-line-len must be >= 1, got %d", s.MinLineLen)
	}
	if s.MinBlock < 1 {
		return nil, fmt.Errorf("commentwrap: min-block must be >= 1, got %d", s.MinBlock)
	}
	return &commentwrapPlugin{settings: s}, nil
}

type commentwrapPlugin struct {
	settings Settings
}

// BuildAnalyzers returns the analyzer(s) this plugin contributes. We
// contribute exactly one: NewAnalyzer with the resolved settings.
func (p *commentwrapPlugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	// Take the address of the field so the analyzer's Flags can mutate
	// in place if golangci-lint exposes flag overrides (it currently
	// does not for module plugins, but the API is consistent with the
	// standalone CLI's pattern).
	return []*analysis.Analyzer{NewAnalyzer(&p.settings)}, nil
}

// GetLoadMode tells golangci-lint how much of the program model to
// materialise before invoking this plugin's analyzer. Syntax is enough
// for comment-wrap analysis: we touch *ast.CommentGroup and source
// bytes, never types.
func (p *commentwrapPlugin) GetLoadMode() string {
	return register.LoadModeSyntax
}
