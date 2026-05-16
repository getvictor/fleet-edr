// Package lint is the comment-wrap-check linter, exposed as a `go/analysis`
// Analyzer so it can run inside golangci-lint v2 (via the module-plugin
// machinery in plugin.go) and as a standalone `singlechecker` binary
// (tools/comment-wrap-check/main.go).
//
// Heuristic: for each multi-line `//` comment group of N >= Settings.MinBlock
// lines, compute the longest rendered line's visual column width (tabs
// expanded to 8, CR stripped). If the longest line falls below
// Settings.MinLineLen, every line in the block is conspicuously short and
// the block was wrapped narrowly (typically at 80). Per-block reporting is
// intentional: one diagnostic per offending block, not N-1 per-line.
//
// What this linter deliberately does NOT do:
//
//   - Auto-rewrap. Comment semantics matter (godoc links, code samples,
//     bullet lists), so the fix sweep is a human / AI judgement call.
//   - Fire on godoc paragraph-style comments. A block that contains a
//     blank `//` separator is treated as deliberate paragraph-formatted
//     prose and skipped.
//   - Touch /* */ block comments. The heuristic does not generalise.
//   - Touch markdown prose. CLAUDE.md's 140-char rule covers both, but
//     issue #149 is scoped to source comments.
package lint

import (
	"go/ast"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Default settings, matched at the linter PR + sweep PR cleanup completion.
const (
	// DefaultMinLineLen is the visual-column floor below which a block's
	// longest line counts as "narrowly wrapped". CLAUDE.md sets the wrap
	// target at 140 characters; 120 matches the literal spec in issue #149
	// ("wrap at least 120 characters and not 80"). Twenty columns below
	// the 140 cap is a tight feedback envelope: blocks wrapped at the old
	// 80 target land well below, and blocks wrapped near the 140 cap stay
	// safely above.
	DefaultMinLineLen = 120
	// DefaultMinBlock is the minimum number of consecutive `//` lines for
	// a group to be considered. 3 matches the issue's "comment blocks that
	// are 3 lines or longer" framing.
	DefaultMinBlock = 3
	// tabWidth matches the gofmt convention: a tab advances the cursor to
	// the next multiple of 8 columns.
	tabWidth = 8
)

// Settings carries the analyzer's tunable knobs. Both the standalone CLI and
// the golangci-lint plugin construct an Analyzer with a Settings value: the
// CLI populates it from -min-line-len / -min-block flags, the plugin
// populates it from .golangci.yml's linters.settings.custom.commentwrap.
type Settings struct {
	MinLineLen int `json:"min-line-len"`
	MinBlock   int `json:"min-block"`
}

// DefaultSettings returns the Settings the CLI and plugin both start from.
// Callers override either field via flags (CLI) or YAML (plugin).
func DefaultSettings() Settings {
	return Settings{
		MinLineLen: DefaultMinLineLen,
		MinBlock:   DefaultMinBlock,
	}
}

// NewAnalyzer constructs a *analysis.Analyzer that fires the comment-wrap
// heuristic under the supplied settings. The settings struct is captured by
// the Run closure so callers can mutate it via the analyzer's Flags before
// the analyzer runs (the standalone CLI does this).
func NewAnalyzer(s *Settings) *analysis.Analyzer {
	a := &analysis.Analyzer{
		Name: "commentwrap",
		Doc:  "Detect narrowly-wrapped Go `//` comment blocks (issue #149).",
		URL:  "https://github.com/getvictor/fleet-edr/issues/149",
		Run: func(pass *analysis.Pass) (any, error) {
			return runPass(pass, s)
		},
	}
	a.Flags.IntVar(&s.MinLineLen, "min-line-len", s.MinLineLen,
		"flag blocks of >=min-block consecutive // comment lines whose longest line falls below this visual width")
	a.Flags.IntVar(&s.MinBlock, "min-block", s.MinBlock,
		"minimum number of consecutive // comment lines for a group to be considered")
	return a
}

// runPass is the per-package analyzer body. golangci-lint calls Analyzer.Run
// once per Go package; pass.Files is that package's AST, pass.Fset gives us
// position info, and pass.Reportf emits each finding in the format every
// downstream consumer (editors, CI annotators, golangci-lint's output
// formatters) already understands.
func runPass(pass *analysis.Pass, s *Settings) (any, error) {
	// Cache source bytes per file so a package with N comment groups across
	// M files still only does M file reads. The pass's Fset gives us the
	// concrete on-disk path each *ast.File came from.
	fileLines := make(map[string][]string)
	getLines := func(path string) []string {
		if lines, ok := fileLines[path]; ok {
			return lines
		}
		data, err := os.ReadFile(path) //nolint:gosec // pass-supplied file path
		if err != nil {
			fileLines[path] = nil
			return nil
		}
		lines := strings.Split(string(data), "\n")
		fileLines[path] = lines
		return lines
	}

	for _, file := range pass.Files {
		path := pass.Fset.File(file.Pos()).Name()
		lines := getLines(path)
		if lines == nil {
			continue
		}
		for _, g := range file.Comments {
			if shouldSkipGroup(g.List, s.MinBlock) {
				continue
			}
			maxLen := maxLineWidth(g.List, pass, lines)
			if maxLen >= s.MinLineLen {
				continue
			}
			pass.Reportf(g.List[0].Slash,
				"comment block of %d lines wrapped narrowly (longest line %d chars; expected at least %d)",
				len(g.List), maxLen, s.MinLineLen)
		}
	}
	return nil, nil
}

// shouldSkipGroup pulls the four-branch filter out of runPass: too-short
// blocks, non-`//` (block) comments, build / generated-code directives, and
// godoc paragraph-style blocks all bypass the narrowness check.
func shouldSkipGroup(list []*ast.Comment, minBlock int) bool {
	if len(list) < minBlock {
		return true
	}
	first := list[0].Text
	if !strings.HasPrefix(first, "//") {
		return true
	}
	if strings.HasPrefix(first, "//go:") || strings.HasPrefix(first, "// Code generated") {
		return true
	}
	return hasGodocBlank(list)
}

// hasGodocBlank reports whether the block contains a blank `//` line, the
// standard godoc paragraph separator. A block using paragraph formatting is
// deliberate prose: the wrap target legitimately varies line by line.
func hasGodocBlank(list []*ast.Comment) bool {
	for _, c := range list {
		if strings.TrimSpace(strings.TrimPrefix(c.Text, "//")) == "" {
			return true
		}
	}
	return false
}

// maxLineWidth returns the maximum visual column width across the block's
// source lines. Visual width respects tab expansion and ignores trailing
// whitespace / CR; see visualWidth.
func maxLineWidth(list []*ast.Comment, pass *analysis.Pass, lines []string) int {
	maxLen := 0
	for _, c := range list {
		idx := pass.Fset.Position(c.Slash).Line - 1
		if idx < 0 || idx >= len(lines) {
			continue
		}
		w := visualWidth(lines[idx])
		if w > maxLen {
			maxLen = w
		}
	}
	return maxLen
}

// visualWidth returns the on-screen column count of s under the gofmt
// convention. Trailing space, tab, and CR are stripped (so CRLF files do
// not report +1 columns and trailing whitespace is not counted). Tabs
// advance to the next multiple of tabWidth, matching how the standard Go
// tooling renders source. Multi-byte UTF-8 runes count as one column each
// (the common cases in this codebase are em-dashes and the Unicode arrow,
// both single-column glyphs); East Asian double-width is not modelled
// because the codebase contains none.
//
// Pure-whitespace inputs are NOT a meaningful case for the linter (every
// comment line has `// content` after any indent), so the trim-trailing
// branch here cannot collapse the whole string to zero in practice. The
// cleanup-sweep PR's tmp/ rewriter learned that the hard way when it
// called this on a pure-tab indent string; the rewriter computes indent
// width directly without calling visualWidth for the same reason.
func visualWidth(s string) int {
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c != ' ' && c != '\t' && c != '\r' {
			break
		}
		end--
	}
	width := 0
	for _, r := range s[:end] {
		if r == '\t' {
			width += tabWidth - (width % tabWidth)
		} else {
			width++
		}
	}
	return width
}
