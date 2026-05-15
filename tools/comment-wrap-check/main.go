// comment-wrap-check audits Go source for narrowly-wrapped `//` comment blocks
// of three or more consecutive lines. CLAUDE.md tells contributors to wrap
// comments at 140 characters; issue #149 surfaced that many older blocks were
// wrapped at 80 instead, leaving the lines visibly ragged and the file longer
// than it needs to be.
//
// Heuristic: for each multi-line `//` comment group of N >= -min-block lines,
// compute the longest rendered line's visual column width (tabs expanded to 8,
// CR stripped). If the longest line falls below -min-line-len, every line in
// the block is conspicuously short and the block was wrapped narrowly
// (typically at 80). Per-block reporting is intentional, so a wrapped-at-80
// block produces ONE entry rather than N-1 noisy per-line entries.
//
// What this tool deliberately does NOT do:
//
//   - Auto-rewrap. Comment semantics matter (godoc links, code samples,
//     bullet lists), so the fix sweep is a human/AI judgement call per file.
//   - Fire on godoc paragraph-style comments. A block that contains a
//     blank `//` separator is treated as paragraph-formatted prose and
//     skipped, so a short summary line followed by a blank and a longer
//     paragraph does not trip the heuristic.
//   - Touch /* */ block comments. Those are vanishingly rare in this repo
//     and the heuristic above does not generalise to them.
//   - Touch markdown prose. CLAUDE.md's 140-char rule covers both, but
//     issue #149 is scoped to source comments.
//
// Default exit code is 0 even when offenders are found, so the tool can be
// invoked manually (`task lint:comments`) without blocking the lint
// aggregate. Pass -fail to flip that for a future CI gate once the existing
// offender count has been driven to zero.
package main

import (
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// defaultMinLineLen is the visual-column floor below which a block's longest line counts as "narrowly wrapped".
	// CLAUDE.md sets the project wrap target at 140 characters; 100 sits 40 columns below that, comfortably above the
	// old 80-character target, so blocks wrapped at 80 land below the floor and blocks wrapped anywhere near 140 stay
	// safely above it.
	defaultMinLineLen = 100
	defaultMinBlock   = 3
	// tabWidth matches the gofmt convention: a tab advances the cursor to the next multiple of 8 columns. This is the
	// width assumed when computing visual line length so deeply-indented short comments are not flagged for false
	// reasons (the byte length would understate their on-screen width).
	tabWidth = 8
)

type config struct {
	minLineLen int
	minBlock   int
	failOn     bool
}

// rawComment is the minimum each comment scanComments needs: the verbatim `//`-prefixed text and the 1-indexed source
// line. Keeping the heuristic over this small struct (rather than over *ast.CommentGroup directly) makes the tests
// trivial to author without round-tripping through go/parser.
type rawComment struct {
	line int
	text string
}

func main() {
	var cfg config
	flag.IntVar(&cfg.minLineLen, "min-line-len", defaultMinLineLen,
		"flag blocks of >=min-block consecutive // comment lines whose longest line falls below this visual width. "+
			"The repo wrap target is 140 chars per CLAUDE.md; the default 100 is the narrowly-wrapped threshold.")
	flag.IntVar(&cfg.minBlock, "min-block", defaultMinBlock,
		"minimum number of consecutive // comment lines for a group to be considered")
	flag.BoolVar(&cfg.failOn, "fail", false,
		"exit 1 if any offenders are found (default is to report and exit 0 so the tool stays non-blocking)")
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	hits := walk(os.Stdout, os.Stderr, roots, cfg)
	if hits > 0 && cfg.failOn {
		os.Exit(1)
	}
}

// walk scans every .go file under each root and writes one line per offender to stdout. Returns the total offender
// count. Parse errors for individual files log to stderr and continue; one bad file should not break the lint sweep
// across the rest of the repo.
func walk(stdout, stderr io.Writer, roots []string, cfg config) int {
	var hits int
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			return visit(stdout, stderr, path, d, err, &hits, cfg)
		})
		if err != nil {
			fmt.Fprintf(stderr, "root %s: %v\n", root, err)
		}
	}
	return hits
}

// visit is the WalkDir callback split out so walk() stays simple (and below Sonar's cognitive-complexity floor). It
// runs filtering, directory-skip logic, and scan-or-skip in sequence; each branch returns early.
func visit(stdout, stderr io.Writer, path string, d fs.DirEntry, walkErr error, hits *int, cfg config) error {
	if walkErr != nil {
		fmt.Fprintf(stderr, "walk %s: %v\n", path, walkErr)
		return nil
	}
	if d.IsDir() {
		if skipDir(d.Name()) {
			return filepath.SkipDir
		}
		return nil
	}
	if filepath.Ext(path) != ".go" {
		return nil
	}
	n, scanErr := scanFile(stdout, path, cfg)
	if scanErr != nil {
		fmt.Fprintf(stderr, "scan %s: %v\n", path, scanErr)
		return nil
	}
	*hits += n
	return nil
}

// skipDir is the directory name list we never descend into. vendor/ and node_modules/ are obvious; .git/ would be a
// long detour for zero hits; tmp/ and ai/ are scratch areas already in .gitignore that nothing imports.
func skipDir(name string) bool {
	switch name {
	case "vendor", "node_modules", ".git", "tmp", "ai", "dist", "build", "DerivedData":
		return true
	}
	return false
}

func scanFile(out io.Writer, path string, cfg config) (int, error) {
	data, err := os.ReadFile(path) //nolint:gosec // walking caller-supplied roots, intentional
	if err != nil {
		return 0, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, parser.ParseComments)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")

	groups := make([][]rawComment, 0, len(file.Comments))
	for _, g := range file.Comments {
		rg := make([]rawComment, 0, len(g.List))
		for _, c := range g.List {
			rg = append(rg, rawComment{
				line: fset.Position(c.Pos()).Line,
				text: c.Text,
			})
		}
		groups = append(groups, rg)
	}
	return scanComments(out, path, groups, lines, cfg), nil
}

// scanComments is the testable core: given the comment groups parsed from path and the file's original source lines,
// write per-block offender entries to out and return the offender count.
func scanComments(out io.Writer, path string, groups [][]rawComment, lines []string, cfg config) int {
	var hits int
	for _, g := range groups {
		if shouldSkipGroup(g, cfg.minBlock) {
			continue
		}
		maxLen := maxLineWidth(g, lines)
		if maxLen < cfg.minLineLen {
			fmt.Fprintf(out, "%s:%d: comment block of %d lines wrapped narrowly (longest line %d chars; expected at least %d)\n",
				path, g[0].line, len(g), maxLen, cfg.minLineLen)
			hits++
		}
	}
	return hits
}

// shouldSkipGroup pulls the four-branch filter out of scanComments so the main loop stays linear: too-short blocks,
// non-`//` (block) comments, build / generated-code directives, and godoc paragraph-style blocks all bypass the
// narrowness check.
func shouldSkipGroup(g []rawComment, minBlock int) bool {
	if len(g) < minBlock {
		return true
	}
	first := g[0].text
	if !strings.HasPrefix(first, "//") {
		return true
	}
	if strings.HasPrefix(first, "//go:") || strings.HasPrefix(first, "// Code generated") {
		return true
	}
	return hasGodocBlank(g)
}

// hasGodocBlank reports whether the block contains a blank `//` line, the standard godoc paragraph separator. A block
// using paragraph formatting is treated as deliberate prose: the wrap target legitimately varies line by line.
func hasGodocBlank(g []rawComment) bool {
	for _, c := range g {
		if strings.TrimSpace(strings.TrimPrefix(c.text, "//")) == "" {
			return true
		}
	}
	return false
}

// maxLineWidth returns the maximum visual column width across the block's source lines. Visual width respects tab
// expansion and ignores trailing whitespace / CR; see visualWidth.
func maxLineWidth(g []rawComment, lines []string) int {
	maxLen := 0
	for _, c := range g {
		idx := c.line - 1
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

// visualWidth returns the on-screen column count of s under the gofmt convention. Trailing space, tab, and CR are
// stripped (so CRLF files do not report +1 columns and trailing whitespace is not counted). Tabs advance to the next
// multiple of tabWidth, matching how the standard Go tooling renders source.
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
	for i := range end {
		if s[i] == '\t' {
			width += tabWidth - (width % tabWidth)
		} else {
			width++
		}
	}
	return width
}
