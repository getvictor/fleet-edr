// Command dash-lint fails when a spaced ASCII hyphen is used as an em dash (" - ", a hyphen with a space on both sides) in
// prose or in a comment / user-facing string. The repo style forbids the em-dash character (U+2014/U+2013, caught by
// tools/lint-no-emdash.sh) AND its spaced-hyphen stand-in: reword the sentence (prefer shorter sentences) or use ":".
//
// Scope (decided with the maintainer): Markdown prose plus code comments and string literals. It deliberately does NOT flag
// bare code expressions, where " - " is subtraction (`n - 1`): per file type it only inspects the parts that are prose.
//   - .md / .markdown: every line outside a fenced code block, with inline `code spans` stripped first. List-item markers and
//     table separator rows do not match the pattern and so are never flagged.
//   - .go: COMMENT and STRING/CHAR tokens only, via go/scanner (exact). Doc() rule descriptions and other user-facing string
//     literals are in scope; arithmetic in code is not.
//   - .swift / .ts / .tsx / .js / .jsx / .c / .h / .m / .mm: // line comments and /* block comments */ only.
//
// Run via `task lint:dashes`; CI gate is .github/workflows/no-emdash.yml. With no file arguments it lints every tracked file
// (`git ls-files`); otherwise it lints the paths it is given (used by the lefthook pre-commit hook on staged files).
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// maxLineBytes bounds the bufio.Scanner buffer. proseWrap: never makes Markdown paragraphs single (long) lines, so the
// default 64 KB token cap is raised well past any realistic paragraph or comment line.
const maxLineBytes = 4 * 1024 * 1024

// emDashUse matches a hyphen with a space on both sides, preceded by a non-space, non-hyphen character: the "word - clause"
// shape. The leading [^\s-] is what keeps list markers ("  - item") and "---" rules / separators from matching.
var emDashUse = regexp.MustCompile(`[^\s-] - `)

// inlineCodeSpan matches a Markdown inline code span so it can be blanked before scanning (a span may legitimately contain
// " - ", e.g. a CLI example or a subtraction).
var inlineCodeSpan = regexp.MustCompile("`[^`]*`")

// fenceLine matches the opening or closing line of a fenced code block (``` or ~~~, optionally indented, with an info string).
var fenceLine = regexp.MustCompile("^\\s*(```|~~~)")

func main() {
	files := os.Args[1:]
	if len(files) == 0 {
		var err error
		files, err = trackedFiles()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dash-lint:", err)
			os.Exit(2)
		}
	}

	var findings []string
	for _, path := range files {
		data, err := os.ReadFile(path) //nolint:gosec // G304: dash-lint exists to read the tracked files it is handed.
		if err != nil {
			continue // deleted-from-index path handed in by a hook, etc.
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".md", ".markdown":
			findings = append(findings, checkMarkdown(path, data)...)
		case ".go":
			findings = append(findings, checkGo(path, data)...)
		case ".swift", ".ts", ".tsx", ".js", ".jsx", ".c", ".h", ".m", ".mm":
			findings = append(findings, checkCStyleComments(path, data)...)
		}
	}

	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, f)
		}
		fmt.Fprintf(os.Stderr,
			"::error::%d spaced-hyphen em dash(es) above. Reword the sentence (prefer shorter sentences) or use ':'. A hyphen is only allowed unspaced inside a compound word (per-IP) or as a list marker.\n",
			len(findings))
		os.Exit(1)
	}
}

// isExcluded mirrors the ignore set of the other prose gates (.markdownlint-cli2.yaml, .prettierignore): AI-tool config we do
// not author, the immutable archived OpenSpec change proposals (format owned upstream, an audit trail we do not rewrite), and
// the free-form maintenance journal. docs/detection-rules.md is intentionally NOT excluded: it is generated from rule Doc()
// strings (which this gate does cover), so `task docs:rules` keeps it clean.
func isExcluded(p string) bool {
	return strings.HasPrefix(p, ".claude/") ||
		strings.HasPrefix(p, "openspec/changes/") ||
		strings.HasPrefix(p, "tools/dash-lint/") || // never scan the scanner: its doc comments and test fixtures hold the pattern by design
		p == "docs/maintenance/log.md"
}

func trackedFiles() ([]string, error) {
	out, err := exec.CommandContext(context.Background(), "git", "ls-files", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var files []string
	for b := range bytes.SplitSeq(out, []byte{0}) {
		if len(b) == 0 {
			continue
		}
		p := string(b)
		if isExcluded(p) {
			continue
		}
		files = append(files, p)
	}
	return files, nil
}

// checkMarkdown flags em-dash use in Markdown prose: every line outside a fenced code block, with inline code spans removed.
func checkMarkdown(path string, data []byte) []string {
	var findings []string
	inFence := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		if fenceLine.MatchString(raw) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		stripped := inlineCodeSpan.ReplaceAllString(raw, " ")
		if emDashUse.MatchString(stripped) {
			findings = append(findings, fmt.Sprintf("%s:%d: %s", path, lineNo, strings.TrimSpace(raw)))
		}
	}
	return findings
}

// checkGo lexes the file and flags em-dash use inside comment, string, and char tokens only (never bare code).
func checkGo(path string, data []byte) []string {
	var findings []string
	fset := token.NewFileSet()
	file := fset.AddFile(path, fset.Base(), len(data))
	var s scanner.Scanner
	s.Init(file, data, nil /* ignore lex errors */, scanner.ScanComments)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		// Only prose-bearing tokens: comments, string literals (Doc() descriptions, UI text), and char literals. Never bare
		// code, where " - " is subtraction.
		if tok == token.COMMENT || tok == token.STRING || tok == token.CHAR {
			if emDashUse.MatchString(lit) {
				p := fset.Position(pos)
				findings = append(findings, fmt.Sprintf("%s:%d: %s", path, p.Line, strings.TrimSpace(firstLine(lit))))
			}
		}
	}
	return findings
}

// checkCStyleComments flags em-dash use inside // line comments and /* block comments */, ignoring code and string literals.
func checkCStyleComments(path string, data []byte) []string {
	var findings []string
	inBlock := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		var commentText string
		switch {
		case inBlock:
			if before, _, closed := strings.Cut(raw, "*/"); closed {
				commentText = before
				inBlock = false
			} else {
				commentText = raw
			}
		default:
			if _, afterOpen, found := strings.Cut(raw, "/*"); found {
				if inner, _, closed := strings.Cut(afterOpen, "*/"); closed {
					commentText = inner
				} else {
					commentText = afterOpen
					inBlock = true
				}
			} else if idx := lineCommentStart(raw); idx >= 0 {
				commentText = raw[idx:]
			}
		}
		if commentText != "" && emDashUse.MatchString(commentText) {
			findings = append(findings, fmt.Sprintf("%s:%d: %s", path, lineNo, strings.TrimSpace(raw)))
		}
	}
	return findings
}

// lineCommentStart returns the index of a // line comment that is not part of a "://" scheme (a crude but effective guard
// against matching inside URLs in string literals); -1 if there is none.
func lineCommentStart(line string) int {
	for i := 0; i+1 < len(line); i++ {
		if line[i] == '/' && line[i+1] == '/' {
			if i > 0 && line[i-1] == ':' {
				continue // e.g. https://
			}
			return i
		}
	}
	return -1
}

func firstLine(s string) string {
	before, _, _ := strings.Cut(s, "\n")
	return before
}
