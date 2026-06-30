// Command dash-lint fails when a spaced ASCII hyphen is used as an em dash (" - " or " -- ", a hyphen / double-hyphen with a
// space on both sides) in prose or in a comment / user-facing string. The repo style forbids the em-dash character
// (U+2014/U+2013, caught by tools/lint-no-emdash.sh) AND its spaced-hyphen stand-in: reword the sentence (prefer shorter
// sentences) or use ":".
//
// Scope (decided with the maintainer): Markdown prose plus code comments and string literals. It deliberately does NOT flag
// bare code expressions, where " - " is subtraction (`n - 1`): per file type it only inspects the parts that are prose.
//   - .md / .markdown: every line outside a fenced code block, with inline `code spans` stripped first. List-item markers and
//     table separator rows do not match the pattern and so are never flagged.
//   - .go: COMMENT and STRING/CHAR tokens only, via go/scanner (exact). Doc() rule descriptions and other user-facing string
//     literals are in scope; arithmetic in code is not. Inline `code spans` inside comments are stripped first.
//   - .swift / .ts / .tsx / .js / .jsx / .c / .h / .m / .mm: // line comments and /* block comments */ only, code spans stripped.
//   - .yml / .yaml / .sh: the #-comment portion of each line only, code spans stripped (workflow / compose / config / script prose).
//
// A legitimate " -- " (a GNU end-of-options separator in a CLI example, e.g. `task uat:l5 -- attack-runbook`) wrapped in `code
// span` backticks is exempt because code spans are stripped before scanning. For the rare case a backtick wrap is not suitable,
// a line containing the literal "dash-lint:ignore" directive is skipped entirely; see ignoreDirective.
//
// Run via `task lint:dashes`; CI gate is .github/workflows/no-emdash.yml. With file arguments it lints those paths; with none
// it reads a NUL-delimited file list from stdin (the Taskfile and CI pipe `git ls-files -z` into it, keeping git out of this
// process so it is not a command-execution surface). Either way, paths in the exclude set are skipped.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// maxLineBytes bounds the bufio.Scanner buffer. proseWrap: never makes Markdown paragraphs single (long) lines, so the
// default 64 KB token cap is raised well past any realistic paragraph or comment line.
const maxLineBytes = 4 * 1024 * 1024

// findingFmt is the "file:line: snippet" shape every finding is reported in.
const findingFmt = "%s:%d: %s"

// emDashUse matches one or two hyphens with a space on both sides, preceded by a non-space, non-hyphen character: the
// "word - clause" / "word -- clause" shape. The leading [^\s-] is what keeps list markers ("  - item") and "---" rules /
// separators from matching, and -{1,2} (not -+) is what keeps a "---" horizontal rule ("a --- b") from matching: the third
// hyphen leaves no trailing space for the pattern to consume.
var emDashUse = regexp.MustCompile(`[^\s-] -{1,2} `)

// ignoreDirective, when present anywhere on a line, suppresses every finding on that line. It is the explicit escape hatch for
// a real " -- " that is neither prose nor a backtick-wrappable code span (e.g. an ASCII diagram). Wrapping a CLI example in
// `code span` backticks is the preferred fix; reach for this only when that does not fit.
const ignoreDirective = "dash-lint:ignore"

// inlineCodeSpan matches a Markdown inline code span so it can be blanked before scanning (a span may legitimately contain
// " - ", e.g. a CLI example or a subtraction).
var inlineCodeSpan = regexp.MustCompile("`[^`]*`")

// lintDirectiveDescSep matches the " -- " that ESLint and gosec require to separate a suppression directive from its human
// description (`eslint-disable-next-line rule -- why`, `#nosec G101 -- why`). That double-hyphen is mandated tool syntax, not
// an em-dash stand-in, so it is blanked before scanning; any em dash in the description text after it is still caught.
var lintDirectiveDescSep = regexp.MustCompile(`((?:eslint-(?:disable|enable)\S*|#nosec)\b.*?) -- `)

// fenceLine matches the opening or closing line of a fenced code block (``` or ~~~, optionally indented, with an info string).
var fenceLine = regexp.MustCompile("^\\s*(```|~~~)")

func main() {
	paths := os.Args[1:]
	if len(paths) == 0 {
		var err error
		paths, err = readPathsFromStdin()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dash-lint:", err)
			os.Exit(2)
		}
	}

	var findings []string
	for _, path := range paths {
		if isExcluded(path) {
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: dash-lint exists to read the tracked files it is handed.
		if err != nil {
			continue // deleted-from-index path handed in by a hook, etc.
		}
		findings = append(findings, checkFile(path, data)...)
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

// generatedMarker matches the standard Go "this file is machine-generated" line (golang.org/s/generatedcode), which protoc-gen-go,
// protoc-gen-go-grpc, stringer, and friends emit. golangci-lint already skips such files (generated: strict); this gate does too, so a
// generated header's ` - protoc` version list is not flagged as a spaced-hyphen em dash.
var generatedMarker = regexp.MustCompile(`(?m)^// Code generated .* DO NOT EDIT\.$`)

// checkFile dispatches one file to the checker for its extension, isolating the prose-bearing parts per file type. An
// unrecognized extension yields no findings (the file is not prose this gate understands). Machine-generated source is skipped: it
// is not hand-authored prose, and its tool-emitted headers can carry punctuation this gate would otherwise flag.
func checkFile(path string, data []byte) []string {
	if generatedMarker.Match(data) {
		return nil
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown":
		return checkMarkdown(path, data)
	case ".go":
		return checkGo(path, data)
	case ".swift", ".ts", ".tsx", ".js", ".jsx", ".c", ".h", ".m", ".mm":
		return checkCStyleComments(path, data)
	case ".yml", ".yaml", ".sh":
		return checkHashComments(path, data)
	}
	return nil
}

// isExcluded mirrors the ignore set of the other prose gates (.markdownlint-cli2.yaml, .prettierignore): AI-tool config we do
// not author, the immutable archived OpenSpec change proposals (format owned upstream, an audit trail we do not rewrite), the
// free-form maintenance journal, and the vendored / generated API-docs embed assets (the minified ReDoc bundle and generated
// OpenAPI spec, none of which is hand-authored prose). docs/detection-rules.md is intentionally NOT excluded: it is generated
// from rule Doc() strings (which this gate does cover), so `task docs:rules` keeps it clean.
func isExcluded(p string) bool {
	return strings.HasPrefix(p, ".claude/") ||
		strings.HasPrefix(p, "openspec/changes/") ||
		strings.HasPrefix(p, "tools/dash-lint/") || // never scan the scanner: its doc comments and test fixtures hold the pattern by design
		strings.HasPrefix(p, "server/apidocs/embed/") || // vendored ReDoc bundle + generated OpenAPI/asset files, not authored prose
		p == "docs/maintenance/log.md"
}

// readPathsFromStdin reads a NUL-delimited list of file paths from stdin (as produced by `git ls-files -z`). Reading the list
// rather than shelling out to git keeps this process free of any command execution.
func readPathsFromStdin() ([]string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	var files []string
	for b := range bytes.SplitSeq(data, []byte{0}) {
		if len(b) == 0 {
			continue
		}
		files = append(files, string(b))
	}
	return files, nil
}

// checkMarkdown flags em-dash use in Markdown prose: every line outside a code block, with inline code spans removed. Both
// fenced (``` / ~~~) and indented (CommonMark 4-space / tab) code blocks are skipped, since a CLI example with a legitimate
// " -- " (e.g. a `task ... -- scenario` end-of-options separator) commonly lives in one.
func checkMarkdown(path string, data []byte) []string {
	var findings []string
	// prevBlank starts true: the start of document is set off like a blank line, so a leading indented block counts as code.
	state := mdCodeState{prevBlank: true}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		if state.step(raw) {
			continue // line is inside a fenced or indented code block (or blank), not prose
		}
		if strings.Contains(raw, ignoreDirective) {
			continue
		}
		stripped := inlineCodeSpan.ReplaceAllString(raw, " ")
		if emDashUse.MatchString(stripped) {
			findings = append(findings, fmt.Sprintf(findingFmt, path, lineNo, strings.TrimSpace(raw)))
		}
	}
	return findings
}

// mdCodeState tracks Markdown fenced/indented code-block state across lines so checkMarkdown can skip code when scanning prose.
type mdCodeState struct {
	inFence      bool
	inIndentCode bool
	prevBlank    bool
}

// step advances the state for one raw line and reports whether that line is code/blank (skip it) rather than prose.
func (s *mdCodeState) step(raw string) (skip bool) {
	if fenceLine.MatchString(raw) {
		s.inFence = !s.inFence
		s.inIndentCode = false
		s.prevBlank = false
		return true
	}
	if s.inFence {
		return true
	}
	if strings.TrimSpace(raw) == "" {
		s.prevBlank = true // a blank line does not close an indented block; interior blanks belong to it
		return true
	}
	indented := strings.HasPrefix(raw, "    ") || strings.HasPrefix(raw, "\t")
	if s.inIndentCode {
		if indented {
			s.prevBlank = false
			return true // still inside the indented code block
		}
		s.inIndentCode = false // a dedented line ends the block; fall through and scan this line as prose
	} else if s.prevBlank && indented {
		s.inIndentCode = true // a blank line then a 4-space/tab indent opens an indented code block
		s.prevBlank = false
		return true
	}
	s.prevBlank = false
	return false
}

// checkGo lexes the file and flags em-dash use inside comment, string, and char tokens only (never bare code).
func checkGo(path string, data []byte) []string {
	var findings []string
	ignored := ignoredLines(data)
	fset := token.NewFileSet()
	file := fset.AddFile(path, fset.Base(), len(data))
	var s scanner.Scanner
	s.Init(file, data, nil /* ignore lex errors */, scanner.ScanComments)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		findings = append(findings, goTokenFindings(path, fset.Position(pos).Line, tok, lit, ignored)...)
	}
	return findings
}

// goTokenFindings inspects one lexed token and returns a finding per prose line that contains em-dash use. Only comment,
// string, and char tokens are prose-bearing; bare code is never inspected. A multi-line COMMENT token (a /* ... */ block) is
// scanned line by line so the per-line `dash-lint:ignore` directive and the reported line number match the line-based scanners
// exactly: a directive on line N suppresses only line N, and a violation on a later line is still reported at that line.
func goTokenFindings(path string, startLine int, tok token.Token, lit string, ignored map[int]bool) []string {
	// An if-ladder, not a switch on tok: token.Token has ~80 members and the exhaustive linter (configured here so a default
	// case does not satisfy it) would demand every one be listed.
	if tok == token.STRING || tok == token.CHAR {
		return goStringTokenFinding(path, startLine, lit, ignored)
	}
	if tok == token.COMMENT {
		return goCommentTokenFindings(path, startLine, lit, ignored)
	}
	return nil
}

// goStringTokenFinding reports a finding for a STRING/CHAR literal whose unquoted value contains em-dash use. Matching on the
// unquoted value keeps an escape like "\n - x" (an embedded newline before a list-ish " - ") from being misread as an em dash;
// the raw literal would show `n - ` and false-positive. A multi-line raw string is reported at its start line.
func goStringTokenFinding(path string, startLine int, lit string, ignored map[int]bool) []string {
	if ignored[startLine] {
		return nil
	}
	val := lit
	if unquoted, err := strconv.Unquote(lit); err == nil {
		val = unquoted
	}
	if emDashUse.MatchString(val) {
		return []string{fmt.Sprintf(findingFmt, path, startLine, strings.TrimSpace(firstLine(lit)))}
	}
	return nil
}

// goCommentTokenFindings scans a COMMENT token line by line so the per-line `dash-lint:ignore` directive and the reported line
// number match the line-based scanners exactly: a directive on line N suppresses only line N, and a violation on a later line of
// a /* ... */ block is still reported at that line.
func goCommentTokenFindings(path string, startLine int, lit string, ignored map[int]bool) []string {
	var out []string
	for offset, line := range strings.Split(lit, "\n") {
		lineNo := startLine + offset
		if ignored[lineNo] {
			continue
		}
		if emDashUse.MatchString(commentProse(line)) {
			out = append(out, fmt.Sprintf(findingFmt, path, lineNo, strings.TrimSpace(line)))
		}
	}
	return out
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
		commentText, inBlock = cStyleCommentText(raw, inBlock)
		if strings.Contains(raw, ignoreDirective) {
			continue
		}
		commentText = commentProse(commentText)
		if commentText != "" && emDashUse.MatchString(commentText) {
			findings = append(findings, fmt.Sprintf(findingFmt, path, lineNo, strings.TrimSpace(raw)))
		}
	}
	return findings
}

// cStyleCommentText returns the comment portion of one line and the updated block-comment state. It handles // line comments
// and /* ... */ blocks (single- or multi-line); code and string-literal content is left out.
func cStyleCommentText(raw string, inBlock bool) (comment string, stillInBlock bool) {
	if inBlock {
		if before, _, closed := strings.Cut(raw, "*/"); closed {
			return before, false
		}
		return raw, true
	}
	lineIdx := lineCommentStart(raw)
	blockIdx := strings.Index(raw, "/*")
	// A // line comment that starts before any /* swallows the rest of the line, so a "/*" sitting inside it (e.g. a
	// "/*.json" glob written in comment prose) is NOT a block-comment open. Without this ordering check the scanner would
	// treat the unterminated "/*" as opening a block and mis-scan the rest of the file as comment text.
	if lineIdx >= 0 && (blockIdx < 0 || lineIdx < blockIdx) {
		return raw[lineIdx:], false
	}
	if blockIdx >= 0 {
		afterOpen := raw[blockIdx+2:]
		if inner, _, closed := strings.Cut(afterOpen, "*/"); closed {
			return inner, false
		}
		return afterOpen, true
	}
	return "", false
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

// commentProse reduces comment text to the prose that should be scanned: inline `code spans` are blanked (a CLI example with a
// legitimate " -- " can live in one), and the ESLint / gosec directive-to-description " -- " separator is blanked (required
// tool syntax, not an em-dash stand-in). Prose after either is preserved, so a real em dash there is still caught.
func commentProse(text string) string {
	text = inlineCodeSpan.ReplaceAllString(text, " ")
	return lintDirectiveDescSep.ReplaceAllString(text, "$1   ")
}

// checkHashComments flags em-dash use inside the #-comment portion of each line (.yml / .yaml / .sh). YAML and shell both use
// #-prefixed comments; only the comment text is scanned, so " - " in a flow sequence value or a shell subtraction is left alone.
func checkHashComments(path string, data []byte) []string {
	var findings []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		if strings.Contains(raw, ignoreDirective) {
			continue
		}
		commentText := commentProse(hashCommentText(raw))
		if commentText != "" && emDashUse.MatchString(commentText) {
			findings = append(findings, fmt.Sprintf(findingFmt, path, lineNo, strings.TrimSpace(raw)))
		}
	}
	return findings
}

// hashCommentText returns the comment portion of one line: everything from the first '#' that begins a comment, or "" when
// there is none. A '#' begins a comment only at the start of the (trimmed) line or when preceded by whitespace, which is the
// YAML inline-comment rule and also skips shell constructs where '#' is glued to a prior token ("${#arr}", "x#frag" in a URL,
// "$#"). A shebang ("#!/bin/sh") starts a comment but carries no prose " - ", so flagging it is harmless.
//
// A hash inside a quoted scalar or string is NOT a comment (e.g. a double-quoted value containing a hash, or a
// single-quoted shell word), so a minimal single-line quote tracker skips single- and double-quoted regions. The YAML
// doubled-single-quote escape is handled by toggling (close then reopen leaves the region effectively still quoted), as is
// a backslash escape inside double quotes. It does not parse full YAML/shell quoting (block scalars, ANSI-C quoting, nested
// heredocs); those are out of scope for a line-oriented prose gate.
func hashCommentText(raw string) string {
	inSingle, inDouble, escaped := false, false, false
	for i := range len(raw) {
		c := raw[i]
		switch {
		case escaped:
			escaped = false
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			switch c {
			case '\\':
				escaped = true
			case '"':
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '#':
			if i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t' {
				return raw[i:]
			}
		}
	}
	return ""
}

// ignoredLines returns the 1-based line numbers that carry the ignoreDirective, so a token-based checker (checkGo) can suppress
// findings on them the same way the line-based checkers do with a direct strings.Contains on the raw line.
func ignoredLines(data []byte) map[int]bool {
	ignored := make(map[int]bool)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if strings.Contains(sc.Text(), ignoreDirective) {
			ignored[lineNo] = true
		}
	}
	return ignored
}

func firstLine(s string) string {
	before, _, _ := strings.Cut(s, "\n")
	return before
}
