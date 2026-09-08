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
// free-form maintenance journal, the vendored / generated API-docs embed assets (the minified ReDoc bundle and generated
// OpenAPI spec, none of which is hand-authored prose), the vendored upstream Sigma rules, and docs/detection-rules.md, which
// reproduces those vendored rules' titles verbatim. Each exclusion carries its reasoning at the line that adds it.
func isExcluded(p string) bool {
	return strings.HasPrefix(p, ".claude/") ||
		strings.HasPrefix(p, "openspec/changes/") ||
		strings.HasPrefix(p, "tools/dash-lint/") || // never scan the scanner: its doc comments and test fixtures hold the pattern by design
		strings.HasPrefix(p, "server/apidocs/embed/") || // vendored ReDoc bundle + generated OpenAPI/asset files, not authored prose
		// Vendored SigmaHQ rules (#763): third-party prose mirrored byte-for-byte, whose being UNMODIFIED is what their tests
		// assert. Rewording someone else's rule comment to suit our house style would break what the fixtures exist to prove.
		//
		// Scoped to the exact path AND to .yml, so an unrelated fixture directory cannot inherit the exemption and the README we
		// wrote beside those rules stays under the gate like every other piece of our own prose.
		(strings.HasPrefix(p, "server/rules/internal/catalog/imported/") && strings.HasSuffix(p, ".yml")) ||
		// docs/detection-rules.md is generated from the rule catalog (tools/gen-rule-docs) and now reproduces vendored rule
		// titles verbatim, several of which use a spaced hyphen ("Binary Padding - MacOS"). Rewriting someone else's rule title
		// to suit our house style would make the reference disagree with the rule it documents and with upstream. The generator's
		// OWN prose is still gated: it lives as string literals in tools/gen-rule-docs, which this linter reads.
		p == "docs/detection-rules.md" ||
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
	var st cStyleState
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		var commentText string
		commentText, st = cStyleCommentText(raw, st)
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
// cStyleState is what a C-style scan carries between lines: whether a block comment is open, and whether a multi-line string is.
type cStyleState struct {
	inBlock bool
	// inTemplate tracks a backtick template literal, which is the only string form in these languages that legally spans lines.
	// A ' or " string is closed at end of line rather than carried, because an unterminated one is a syntax error and carrying it
	// would let one typo silence the rest of the file, which is the failure mode this whole change is about.
	inTemplate bool
}

// cStyleCommentText returns the comment prose on one line and the state to carry to the next.
//
// It is a character scan rather than an index search because `/*` and `*/` mean nothing inside a string literal, and treating them
// as comment delimiters there flips the scanner's state for the rest of the file. Issue #820: a glob written
// `"*/claude/versions/*"` ends in `/` `*`, which read as opening a block comment, and the state stayed flipped until another glob
// supplied a `*/`. The visible symptom was a false positive on ordinary arithmetic; the serious direction is the false negative,
// where real comments are scanned as code and a genuine violation goes unreported with nothing to say the linter stopped looking.
//
// Only the NORMAL state opens a string, so an apostrophe in comment prose is inert, and only the string states make the comment
// delimiters inert. Escapes are honoured inside strings so a trailing `\"` does not leak the string past its close.
//
// Regex literals are NOT tracked. Disambiguating `/` as division from `/` as a regex open needs the previous token, which is a
// tokenizer rather than a scan, and a regex containing `/*` appears nowhere in the tree (checked). If one is ever added, its `/*`
// would read as a comment open exactly as the glob did, and the fix is the same shape as this one.
func cStyleCommentText(raw string, st cStyleState) (comment string, next cStyleState) {
	if st.inBlock {
		return continueBlock(raw)
	}
	return scanCode(raw, st.inTemplate)
}

// continueBlock handles a line that begins inside a block comment: everything up to the close is comment prose, and whatever
// follows the close is code that may open a string or another comment of its own.
func continueBlock(raw string) (string, cStyleState) {
	before, rest, closed := strings.Cut(raw, "*/")
	if !closed {
		return raw, cStyleState{inBlock: true}
	}
	tail, tailState := scanCode(rest, false)
	if tail != "" {
		return before + " " + tail, tailState
	}
	return before, tailState
}

// scanCode walks a line that starts in code, returning the comment prose it contains and the state to carry on.
//
// A character scan rather than an index search, because `/*` and `*/` mean nothing inside a string literal and treating them as
// comment delimiters there flips the scanner for the rest of the file. Issue #820: a glob written `"*/claude/versions/*"` ends in
// `/` `*`, which read as opening a block comment, and the state stayed flipped until another glob supplied a `*/`. The visible
// symptom was a false positive on ordinary arithmetic; the serious direction is the false negative, where real comments are then
// scanned as code and a genuine violation goes unreported with nothing to say the linter stopped looking.
//
// Regex literals are NOT tracked. Telling `/` as division from `/` as a regex open needs the previous token, which is a tokenizer
// rather than a scan, and no regex in the tree contains `/*` (checked). One that did would read as a comment open exactly as the
// glob did, and the fix would be the same shape as this.
func scanCode(raw string, inTemplate bool) (string, cStyleState) {
	var b strings.Builder
	i := 0
	if inTemplate {
		next, closed := skipString(raw, 0, '`')
		if !closed {
			return "", cStyleState{inTemplate: true}
		}
		i = next
	}
	for ; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '"' || c == '\'' || c == '`':
			// Only code opens a string, so an apostrophe in comment prose never reaches here. An unterminated ' or " is dropped
			// at end of line: it is a syntax error, and carrying it would let one typo silence the rest of the file.
			next, closed := skipString(raw, i+1, c)
			if !closed {
				return b.String(), cStyleState{inTemplate: c == '`'}
			}
			i = next - 1
		case c == '/' && i+1 < len(raw) && raw[i+1] == '/':
			return raw[i:], cStyleState{}
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			inner, after, closed := strings.Cut(raw[i+2:], "*/")
			if !closed {
				return inner, cStyleState{inBlock: true}
			}
			b.WriteString(inner)
			b.WriteString(" ")
			tail, tailState := scanCode(after, false)
			b.WriteString(tail)
			return b.String(), tailState
		}
	}
	return b.String(), cStyleState{}
}

// skipString advances past a string literal's body, starting just after its opening quote. It reports the index following the
// closing quote, and whether the string closed on this line at all.
//
// Escapes are honoured so a trailing `\"` does not leak the string past its close, which would put the rest of the line back into
// code and re-expose the comment delimiters this exists to make inert.
func skipString(raw string, from int, quote byte) (int, bool) {
	for i := from; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case quote:
			return i + 1, true
		}
	}
	return len(raw), false
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
