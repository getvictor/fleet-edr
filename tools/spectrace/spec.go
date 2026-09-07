package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Scenario is one canonical scenario from openspec/specs/<dir>/spec.md. The canonical ID is the slash-joined slug used by the
// spec.id / test marker contract documented in docs/testing-strategy.md. SourcePath is normalised to forward-slash and made
// relative to the cwd at parse time so report output is stable regardless of whether the caller passed `--specs-dir` as a
// repo-relative or absolute path.
type Scenario struct {
	ID          string
	SpecDir     string
	Requirement string
	Title       string
	SourcePath  string
	SourceLine  int
	Normative   bool
}

// ParseAllSpecs walks specsDir for spec.md files and returns every scenario it finds. Scenarios are sorted by canonical ID so
// downstream output is deterministic across runs and across filesystems with different directory orderings. SourcePath on
// each emitted Scenario is normalised to a forward-slash, cwd-relative path so reports stay clickable whether the caller
// passed --specs-dir as a repo-relative or absolute path.
func ParseAllSpecs(specsDir string) ([]Scenario, error) {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "" // fall through; relPath() handles the empty-cwd case as identity.
	}
	var all []Scenario
	err = filepath.WalkDir(specsDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Base(path) != "spec.md" {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // path comes from filepath.WalkDir under specsDir
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		specDir := filepath.Base(filepath.Dir(path))
		scenarios, _, err := parseSpec(f, specDir, relPath(cwd, path))
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		all = append(all, scenarios...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}

// relPath returns a forward-slash, cwd-relative path for reporting. When cwd is empty (Getwd failed) or filepath.Rel returns
// an error, the input is returned with backslashes converted but otherwise unchanged. The cost of the conversion is one
// allocation per spec.md file; specs are sub-100 in this repo, so the work is negligible.
func relPath(cwd, path string) string {
	if cwd == "" {
		return filepath.ToSlash(path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// parseSpec walks one spec.md and emits a Scenario per `#### Scenario:` heading. Normative is derived from whether the parent
// `### Requirement:` block's body (the lines BEFORE any subheading) contains the words SHALL or MUST. The function is a small
// streaming parser rather than a Markdown library import: spec format is line-regular and a regex over fixed prefixes is the
// minimum implementation that meets the contract in docs/testing-strategy.md.
func parseSpec(r io.Reader, specDir, sourcePath string) ([]Scenario, map[string][]string, error) {
	var scenarios []Scenario
	bodies := make(map[string][]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		currentReq     string
		currentReqSlug string
		seenSubheading bool
		reqIsNormative bool
		lineNo         int
	)

	keepBodyLine := func(line string) {
		// Everything under the active requirement, verbatim. Where a requirement's OWN text ends is collapseProse's rule, not
		// this one's, because the archived-delta side reaches it as verbatim lines too and one boundary applied to both sides is
		// the only way the two can be compared. A copy of that rule here passed every test while doing nothing.
		bodies[currentReqSlug] = append(bodies[currentReqSlug], line)
	}

	flushReqBodyLine := func(line string) {
		// Only inspect lines BEFORE the first subheading under the requirement so a scenario's GIVEN/WHEN/THEN body cannot
		// promote a non-normative requirement to normative status.
		if seenSubheading {
			return
		}
		if containsNormativeKeyword(line) {
			reqIsNormative = true
		}
	}

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "### Requirement:"):
			title := strings.TrimSpace(strings.TrimPrefix(line, "### Requirement:"))
			currentReq = title
			currentReqSlug = slugify(title)
			seenSubheading = false
			reqIsNormative = false
			if _, ok := bodies[currentReqSlug]; !ok {
				bodies[currentReqSlug] = nil
			}
		case strings.HasPrefix(line, "#### Scenario:") && currentReq != "":
			title := strings.TrimSpace(strings.TrimPrefix(line, "#### Scenario:"))
			scenarios = append(scenarios, Scenario{
				ID:          specDir + "/" + currentReqSlug + "/" + slugify(title),
				SpecDir:     specDir,
				Requirement: currentReq,
				Title:       title,
				SourcePath:  sourcePath,
				SourceLine:  lineNo,
				Normative:   reqIsNormative,
			})
			seenSubheading = true
		case strings.HasPrefix(line, "### ") || strings.HasPrefix(line, "## "):
			// A new top-level or sibling heading closes the active requirement. Subsequent body text until the next
			// `### Requirement:` is irrelevant to the scenario list.
			currentReq = ""
			currentReqSlug = ""
			seenSubheading = false
			reqIsNormative = false
		case strings.HasPrefix(line, "#### "):
			// Non-Scenario subheading under a requirement (e.g. `#### Notes`). Closes the requirement-body inspection so
			// later body text under that subheading does not change the normative classification.
			seenSubheading = true
		default:
			if currentReq != "" {
				flushReqBodyLine(line)
				keepBodyLine(line)
			}
		}
	}
	return scenarios, bodies, scanner.Err()
}

// containsNormativeKeyword reports whether a line of a requirement body contains the RFC 2119 normative keywords SHALL or MUST.
// Matching is whole-word, case-sensitive (RFC 2119 uppercases all five normative keywords); this avoids treating a casual
// "must" or "shall" inside English prose as a contract.
func containsNormativeKeyword(line string) bool {
	for _, kw := range [...]string{"SHALL", "MUST"} {
		idx := 0
		for {
			j := strings.Index(line[idx:], kw)
			if j < 0 {
				break
			}
			start := idx + j
			end := start + len(kw)
			leftOK := start == 0 || !isWordChar(line[start-1])
			rightOK := end == len(line) || !isWordChar(line[end])
			if leftOK && rightOK {
				return true
			}
			idx = end
		}
	}
	return false
}

func isWordChar(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// slugify applies the canonical-ID rule from docs/testing-strategy.md: lowercase, replace runs of non-alphanumeric with a
// single dash, strip leading and trailing dashes. Pure ASCII; non-ASCII letters become dashes by design (the spec scenario
// titles in this repo are all ASCII English).
func slugify(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := true // start "true" so any leading non-alphanumeric becomes a no-op rather than a leading dash
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
			b.WriteByte(c)
			prevDash = false
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	return strings.Trim(out, "-")
}

// ParseAllRequirementBodies returns every canonical requirement's body lines, keyed the way scenario IDs are prefixed
// (`<specDir>/<requirement-slug>`).
//
// A second walk rather than a second parser, and a second entry point rather than a wider ParseAllSpecs: the archive verifier is
// the only caller that needs bodies, and every other caller would have to thread a return value it ignores. What must not happen
// is a second implementation of the heading rules, which is why this goes through parseSpec.
func ParseAllRequirementBodies(specsDir string) (map[string][]string, error) {
	out := make(map[string][]string)
	err := filepath.WalkDir(specsDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Base(path) != "spec.md" {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // path comes from filepath.WalkDir under specsDir
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		specDir := filepath.Base(filepath.Dir(path))
		_, bodies, err := parseSpec(f, specDir, path)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for requirement, lines := range bodies {
			out[specDir+"/"+requirement] = lines
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// collapseProse reduces requirement text to comparable logical lines: whitespace-only differences and LINE WRAPPING are absorbed,
// nothing else.
//
// The wrapping is the whole reason this exists rather than reusing normaliseRestatement. Measured across the archive, comparing
// bodies with trailing-whitespace normalisation alone reports 17 requirements as differing and 9 of those differ ONLY by reflow:
// the canonical tree is Prettier `proseWrap: never` and the change deltas are hard-wrapped by hand. A check whose output is nine
// parts reflow is one a reader learns to ignore, which is worse than not having it.
//
// A blank line, a list marker and a heading each start a new logical line, so a bullet that gained or lost a clause is still its
// own difference rather than being absorbed into the paragraph around it.
func collapseProse(lines []string) []string {
	var out []string
	var buf []string
	flush := func() {
		if len(buf) > 0 {
			out = append(out, strings.Join(buf, " "))
			buf = nil
		}
	}
	for _, line := range lines {
		trimmed := strings.Join(strings.Fields(line), " ")
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "### Requirement:"):
			// The heading is the key, not body text, and the two sides carry it differently.
			flush()
		case strings.HasPrefix(trimmed, "#### "):
			// A subheading ends the requirement's own text, and everything past it belongs to a scenario.
			//
			// Scenario bodies are deliberately outside the comparison. They are covered by comparing scenario NAMES, and a
			// scenario that goes missing takes its GIVEN/WHEN/THEN bullets with it: counting those as prose losses too reported
			// one lost scenario as seven findings, measured at 127 lines across the archive against 21 for requirement text.
			flush()
			return out
		case strings.HasPrefix(trimmed, "#"), strings.HasPrefix(trimmed, "- "), strings.HasPrefix(trimmed, "* "):
			flush()
			buf = append(buf, trimmed)
		default:
			buf = append(buf, trimmed)
		}
	}
	flush()
	return out
}
