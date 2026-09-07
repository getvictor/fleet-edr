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
		// EVERY line under the active requirement, headings included, verbatim. Which lines are body, which belong to a scenario,
		// and where a requirement's own text ends are splitRequirementText's rules, not this one's, because the archived-delta
		// side reaches that function as verbatim lines too and one set of rules applied to both sides is the only way the two can
		// be compared. Filtering the scenario headings out here, which this did, put every scenario bullet in the canonical
		// requirement's BODY and under a scenario key on the delta side, and reported 648 identical lines as retired.
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
			keepBodyLine(line)
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
			keepBodyLine(line)
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

// ParseAllRequirementText returns every canonical requirement's prose, keyed the way scenario IDs are prefixed
// (`<specDir>/<requirement-slug>`).
//
// A second walk rather than a second parser, and a second entry point rather than a wider ParseAllSpecs: the archive verifier is
// the only caller that needs bodies, and every other caller would have to thread a return value it ignores. What must not happen
// is a second implementation of the heading rules, which is why this goes through parseSpec.
func ParseAllRequirementText(specsDir string) (map[string]requirementText, error) {
	out := make(map[string]requirementText)
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
			out[specDir+"/"+requirement] = splitRequirementText(lines)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// requirementText is a requirement's prose split the way it is compared: its own normative body, and each scenario's body under
// the scenario's slug.
//
// Split rather than one flat list because a scenario that goes missing takes its GIVEN/WHEN/THEN bullets with it. Comparing the
// text flat reported one lost scenario as seven findings, measured at 127 lines across the archive; keyed by scenario, a missing
// scenario is reported once by name and only the bodies of scenarios that exist on BOTH sides are compared.
type requirementText struct {
	body      []string
	scenarios map[string][]string
}

// splitRequirementText turns a requirement's verbatim lines into comparable logical lines. Whitespace differences and LINE
// WRAPPING are absorbed, nothing else.
//
// The wrapping is the whole reason this exists rather than a plain trim. Measured across the archive, comparing bodies with
// trailing-whitespace normalisation alone reports 17 requirements as differing and 9 of those differ ONLY by reflow: the canonical
// tree is Prettier `proseWrap: never` and the change deltas are hard-wrapped by hand. A check whose output is nine parts reflow is
// one a reader learns to ignore, which is worse than not having it.
//
// A blank line, a list marker (bulleted or numbered) and a heading each start a new logical line, so an item that gained or lost
// a clause is its own difference rather than being absorbed into the paragraph around it.
//
// One function for both sides of the comparison, deliberately: it takes the verbatim lines a canonical spec.md yields and the
// verbatim lines an archived delta's MODIFIED entry yields, and a second implementation of these rules is how the two sides would
// come to disagree about where a requirement's own text ends.
func splitRequirementText(lines []string) requirementText {
	out := requirementText{scenarios: map[string][]string{}}
	var buf []string
	scenario := ""
	flush := func() {
		if len(buf) == 0 {
			return
		}
		joined := strings.Join(buf, " ")
		if scenario == "" {
			out.body = append(out.body, joined)
		} else {
			out.scenarios[scenario] = append(out.scenarios[scenario], joined)
		}
		buf = nil
	}
	for _, line := range lines {
		trimmed := strings.Join(strings.Fields(line), " ")
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "### Requirement:"):
			// The heading is the key, not body text, and the two sides carry it differently.
			flush()
		case strings.HasPrefix(trimmed, "#### Scenario:"):
			// Compared by NAME elsewhere, so the heading itself is not text; what follows belongs to this scenario.
			flush()
			scenario = slugify(strings.TrimSpace(strings.TrimPrefix(trimmed, "#### Scenario:")))
			if _, ok := out.scenarios[scenario]; !ok {
				out.scenarios[scenario] = nil
			}
		case strings.HasPrefix(trimmed, "#### "):
			// Any other subheading ends the requirement's own text without belonging to a scenario.
			flush()
			scenario = ""
		case strings.HasPrefix(trimmed, "#"), isListItem(trimmed):
			flush()
			buf = append(buf, trimmed)
		default:
			buf = append(buf, trimmed)
		}
	}
	flush()
	return out
}

// isListItem reports a Markdown list marker, ORDERED as well as bulleted.
//
// The ordered form is not decoration: `openspec/specs/ui-authentication-session/spec.md` numbers the steps of a requirement, and
// without this those items merge into the paragraph above them, which both blurs a finding and lets a list-versus-prose
// restructuring compare equal. Review caught the comment above promising every list marker while the code recognised two of them.
func isListItem(trimmed string) bool {
	if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
		return true
	}
	digits := 0
	for digits < len(trimmed) && trimmed[digits] >= '0' && trimmed[digits] <= '9' {
		digits++
	}
	return digits > 0 && strings.HasPrefix(trimmed[digits:], ". ")
}
