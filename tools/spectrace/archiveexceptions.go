package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// defaultExceptionsFile is the auditable record of archive-verify findings that are correct as they stand.
//
// The file exists because the report cannot tell a deliberate non-restoration from an unrepaired drop. An archived change that
// declared the same behaviour under two capabilities, a requirement later renamed or moved, and a capability that was specified
// and never built all look identical to it: the archive said the canonical spec should hold something, and it does not. Without a
// way to say WHY, those findings report forever and the release checklist's before-and-after diff has to be read past a standing
// list nobody can shorten.
const defaultExceptionsFile = "openspec/archive-verify-exceptions.yaml"

// archiveException excuses every finding for one requirement, and says what makes it correct.
//
// This is deliberately not a mute list. Each entry has to name where the behaviour actually went, and both forms are checkable:
// coveredBy is verified against the canonical tree on every run, and trackedBy names an issue a reader can open. An entry that
// excuses nothing is an error, so the file cannot outlive the findings it was written for.
type archiveException struct {
	// Requirement is `<capability>/<requirement-slug>`, matching the finding prefix the report prints.
	Requirement string `yaml:"requirement"`

	// CoveredBy names the canonical requirement that carries this behaviour now, as `<capability>/<requirement-slug>`. Use it
	// when the behaviour survives under another name, in another capability, or in a copy the archive happened to keep.
	CoveredBy string `yaml:"covered_by"`

	// TrackedBy names the issue tracking a capability that was specified and never built. Restoring such a requirement would
	// write a spec that claims what the product does not do, which is worse than the current silence: it breaks the traceability
	// gate, since there is nothing to test, and it is how a spec stops being trusted.
	TrackedBy string `yaml:"tracked_by"`

	// Reason is the evidence for the claim, in the author's own words. Reviewed the way a `no-behavior-change` label is.
	Reason string `yaml:"reason"`
}

// excusedFinding pairs a finding with the entry that excused it, so the report can show both.
type excusedFinding struct {
	finding   string
	exception archiveException
}

// loadArchiveExceptions reads the exceptions file. A missing file is not an error: the check works without one, and requiring the
// file would mean every consumer of this tool has to carry it.
func loadArchiveExceptions(path string) ([]archiveException, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, same trust level as the spec tree this tool already reads
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []archiveException
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

// validateExceptions checks every entry's shape and its claim, and returns one message per problem.
//
// Order matters here: a malformed entry is reported and then skipped for the coverage check, so one entry missing its reason does
// not also produce a spurious "excuses nothing".
func validateExceptions(exceptions []archiveException, canonical map[string]struct{}, matched map[int]int) []string {
	var problems []string
	seen := make(map[string]int, len(exceptions))
	for i, e := range exceptions {
		where := fmt.Sprintf("%s (entry %d)", e.Requirement, i+1)
		if strings.TrimSpace(e.Requirement) == "" {
			problems = append(problems, fmt.Sprintf("entry %d: requirement is empty", i+1))
			continue
		}
		if prev, dup := seen[e.Requirement]; dup {
			problems = append(problems, fmt.Sprintf("%s: duplicate of entry %d", where, prev+1))
			continue
		}
		seen[e.Requirement] = i

		hasCovered, hasTracked := e.CoveredBy != "", e.TrackedBy != ""
		switch {
		case hasCovered && hasTracked:
			problems = append(problems, where+": sets both covered_by and tracked_by; an excused finding is one or the other")
			continue
		case !hasCovered && !hasTracked:
			problems = append(problems, where+": sets neither covered_by nor tracked_by")
			continue
		}
		if strings.TrimSpace(e.Reason) == "" {
			problems = append(problems, where+": reason is empty")
			continue
		}
		// The claim that keeps this file honest. A survivor that no longer exists means the behaviour is now genuinely
		// unspecified, and the entry would otherwise go on hiding that.
		if hasCovered {
			if _, ok := canonical[e.CoveredBy]; !ok {
				problems = append(problems, fmt.Sprintf("%s: covered_by %q is not a requirement in the canonical spec", where, e.CoveredBy))
				continue
			}
		}
		if matched[i] == 0 {
			problems = append(problems, where+": excuses no finding, so it is stale and should be deleted")
		}
	}
	return problems
}

// applyExceptions splits findings into the ones still outstanding and the ones an entry excuses, and reports how many findings
// each entry matched so a stale entry can be caught.
//
// Matching is by requirement prefix, because one requirement produces findings at several granularities: its own body text, each
// scenario under it, and its retirement. Excusing a requirement excuses all of them, which is the unit a reviewer actually
// decides on. The boundary check is what keeps `web-ui/alerts-list` from swallowing `web-ui/alerts-list-filters-by-subtype`.
func applyExceptions(findings []string, exceptions []archiveException) (outstanding []string, excused []excusedFinding, matched map[int]int) {
	matched = make(map[int]int, len(exceptions))
	for _, f := range findings {
		head, _, _ := strings.Cut(f, "\n")
		idx := -1
		for i, e := range exceptions {
			if head == e.Requirement || strings.HasPrefix(head, e.Requirement+"/") {
				idx = i
				break
			}
		}
		if idx < 0 {
			outstanding = append(outstanding, f)
			continue
		}
		matched[idx]++
		excused = append(excused, excusedFinding{finding: f, exception: exceptions[idx]})
	}
	return outstanding, excused, matched
}

// printExcused renders the excused section. It is printed in full rather than counted, because an excuse a reader cannot see is a
// mute, and the whole point of the file is that these decisions stay visible and checkable.
func printExcused(p func(string, ...any), excused []excusedFinding) {
	if len(excused) == 0 {
		return
	}
	byRequirement := map[string][]string{}
	entries := map[string]archiveException{}
	for _, e := range excused {
		head, _, _ := strings.Cut(e.finding, "\n")
		key := e.exception.Requirement
		entries[key] = e.exception
		byRequirement[key] = append(byRequirement[key], head)
	}
	keys := make([]string, 0, len(byRequirement))
	for k := range byRequirement {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	p("\nspectrace: %d finding(s) excused by %s, each with the survivor or issue that makes it correct.\n",
		len(excused), defaultExceptionsFile)
	for _, k := range keys {
		e := entries[k]
		where := "covered by " + e.CoveredBy
		if e.TrackedBy != "" {
			where = "tracked by " + e.TrackedBy
		}
		p("  %s (%d finding(s)): %s\n", k, len(byRequirement[k]), where)
		p("      %s\n", e.Reason)
	}
}

// exceptionsPathFor locates the exceptions file relative to the specs tree, so a caller that points the tool at a different
// checkout gets that checkout's file rather than the repository root's.
func exceptionsPathFor(specsDir string) string {
	// specsDir is `<root>/openspec/specs`; the file sits beside `specs` under `openspec`.
	return filepath.Join(filepath.Dir(specsDir), filepath.Base(defaultExceptionsFile))
}
