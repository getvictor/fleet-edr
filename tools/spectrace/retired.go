package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// parseModifiedRequirementScenarios returns, for each "<capability>/<requirement-slug>" that an in-flight change restates under
// `## MODIFIED Requirements`, the set of scenario slugs that restatement lists.
//
// It exists for the same reason parseRemovedRequirementKeys does, one level down. Archiving is batched at release time, so a
// merged change lives in openspec/changes for the whole window between merge and the release archive, during which the canonical
// tree still describes the old behaviour. `## REMOVED Requirements` already covers a change that retires a whole requirement.
// A change that retires ONE SCENARIO of a requirement it otherwise keeps had no equivalent, and the only ways past `--strict`
// were to leave a test asserting behaviour the change reverses, or to retire and re-add the whole requirement to reach the
// existing exemption. The first is the dishonesty issue #810 was filed about: a scenario reading as covered by a test that does
// not exercise it.
//
// A restatement is authoritative because that is what `openspec archive` does with it: merging a MODIFIED requirement replaces
// the canonical requirement's scenario list rather than adding to it. A canonical scenario the restatement omits is therefore a
// scenario the change is retiring, and it will be gone from openspec/specs at the next release archive.
//
// The archive subtree is skipped: archived changes are already applied into openspec/specs.
func parseModifiedRequirementScenarios(changesDir string) (map[string]map[string]struct{}, error) {
	byRequirement := make(map[string]map[string]struct{})
	err := forEachInFlightChangeDir(changesDir, func(changeDir string) error {
		return collectModifiedRequirementScenarios(changeDir, byRequirement)
	})
	if err != nil {
		return nil, err
	}
	return byRequirement, nil
}

// collectModifiedRequirementScenarios walks one in-flight change's delta-spec subtree for spec.md files, deriving the capability
// from each file's parent directory the way collectRemovedRequirementKeys does, so the keys line up with scenario ID prefixes.
func collectModifiedRequirementScenarios(changeDir string, byRequirement map[string]map[string]struct{}) error {
	specsDir := filepath.Join(changeDir, "specs")
	info, err := os.Stat(specsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	return filepath.WalkDir(specsDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Base(path) != "spec.md" {
			return nil
		}
		return scanModifiedRequirementsFile(path, byRequirement)
	})
}

// scanModifiedRequirementsFile opens one delta spec.md and records its `## MODIFIED Requirements` scenario sets under the
// capability derived from the file's parent directory.
func scanModifiedRequirementsFile(path string, byRequirement map[string]map[string]struct{}) error {
	f, err := os.Open(path) //nolint:gosec // path comes from filepath.WalkDir under changesDir/<change>/specs
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return scanModifiedRequirements(f, filepath.Base(filepath.Dir(path)), byRequirement)
}

// scanModifiedRequirements is the streaming parser. It tracks the active `## ` section and, while inside
// `## MODIFIED Requirements`, records each `#### Scenario:` slug against the `### Requirement:` heading above it.
//
// A requirement whose restatement lists no scenarios is NOT recorded. `openspec validate --strict` rejects that shape, but a
// delta being written has it for as long as the author has typed the heading and not yet the scenarios, and registering an empty
// set would exempt every one of that requirement's canonical scenarios from the gate for exactly that window.
//
// Two deltas restating the same requirement contribute a union rather than one silently winning here. That is deliberately more
// conservative than the archive, which applies them in sequence so the last one's list is what survives: a scenario either delta
// still lists is one this gate keeps demanding a marker for.
func scanModifiedRequirements(r io.Reader, capability string, byRequirement map[string]map[string]struct{}) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inModified := false
	current := ""
	var scenarios map[string]struct{}
	flush := func() {
		// Recorded on leaving the requirement rather than on entering it, so the "no scenarios listed" case above never reaches
		// the map at all.
		if current != "" && len(scenarios) > 0 {
			existing, ok := byRequirement[current]
			if !ok {
				byRequirement[current] = scenarios
			} else {
				for slug := range scenarios {
					existing[slug] = struct{}{}
				}
			}
		}
		current, scenarios = "", nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "## "):
			flush()
			// Matching the precise heading, as scanRemovedRequirements does, so a future `## MODIFIED <other>` section carrying
			// requirement headings cannot exempt canonical scenarios.
			inModified = strings.TrimSpace(line) == "## MODIFIED Requirements"
		case inModified && strings.HasPrefix(line, "### Requirement:"):
			flush()
			current = capability + "/" + slugify(strings.TrimSpace(strings.TrimPrefix(line, "### Requirement:")))
			scenarios = make(map[string]struct{})
		case inModified && current != "" && strings.HasPrefix(line, "#### Scenario:"):
			scenarios[slugify(strings.TrimSpace(strings.TrimPrefix(line, "#### Scenario:")))] = struct{}{}
		}
	}
	flush()
	return scanner.Err()
}

// filterOutRetiredScenarios drops canonical scenarios that an in-flight change's MODIFIED restatement of their requirement no
// longer lists, and returns the dropped ones alongside. Scenarios of requirements no in-flight change modifies are untouched, as
// are the listed scenarios of one that is.
//
// The retired IDs come back rather than just a count so the caller can NAME them. That is the difference between this exemption
// and a silence: an omission from a restatement is how a scenario gets retired ON PURPOSE and also how one gets dropped BY
// ACCIDENT, and the two are indistinguishable in the file. Printing them puts the list in front of a reviewer, who is the only
// one who can tell which it was. This was not hypothetical when it was written: the first run named a scenario about
// `edr.agent.queue.dropped` that an already-merged change had dropped from its restatement by mistake, which would otherwise
// have been deleted from the canonical spec at the next release archive with nothing said.
func filterOutRetiredScenarios(scenarios []Scenario, modified map[string]map[string]struct{}) (kept []Scenario, retired []string) {
	if len(modified) == 0 {
		return scenarios, nil
	}
	kept = make([]Scenario, 0, len(scenarios))
	for _, s := range scenarios {
		if listed, ok := modified[s.SpecDir+"/"+slugify(s.Requirement)]; ok {
			if _, still := listed[slugify(s.Title)]; !still {
				retired = append(retired, s.ID)
				continue
			}
		}
		kept = append(kept, s)
	}
	return kept, retired
}
