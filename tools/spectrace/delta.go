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

// deltaSections is what one pass over the in-flight OpenSpec change deltas yields: the requirements a change RETIRES outright,
// and the scenario list each change RESTATES for a requirement it keeps.
//
// Both are read from the same headings by the same scanner, because two scanners disagreeing about where a `## ` section ends is
// how one exemption starts applying where the other does not.
type deltaSections struct {
	// removedRequirements holds "<capability>/<requirement-slug>" for each requirement marked under `## REMOVED Requirements`.
	removedRequirements map[string]struct{}
	// modifiedScenarios maps "<capability>/<requirement-slug>" to the scenario slugs each in-flight change restates for it, keyed
	// by change name so a divergence between two changes can be reported against the changes that caused it.
	modifiedScenarios map[string]map[string]map[string]struct{}
}

// restatedScenarios collapses modifiedScenarios to one scenario set per requirement, which is what the exemption filter consumes.
//
// The sets are unioned. That is only sound because divergentRestatements below rejects the case where they differ: if two changes
// restated one requirement with different lists, the union would keep every scenario gated while the archive silently kept only
// the last change's list, and the gate would be quietly describing a different spec than the one being built.
func (d *deltaSections) restatedScenarios() map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(d.modifiedScenarios))
	for requirement, byChange := range d.modifiedScenarios {
		merged := make(map[string]struct{})
		for _, scenarios := range byChange {
			for slug := range scenarios {
				merged[slug] = struct{}{}
			}
		}
		out[requirement] = merged
	}
	return out
}

// divergentRestatement names one requirement that two or more in-flight changes restate with different scenario lists.
type divergentRestatement struct {
	requirement string
	changes     []string
	// missing maps a change name to the scenarios OTHER changes list and it does not, which are exactly the scenarios that change
	// deletes if it archives last.
	missing map[string][]string
}

// divergentRestatements reports every requirement that two or more in-flight changes restate with DIFFERENT scenario lists.
//
// This is a real defect, not a style point. `openspec archive` applies a MODIFIED requirement by replacing the canonical
// requirement's scenario list with the restatement, and archiving is batched at release time, so several in-flight changes can
// restate one requirement before any of them is applied. They are then applied in sequence and the LAST one's list is what
// survives: every scenario the other restatements added is deleted, at release, with nothing said.
//
// A restatement therefore has to describe the requirement as it will be once every in-flight change has landed, not as it was when
// that change was written. Two restatements that disagree are two authors who have not seen each other's work, and the only moment
// anyone can notice is now.
func (d *deltaSections) divergentRestatements() []divergentRestatement {
	var out []divergentRestatement
	for requirement, byChange := range d.modifiedScenarios {
		if len(byChange) < 2 {
			continue
		}
		if divergence, ok := divergenceOf(requirement, byChange); ok {
			out = append(out, divergence)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].requirement < out[j].requirement })
	return out
}

// divergenceOf reports what each of several restatements of one requirement omits relative to the others, and whether any of them
// omits anything at all.
func divergenceOf(requirement string, byChange map[string]map[string]struct{}) (divergentRestatement, bool) {
	union := make(map[string]struct{})
	for _, scenarios := range byChange {
		for slug := range scenarios {
			union[slug] = struct{}{}
		}
	}
	missing := make(map[string][]string)
	changes := make([]string, 0, len(byChange))
	for change, scenarios := range byChange {
		changes = append(changes, change)
		for slug := range union {
			if _, ok := scenarios[slug]; !ok {
				missing[change] = append(missing[change], slug)
			}
		}
		sort.Strings(missing[change])
	}
	if len(missing) == 0 {
		return divergentRestatement{}, false
	}
	sort.Strings(changes)
	return divergentRestatement{requirement: requirement, changes: changes, missing: missing}, true
}

// parseDeltaSections walks every in-flight change's delta-spec subtree once and returns both exemption inputs.
//
// The archive subtree is skipped: archived changes are already applied into openspec/specs.
func parseDeltaSections(changesDir string) (*deltaSections, error) {
	d := &deltaSections{
		removedRequirements: make(map[string]struct{}),
		modifiedScenarios:   make(map[string]map[string]map[string]struct{}),
	}
	err := forEachInFlightChangeDir(changesDir, func(changeDir string) error {
		return d.collectChange(changeDir)
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// collectChange walks one in-flight change's delta-spec subtree for spec.md files. The capability comes from each file's parent
// directory (specs/<capability>/spec.md), matching the specDir parseSpec derives for the canonical tree so the keys line up with
// scenario ID prefixes. Scoping the walk to specs/ keeps a stray spec.md elsewhere under the change from deriving a bogus
// capability. A change with no specs/ subtree (no delta) contributes nothing.
func (d *deltaSections) collectChange(changeDir string) error {
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
	change := filepath.Base(changeDir)
	return filepath.WalkDir(specsDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Base(path) != "spec.md" {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // path comes from filepath.WalkDir under changesDir/<change>/specs
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		return d.scan(f, change, filepath.Base(filepath.Dir(path)))
	})
}

// scan is the streaming parser behind both exemptions. It tracks the active `## ` section and, inside the two it recognises,
// records a requirement key (REMOVED) or the scenario slugs listed beneath each requirement (MODIFIED).
//
// The section headings are matched exactly rather than by prefix, so a future `## REMOVED <other>` or `## MODIFIED <other>` section
// carrying requirement headings cannot exempt canonical scenarios.
//
// A MODIFIED requirement whose restatement lists NO scenarios is not recorded. `openspec validate --strict` rejects that shape, but
// a delta being written has it for as long as the author has typed the heading and not yet the scenarios, and recording an empty
// set would exempt every one of that requirement's canonical scenarios from the gate for exactly that window.
func (d *deltaSections) scan(r io.Reader, change, capability string) error {
	const (
		sectionOther = iota
		sectionRemoved
		sectionModified
	)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	section := sectionOther
	current := ""
	var scenarios map[string]struct{}
	flush := func() {
		// Recorded on leaving the requirement rather than on entering it, so the "no scenarios listed" case never reaches the map.
		if current != "" && len(scenarios) > 0 {
			if d.modifiedScenarios[current] == nil {
				d.modifiedScenarios[current] = make(map[string]map[string]struct{})
			}
			d.modifiedScenarios[current][change] = scenarios
		}
		current, scenarios = "", nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "## "):
			flush()
			switch strings.TrimSpace(line) {
			case "## REMOVED Requirements":
				section = sectionRemoved
			case "## MODIFIED Requirements":
				section = sectionModified
			default:
				section = sectionOther
			}
		case section == sectionRemoved && strings.HasPrefix(line, "### Requirement:"):
			d.removedRequirements[capability+"/"+requirementSlug(line)] = struct{}{}
		case section == sectionModified && strings.HasPrefix(line, "### Requirement:"):
			flush()
			current = capability + "/" + requirementSlug(line)
			scenarios = make(map[string]struct{})
		case section == sectionModified && current != "" && strings.HasPrefix(line, "#### Scenario:"):
			scenarios[slugify(strings.TrimSpace(strings.TrimPrefix(line, "#### Scenario:")))] = struct{}{}
		}
	}
	flush()
	return scanner.Err()
}

// requirementSlug turns a `### Requirement: <title>` heading into the slug used in a scenario ID prefix.
func requirementSlug(line string) string {
	return slugify(strings.TrimSpace(strings.TrimPrefix(line, "### Requirement:")))
}

// filterOutRemovedRequirements drops scenarios whose parent requirement an in-flight change marks `## REMOVED`. The match key is
// SpecDir + "/" + slugify(Requirement), the same prefix parseSpec builds into each scenario ID. Returns the input unchanged when
// there are no removals.
func filterOutRemovedRequirements(scenarios []Scenario, removedReqKeys map[string]struct{}) []Scenario {
	if len(removedReqKeys) == 0 {
		return scenarios
	}
	out := make([]Scenario, 0, len(scenarios))
	for _, s := range scenarios {
		if _, ok := removedReqKeys[s.SpecDir+"/"+slugify(s.Requirement)]; ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

// filterOutRetiredScenarios drops canonical scenarios that an in-flight change's MODIFIED restatement of their requirement no
// longer lists, and returns the dropped ones alongside. Scenarios of requirements no in-flight change modifies are untouched, as
// are the listed scenarios of one that is.
//
// The retired IDs come back rather than just a count so the caller can NAME them. That is the difference between this exemption
// and a silence: an omission from a restatement is how a scenario gets retired ON PURPOSE and also how one gets dropped BY
// ACCIDENT, and the two are indistinguishable in the file. Printing them puts the list in front of a reviewer, who is the only one
// who can tell which it was. This was not hypothetical when it was written: the first run named a scenario about
// `edr.agent.queue.dropped` that an already-merged change had dropped from its restatement by mistake, which would otherwise have
// been deleted from the canonical spec at the next release archive with nothing said.
func filterOutRetiredScenarios(scenarios []Scenario, restated map[string]map[string]struct{}) (kept []Scenario, retired []string) {
	if len(restated) == 0 {
		return scenarios, nil
	}
	kept = make([]Scenario, 0, len(scenarios))
	for _, s := range scenarios {
		if listed, ok := restated[s.SpecDir+"/"+slugify(s.Requirement)]; ok {
			if _, still := listed[slugify(s.Title)]; !still {
				retired = append(retired, s.ID)
				continue
			}
		}
		kept = append(kept, s)
	}
	return kept, retired
}
