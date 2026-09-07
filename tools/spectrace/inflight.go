package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// InFlightScenarios returns every scenario declared by an in-flight change delta under changesDir, as full Scenario values
// rather than the bare IDs parseChangeScenarioIDs collects.
//
// The full values are what the gate needs: whether a scenario is normative, and where to point a reader who has to fix it.
//
// The archive is skipped for the reason it is skipped everywhere else here: an archived change's delta has already been merged
// into the canonical tree, so its scenarios are gated there and gating them again would double-count them.
//
// Scenario IDs are NOT run through buildCanonicalSet's duplicate detection, matching parseChangeScenarioIDs. A MODIFIED
// requirement repeats the scenario headings it keeps, and two changes may restate one requirement, so collisions are expected
// here in a way they are not in the canonical tree.
func InFlightScenarios(changesDir string) ([]Scenario, error) {
	var all []Scenario
	err := forEachInFlightChangeDir(changesDir, func(changeDir string) error {
		scenarios, err := ParseAllSpecs(filepath.Join(changeDir, "specs"))
		if err != nil {
			return fmt.Errorf("parse %s: %w", changeDir, err)
		}
		all = append(all, scenarios...)
		return nil
	})
	return all, err
}

// UngatedInFlight returns the normative scenarios an in-flight delta introduces on THIS branch that no marker covers.
//
// This is the half of the reference-valid set that had no gate. A delta-declared ID joins referenceValid so a test in the same
// PR can point at a scenario before it is canonical, which is the affordance that makes the delta-first workflow work. The other
// half is that a delta-declared scenario with NO marker was indistinguishable from one that never needed one, so nothing failed
// until `openspec archive` merged it into the canonical tree at release, where a whole release's worth surfaced at once in what
// is meant to be a mechanical step (issue #841).
//
// Scoped to the branch, and that is the load-bearing part rather than a refinement. Changes stay in openspec/changes from merge
// until the release archive, so the in-flight set holds every change merged since the last release; gating all of it would fail
// every PR in the repository on scenarios somebody else wrote. Scoping asks the question the project rule actually asks, which is
// whether the PR that INTRODUCES a scenario ships a marker for it.
//
// Scenarios already in the canonical tree are excluded, not because they are safe but because they are already gated: a MODIFIED
// requirement restates the headings it keeps, so most of what a delta touches is canonical already and would otherwise be
// reported twice.
func UngatedInFlight(
	ctx context.Context, changesDir, baseRef string, canonical map[string]struct{}, covered map[string][]Marker,
) ([]Scenario, error) {
	touched, err := computeNewCodeScenarioIDs(ctx, changesDir, baseRef)
	if err != nil {
		return nil, err
	}
	if len(touched) == 0 {
		return nil, nil
	}
	// ADDED, not merely touched, and review was right that the difference matters here in a way it does not for the canonical
	// gate. computeNewCodeScenarioIDs promotes every scenario under a requirement whose prose changed, which is correct there
	// because those scenarios are gated anyway. Here it would attribute a sibling somebody else left unmarked to whoever next
	// edits that requirement's wording, which is the wedge the branch scoping exists to prevent, one level in. Measured against
	// this repository while writing the gate: 31 in-flight scenarios currently carry no marker, so it is not hypothetical.
	alreadyThere, err := inFlightIDsAtMergeBase(ctx, changesDir, baseRef)
	if err != nil {
		return nil, err
	}
	declared, err := InFlightScenarios(changesDir)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(declared))
	var out []Scenario
	for _, s := range declared {
		if _, ok := touched[s.ID]; !ok {
			continue
		}
		if _, ok := alreadyThere[s.ID]; ok {
			continue
		}
		if _, ok := canonical[s.ID]; ok {
			continue
		}
		if _, ok := covered[s.ID]; ok {
			continue
		}
		if !s.Normative {
			continue
		}
		// One entry per ID. Two changes restating one requirement declare the same scenario twice, and a reader fixing it has
		// one thing to do either way.
		if _, dup := seen[s.ID]; dup {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

// printUngatedInFlight reports the scenarios a branch introduces without a marker, and says what to do about them.
func printUngatedInFlight(scenarios []Scenario) {
	fmt.Printf("spectrace: %d scenario(s) added by an in-flight delta on this branch have no test marker:\n", len(scenarios))
	for _, s := range scenarios {
		fmt.Printf("  %s\n    %s:%d\n", s.ID, s.SourcePath, s.SourceLine)
	}
	fmt.Println("  Add a `// spec:<id>` marker to a test that exercises the scenario, in this PR. spectrace accepts a marker")
	fmt.Println("  pointing at a delta-declared scenario, so it does not have to reach openspec/specs first.")
}

// canonicalIDs projects the canonical scenarios to a set, for the exclusion above.
func canonicalIDs(scenarios []Scenario) map[string]struct{} {
	ids := make(map[string]struct{}, len(scenarios))
	for _, s := range scenarios {
		ids[s.ID] = struct{}{}
	}
	return ids
}

// inFlightIDsAtMergeBase returns the scenario IDs the changed delta files already declared at the merge base.
//
// Only the CHANGED files are read, which is the whole set that matters: a scenario in a file this branch did not touch cannot
// have been reported as touched in the first place.
//
// A file that does not exist at the merge base is a delta this branch created, and `git show` fails for it. That is not an error
// to propagate: everything in a new file is new, which is exactly what an empty result for it means.
func inFlightIDsAtMergeBase(ctx context.Context, changesDir, baseRef string) (map[string]struct{}, error) {
	if baseRef == "" {
		baseRef = defaultBaseRef
	}
	if err := validateBaseRef(baseRef); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, gitCommandTimeout)
	defer cancel()

	repoRoot, err := gitTopLevel(ctx)
	if err != nil {
		return nil, fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	mergeBase, err := gitMergeBase(ctx, repoRoot, baseRef)
	if err != nil {
		return nil, fmt.Errorf("git merge-base HEAD %s: %w", baseRef, err)
	}
	changed, err := gitChangedFiles(ctx, repoRoot, mergeBase, changesDir)
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only: %w", err)
	}

	out := make(map[string]struct{})
	for _, file := range changed {
		if filepath.Base(file) != "spec.md" || strings.Contains(filepath.ToSlash(file), "/"+archiveDirName+"/") {
			continue
		}
		blob, showErr := gitShowFile(ctx, repoRoot, mergeBase, file)
		if showErr != nil {
			// The file is new on this branch, so it declared nothing at the merge base.
			continue
		}
		scenarios, parseErr := parseSpec(strings.NewReader(blob), filepath.Base(filepath.Dir(file)), file)
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s at %s: %w", file, mergeBase, parseErr)
		}
		for _, sc := range scenarios {
			out[sc.ID] = struct{}{}
		}
	}
	return out, nil
}

// gitShowFile returns a file's contents at a revision.
func gitShowFile(ctx context.Context, repoRoot, rev, file string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "show", rev+":"+file) //nolint:gosec // rev is a merge base, file comes from git diff
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", wrapGitErr(err, out)
	}
	return string(out), nil
}
