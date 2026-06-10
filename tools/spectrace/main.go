// spectrace is the UAT plan M13 deliverable: a contributor-facing linter that ties each `#### Scenario:` heading under a
// SHALL / MUST `### Requirement:` in openspec/specs/<dir>/spec.md to a test marker somewhere in the codebase. The marker
// syntax and the canonical-ID slug rule are documented in docs/testing-strategy.md.
//
// Three subcommands ship:
//
//	tools/spectrace check         walks specs + sources, prints a coverage gap report, exits 1 on INVALID references and
//	                              (with --strict) on uncovered SHALL / MUST scenarios. --new-code scopes the gate to
//	                              scenarios added or modified in the current PR (via git diff against the merge base).
//	                              --by-layer expands the gap output with the per-layer coverage profile so contributors
//	                              can see which test rung is missing.
//	tools/spectrace list-ids      prints every canonical scenario ID, one per line. Useful when authoring a test marker
//	                              without typing the slug by hand.
//	tools/spectrace report        renders a Markdown coverage matrix (one row per scenario, one column per layer L0..L6
//	                              and an optional Other column for non-test enforcement markers) to stdout or --output.
//	                              No gating; the matrix is for humans + PR comments.
//
// Phased rollout matches the plan's "never goes red on day one" guidance: the CI workflow this binary feeds is advisory by
// default (exit code is 0 when there are uncovered SHALL / MUST scenarios but no invalid references), --strict is the
// "full gate" toggle, and --new-code is the SonarCloud-style "fail only on the delta this PR introduced" intermediate.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	defaultSpecsDir = "openspec/specs"
	defaultRootDir  = "."
	// defaultChangesDir holds in-flight OpenSpec change proposals. Scenarios declared in their delta specs
	// (openspec/changes/<change>/specs/<capability>/spec.md) are treated as VALID marker targets so a test can
	// reference a not-yet-archived scenario ID without spectrace flagging a dangling reference. They are not added to
	// the gated coverage set: a proposal imposes no coverage obligation until it is archived into openspec/specs.
	defaultChangesDir = "openspec/changes"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
	switch cmd {
	case "check":
		os.Exit(runCheck(rest))
	case "list-ids":
		os.Exit(runListIDs(rest))
	case "report":
		os.Exit(runReport(rest))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "spectrace: unknown subcommand %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `spectrace: openspec spec-to-test traceability linter

Usage:
  spectrace check    [--specs-dir DIR] [--changes-dir DIR] [--root DIR] [--strict] [--by-layer] [--new-code] [--base-ref REF]
  spectrace list-ids [--specs-dir DIR] [--normative-only]
  spectrace report   [--specs-dir DIR] [--changes-dir DIR] [--root DIR] [--format md] [--output FILE] [--normative-only]

Subcommands:
  check     Walk specs and codebase; report uncovered scenarios and invalid references.
            Exit code 0 unless --strict is set or invalid references are present.
            --changes-dir  openspec/changes tree; scenarios in in-flight proposals are valid
                           marker targets (not yet gated for coverage). Default openspec/changes.
            --by-layer  Annotate the gap report with per-layer coverage (L0..L6).
            --new-code  Gate only on scenarios added or modified in the current PR (diff against --base-ref).
            --base-ref  Git revision the merge base is computed against (default: origin/main).
  list-ids  Print canonical scenario IDs, one per line.
  report    Render the Markdown coverage matrix (one row per scenario, one column per layer).
            Exit code 0 on a clean render; the subcommand never gates.

See docs/testing-strategy.md for the marker syntax and rollout plan.
`)
}

// runCheck loads every scenario from --specs-dir, every marker from --root, and reports the coverage diff. Exit codes:
//
//	0 = clean (or only advisory issues without --strict)
//	1 = invalid references present, OR --strict and uncovered SHALL/MUST scenarios in the gated set
//	2 = usage / IO error
//
// --new-code restricts the gated SHALL/MUST set to scenarios added or modified in the current branch relative to
// --base-ref (default origin/main). The framing matches SonarCloud's "new code" gate: an unfixed legacy gap doesn't
// block a PR that doesn't touch it, but a new gap added by the PR does. --by-layer expands the gap output with the
// per-layer coverage profile per scenario so contributors can see which test rung is missing.
func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	specsDir := fs.String("specs-dir", defaultSpecsDir, "root of the openspec/specs tree")
	changesDir := fs.String("changes-dir", defaultChangesDir, "openspec/changes tree; in-flight proposal scenarios are valid marker targets")
	rootDir := fs.String("root", defaultRootDir, "root of the source tree to scan for markers")
	strict := fs.Bool("strict", false, "exit non-zero if any SHALL/MUST scenario is uncovered")
	byLayer := fs.Bool("by-layer", false, "annotate the gap report with per-layer coverage (L0..L6)")
	newCode := fs.Bool("new-code", false, "gate only on scenarios added or modified in the current branch")
	baseRef := fs.String("base-ref", defaultBaseRef, "git revision the merge base is computed against (for --new-code)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Promote --specs-dir / --root to their repo-root-relative form so spectrace works whether invoked from the repo
	// top-level (CI shape) or a nested package (Copilot's PR #281 concern). Defaults bind to the repo root unconditionally
	// because their literal cwd-relative meaning is rarely the intent; explicit values keep cwd-first semantics.
	setFlags := userSetFlagNames(fs)
	*specsDir = resolvePathFlag(*specsDir, setFlags["specs-dir"])
	*changesDir = resolvePathFlag(*changesDir, setFlags["changes-dir"])
	*rootDir = resolvePathFlag(*rootDir, setFlags["root"])

	scenarios, referenceValid, markers, exitCode := loadScenariosAndMarkers(*specsDir, *changesDir, *rootDir)
	if exitCode != 0 {
		return exitCode
	}

	// A marker is a valid reference when its ID is in referenceValid (live specs ∪ in-flight proposals); only then does it
	// count toward `covered`. A live scenario it points at is covered; a WIP-only ID resolves without error but covers no
	// gated scenario (WIP scenarios are not in `scenarios`, so splitUncovered + --strict ignore them).
	covered := make(map[string][]Marker, len(markers))
	var invalid []Marker
	for _, m := range markers {
		if _, ok := referenceValid[m.ID]; ok {
			covered[m.ID] = append(covered[m.ID], m)
			continue
		}
		invalid = append(invalid, m)
	}

	uncoveredNormative, uncoveredAdvisory := splitUncovered(scenarios, covered)

	gatedNormative := uncoveredNormative
	if *newCode {
		newCodeIDs, err := computeNewCodeScenarioIDs(context.Background(), *specsDir, *baseRef)
		if err != nil {
			fmt.Fprintln(os.Stderr, "spectrace --new-code:", err)
			return 2
		}
		gatedNormative = filterByIDSet(uncoveredNormative, newCodeIDs)
		fmt.Printf("spectrace: --new-code scope: %d scenarios touched in branch (vs %s)\n",
			len(newCodeIDs), *baseRef)
	}

	printReport(scenarios, uncoveredNormative, uncoveredAdvisory, invalid)
	if *byLayer {
		printByLayer(scenarios, covered)
	}

	switch {
	case len(invalid) > 0:
		return 1
	case *strict && len(gatedNormative) > 0:
		return 1
	default:
		return 0
	}
}

// filterByIDSet keeps only scenarios whose ID is in the set. Used by --new-code to scope the gate to scenarios touched
// by the current branch.
func filterByIDSet(in []Scenario, ids map[string]struct{}) []Scenario {
	if len(ids) == 0 {
		return nil
	}
	out := in[:0:0]
	for _, s := range in {
		if _, ok := ids[s.ID]; ok {
			out = append(out, s)
		}
	}
	return out
}

// printByLayer writes a per-scenario layer coverage map to stderr. Each line is `<id> [L0,L4]` listing the labels of the
// layers that cover the scenario; empty brackets mean the scenario is uncovered. The output is intentionally compact so a
// human skimming a 200-scenario report can scan it; for the full detail (with file:line links per cell), use
// `spectrace report --format=md`.
func printByLayer(scenarios []Scenario, covered map[string][]Marker) {
	fmt.Fprintln(os.Stderr, "\nPer-layer coverage (--by-layer):")
	for _, s := range scenarios {
		fmt.Fprintf(os.Stderr, "  %s [%s]\n", s.ID, layerLabelsFor(covered[s.ID]))
	}
}

// layerLabelsFor returns a comma-separated list of the unique layer labels that cover the scenario. Empty if no markers.
func layerLabelsFor(markers []Marker) string {
	seen := make(map[Layer]struct{}, len(markers))
	for _, m := range markers {
		seen[m.Layer] = struct{}{}
	}
	var labels []string
	for _, l := range allTestLayers {
		if _, ok := seen[l]; ok {
			labels = append(labels, l.Label())
		}
	}
	if _, ok := seen[LayerOther]; ok {
		labels = append(labels, LayerOther.Label())
	}
	return strings.Join(labels, ",")
}

// buildCanonicalSet builds the lookup map used to validate marker references AND fails fast if two scenarios slug to the
// same canonical ID. A silent collapse would let one marker appear to cover two scenarios and hide a real gap, so duplicate
// IDs are surfaced as a hard error pointing at both source locations. With the slug algorithm in spec.go, collisions can
// only happen when two requirement+scenario heading pairs slugify identically; if that happens, one of the spec headings
// needs to be edited.
func buildCanonicalSet(scenarios []Scenario) (map[string]struct{}, error) {
	canonical := make(map[string]struct{}, len(scenarios))
	seen := make(map[string]Scenario, len(scenarios))
	for _, s := range scenarios {
		if prev, exists := seen[s.ID]; exists {
			return nil, fmt.Errorf("duplicate canonical scenario ID %q at %s:%d and %s:%d (rename one of the spec headings)",
				s.ID, prev.SourcePath, prev.SourceLine, s.SourcePath, s.SourceLine)
		}
		seen[s.ID] = s
		canonical[s.ID] = struct{}{}
	}
	return canonical, nil
}

// splitUncovered separates the uncovered scenarios into normative (SHALL/MUST) and advisory (no normative keyword in the
// requirement body). Only the normative set is gateable; the advisory set is informational.
func splitUncovered(scenarios []Scenario, covered map[string][]Marker) ([]Scenario, []Scenario) {
	var normative, advisory []Scenario
	for _, s := range scenarios {
		if _, ok := covered[s.ID]; ok {
			continue
		}
		if s.Normative {
			normative = append(normative, s)
		} else {
			advisory = append(advisory, s)
		}
	}
	return normative, advisory
}

func printReport(scenarios []Scenario, uncoveredNormative, uncoveredAdvisory []Scenario, invalid []Marker) {
	totalNormative := 0
	for _, s := range scenarios {
		if s.Normative {
			totalNormative++
		}
	}
	coveredNormative := totalNormative - len(uncoveredNormative)

	fmt.Printf("spectrace: %d/%d normative scenarios have a test marker (%.0f%%)\n",
		coveredNormative, totalNormative, percent(coveredNormative, totalNormative))
	fmt.Printf("spectrace: %d advisory scenarios uncovered (requirement body has no SHALL/MUST)\n",
		len(uncoveredAdvisory))
	fmt.Printf("spectrace: %d invalid references in tests (ID does not exist in any spec)\n", len(invalid))

	if len(invalid) > 0 {
		fmt.Fprintln(os.Stderr, "\nInvalid references:")
		for _, m := range invalid {
			fmt.Fprintf(os.Stderr, "  %s:%d  spec:%s\n", m.SourcePath, m.SourceLine, m.ID)
		}
	}
	if len(uncoveredNormative) > 0 {
		fmt.Fprintln(os.Stderr, "\nUncovered SHALL/MUST scenarios:")
		for _, s := range uncoveredNormative {
			fmt.Fprintf(os.Stderr, "  %s:%d  %s\n", s.SourcePath, s.SourceLine, s.ID)
		}
	}
}

func percent(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return 100 * float64(num) / float64(denom)
}

// runListIDs prints every canonical scenario ID, one per line. With --normative-only the output is restricted to scenarios
// whose parent requirement has a SHALL/MUST in its body; that's the set the gate is concerned with.
func runListIDs(args []string) int {
	fs := flag.NewFlagSet("list-ids", flag.ContinueOnError)
	specsDir := fs.String("specs-dir", defaultSpecsDir, "root of the openspec/specs tree")
	normativeOnly := fs.Bool("normative-only", false, "restrict output to scenarios under SHALL/MUST requirements")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	*specsDir = resolvePathFlag(*specsDir, userSetFlagNames(fs)["specs-dir"])
	scenarios, err := ParseAllSpecs(*specsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spectrace: parse specs:", err)
		return 2
	}
	ids := make([]string, 0, len(scenarios))
	for _, s := range scenarios {
		if *normativeOnly && !s.Normative {
			continue
		}
		ids = append(ids, s.ID)
	}
	sort.Strings(ids)
	fmt.Println(strings.Join(ids, "\n"))
	return 0
}
