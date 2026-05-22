// spectrace is the UAT plan M13 deliverable: a contributor-facing linter that ties each `#### Scenario:` heading under a
// SHALL / MUST `### Requirement:` in openspec/specs/<dir>/spec.md to a test marker somewhere in the codebase. The marker
// syntax and the canonical-ID slug rule are documented in docs/testing-strategy.md.
//
// Two subcommands ship in v1:
//
//	tools/spectrace check         walks specs + sources, prints a coverage gap report, exits 1 on INVALID references and
//	                              (with --strict) on uncovered SHALL / MUST scenarios.
//	tools/spectrace list-ids      prints every canonical scenario ID, one per line. Useful when authoring a test marker
//	                              without typing the slug by hand.
//
// The `report --format=md` coverage matrix mentioned in docs/testing-strategy.md is intentionally deferred to a follow-up:
// it's a presentation layer over the same data the check command already collects, and the M13 budget is the linter.
//
// Phased rollout matches the plan's "never goes red on day one" guidance: the CI workflow this binary feeds is advisory by
// default (exit code is 0 when there are uncovered SHALL / MUST scenarios but no invalid references), and the --strict flag
// is the future "full gate" toggle.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	defaultSpecsDir = "openspec/specs"
	defaultRootDir  = "."
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
	fmt.Fprint(os.Stderr, `spectrace - openspec spec-to-test traceability linter

Usage:
  spectrace check      [--specs-dir DIR] [--root DIR] [--strict]
  spectrace list-ids   [--specs-dir DIR] [--normative-only]

Subcommands:
  check       Walk specs and codebase; report uncovered scenarios and invalid references.
              Exit code 0 unless --strict is set or invalid references are present.
  list-ids    Print canonical scenario IDs, one per line.

See docs/testing-strategy.md for the marker syntax and rollout plan.
`)
}

// runCheck loads every scenario from --specs-dir, every marker from --root, and reports the coverage diff. Exit codes:
//
//	0 = clean (or only advisory issues without --strict)
//	1 = invalid references present, OR --strict and uncovered SHALL/MUST scenarios present
//	2 = usage / IO error
func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	specsDir := fs.String("specs-dir", defaultSpecsDir, "root of the openspec/specs tree")
	rootDir := fs.String("root", defaultRootDir, "root of the source tree to scan for markers")
	strict := fs.Bool("strict", false, "exit non-zero if any SHALL/MUST scenario is uncovered")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	scenarios, err := ParseAllSpecs(*specsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spectrace: parse specs:", err)
		return 2
	}
	canonical, dupErr := buildCanonicalSet(scenarios)
	if dupErr != nil {
		fmt.Fprintln(os.Stderr, "spectrace:", dupErr)
		return 2
	}
	markers, err := ScanMarkers(*rootDir, canonical)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spectrace: scan markers:", err)
		return 2
	}

	covered := make(map[string][]Marker, len(markers))
	var invalid []Marker
	for _, m := range markers {
		if _, ok := canonical[m.ID]; ok {
			covered[m.ID] = append(covered[m.ID], m)
			continue
		}
		invalid = append(invalid, m)
	}

	uncoveredNormative, uncoveredAdvisory := splitUncovered(scenarios, covered)

	printReport(scenarios, uncoveredNormative, uncoveredAdvisory, invalid)

	switch {
	case len(invalid) > 0:
		return 1
	case *strict && len(uncoveredNormative) > 0:
		return 1
	default:
		return 0
	}
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
