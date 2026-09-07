package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// archivedRestatement is one archived change's MODIFIED entry for one requirement, with the folder it came from.
type archivedRestatement struct {
	change    string
	scenarios []string
}

// verifyArchive reports scenarios an archived restatement listed that the canonical tree no longer has.
//
// This is the detection half of issue #901, and it exists because the prevention half is advice. `archive-order` prints an order,
// and an operator who archives in a different one gets no error from anything: `openspec validate --strict` passes on a
// requirement that lost half its text, and `check --strict` passes as long as whatever survived still has markers.
//
// The check is on SCENARIOS rather than on prose, deliberately. Archiving merges rather than copies, so comparing wording would
// report formatting as loss and train a reader to ignore the output. A scenario heading is stable through the merge, is what the
// v0.4.0 archive dropped, and is what the traceability gate keys on, so a missing one is both detectable and material.
//
// What this CANNOT do is tell a loss from a legitimate retirement, and the reason is worth stating because it bounds the whole
// design: openspec stamps every folder in one batch with the same date, so within a batch the archive order is not recoverable
// from the tree, and "the last restatement wins" cannot be evaluated. A scenario a later change deliberately retired therefore
// looks the same here as one an out-of-order archive discarded.
//
// So this REPORTS and does not gate, and the checklist uses it as a before-and-after: run it, archive, run it again, and any line
// that is new is a scenario this archive lost. That comparison needs no ordering and no baseline file, and it is the question a
// release engineer actually has.
func verifyArchive(archived map[string][]archivedRestatement, canonical map[string]map[string]struct{},
	retired map[string]struct{},
) []string {
	var losses []string
	for _, requirement := range sortedKeysOfArchived(archived) {
		entries := archived[requirement]
		if len(entries) == 0 {
			continue
		}
		winner := entries[len(entries)-1]
		have, stillCanonical := canonical[requirement]
		// A retirement excuses a requirement that is GONE, and the canonical tree is what says whether it took effect.
		//
		// Two earlier versions of this asked the archive folders instead, and both were wrong in the same way. Comparing folder
		// names is alphabetical order, which review caught: within a batch every folder carries one date, so the pending pair
		// `latch-dns-proxy-bypass` (restates) and `dns-proxy-no-bypass` (retires) would have read as a loss. Comparing DATES fixed
		// that and left the opposite hole: a retirement the archive did not end up applying, because a later change re-created the
		// requirement, still excused it, so a restatement's scenarios could go missing from a requirement that is right there in
		// the tree.
		//
		// Neither question needed asking. The end state answers both: gone plus a recorded retirement is a retirement that
		// happened, and present means it did not, whatever order the folders imply.
		if !stillCanonical {
			if _, ok := retired[requirement]; ok {
				continue
			}
		}
		for _, scenario := range winner.scenarios {
			if _, ok := have[scenario]; ok {
				continue
			}
			losses = append(losses, fmt.Sprintf("%s/%s\n    listed by %s, the last change archived that restated it, and not in the canonical spec",
				requirement, scenario, winner.change))
		}
	}
	sort.Strings(losses)
	return losses
}

// canonicalScenarios indexes the canonical tree the way the archived deltas are keyed, so the two sides of the comparison derive
// their keys in one place rather than in two that agree until one is edited.
func canonicalScenarios(scenarios []Scenario) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	for _, s := range scenarios {
		key := s.SpecDir + "/" + slugify(s.Requirement)
		if out[key] == nil {
			out[key] = make(map[string]struct{})
		}
		out[key][slugify(s.Title)] = struct{}{}
	}
	return out
}

// collectArchivedRestatements walks the archive subtree and returns each requirement's restatements in archive order, plus the
// requirements some archived change retired.
func collectArchivedRestatements(changesDir string) (map[string][]archivedRestatement, map[string]struct{}, error) {
	archiveDir := filepath.Join(changesDir, archiveDirName)
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	restatements := make(map[string][]archivedRestatement)
	retired := make(map[string]struct{})
	for _, name := range names {
		one := &deltaSections{
			removedRequirements:  make(map[string]struct{}),
			addedBy:              make(map[string]map[string]struct{}),
			removedBy:            make(map[string]map[string]struct{}),
			modifiedRestatements: make(map[string]map[string]restatement),
		}
		if err := one.collectChange(filepath.Join(archiveDir, name)); err != nil {
			return nil, nil, err
		}
		for requirement, byChange := range one.modifiedRestatements {
			for _, r := range byChange {
				restatements[requirement] = append(restatements[requirement],
					archivedRestatement{change: name, scenarios: sortedKeys(r.scenarios)})
			}
		}
		for requirement := range one.removedRequirements {
			retired[requirement] = struct{}{}
		}
	}
	return restatements, retired, nil
}

// runArchiveVerify is the post-archive half of the release checklist's step 1.
func runArchiveVerify(args []string) int {
	fs := flag.NewFlagSet("archive-verify", flag.ContinueOnError)
	specsDir := fs.String("specs-dir", defaultSpecsDir, "root of the openspec/specs tree")
	changesDir := fs.String("changes-dir", defaultChangesDir, "openspec/changes tree, whose archive subtree is read")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := userSetFlagNames(fs)
	*specsDir = resolvePathFlag(*specsDir, setFlags["specs-dir"])
	*changesDir = resolvePathFlag(*changesDir, setFlags["changes-dir"])

	scenarios, err := ParseAllSpecs(*specsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}
	canonical := canonicalScenarios(scenarios)

	archived, retired, err := collectArchivedRestatements(*changesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}

	return printArchiveVerify(os.Stdout, verifyArchive(archived, canonical, retired), len(archived))
}

// printArchiveVerify renders the report. FINDINGS never gate: the tree carries pre-existing entries this pass cannot classify,
// and a command that fails from the day it lands is a command someone adds a skip for. The checklist reads it by DIFFERENCE, so a
// line that was not there before this archive is one this archive caused.
//
// A failed WRITE does gate, and the distinction is the point. The whole procedure is a release engineer diffing this output
// against the run from before archiving, so a report truncated by a broken pipe while the status says it succeeded would hide
// exactly the new line the diff exists to surface. That is the same reasoning report.go records for PR #281, and printArchiveOrder
// for its plan. Returns 2 on a write failure, matching the usage/IO code the rest of the tool uses.
func printArchiveVerify(w io.Writer, findings []string, requirements int) int {
	var werr error
	p := func(format string, args ...any) {
		if werr != nil {
			return
		}
		_, werr = fmt.Fprintf(w, format, args...)
	}

	if len(findings) == 0 {
		p("spectrace: %d archived requirement restatement(s) checked, every scenario still canonical\n", requirements)
	} else {
		p("spectrace: %d scenario(s) an archived restatement listed are not in the canonical spec.\n", len(findings))
		p("%s\n%s\n%s\n",
			"Compare this list with the one from before the archive. A line that is NEW is a scenario this archive",
			"discarded, which is what archiving out of order does. A line that was already there is either an older loss,",
			"or a scenario dropped from a requirement that is still in the tree for a reason older than this run.")
		for _, l := range findings {
			p("  %s\n", l)
		}
	}

	if werr != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: write output: %v\n", werr)
		return 2
	}
	return 0
}

// sortedKeysOfArchived returns the requirement keys in a stable order.
func sortedKeysOfArchived(m map[string][]archivedRestatement) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
