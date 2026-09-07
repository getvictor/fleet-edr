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
	removedLater map[string]string,
) []string {
	var losses []string
	for _, requirement := range sortedKeysOfArchived(archived) {
		entries := archived[requirement]
		if len(entries) == 0 {
			continue
		}
		winner := entries[len(entries)-1]
		// A requirement a retirement reached legitimately has nothing canonical left, and this compares the archive DATES rather
		// than the folder names.
		//
		// Comparing names was the bug review caught, and it was the same mistake this file's own comment warns about: within a
		// batch every folder carries one date, so a name comparison degenerates to alphabetical order. The pending pair
		// `latch-dns-proxy-bypass` (restates) and `dns-proxy-no-bypass` (retires) archive together, and the remover sorts first
		// alphabetically, so a correct retirement would have been reported as a loss the moment they landed.
		//
		// Equal dates therefore mean "cannot tell", and cannot-tell is silence: a false positive here costs more than a missed
		// one, because the whole procedure is a reader comparing two lists and noticing what is new.
		if by, ok := removedLater[requirement]; ok && archiveDate(by) >= archiveDate(winner.change) {
			continue
		}
		have := canonical[requirement]
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

// collectArchivedRestatements walks the archive subtree and returns each requirement's restatements in archive order, plus the
// change that last retired a requirement.
func collectArchivedRestatements(changesDir string) (map[string][]archivedRestatement, map[string]string, error) {
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
	removedLater := make(map[string]string)
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
			removedLater[requirement] = name
		}
	}
	return restatements, removedLater, nil
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
	canonical := make(map[string]map[string]struct{})
	for _, s := range scenarios {
		key := s.SpecDir + "/" + slugify(s.Requirement)
		if canonical[key] == nil {
			canonical[key] = make(map[string]struct{})
		}
		canonical[key][slugify(s.Title)] = struct{}{}
	}

	archived, removedLater, err := collectArchivedRestatements(*changesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}

	return printArchiveVerify(os.Stdout, verifyArchive(archived, canonical, removedLater), len(archived))
}

// printArchiveVerify renders the report. It returns 0 whatever it finds, because the tree carries pre-existing entries that this
// pass cannot classify, and a command that fails from the day it lands is a command someone adds a skip for. The checklist reads
// it by DIFFERENCE: a line that was not there before this archive is one this archive caused.
func printArchiveVerify(w io.Writer, findings []string, requirements int) int {
	if len(findings) == 0 {
		fmt.Fprintf(w, "spectrace: %d archived requirement restatement(s) checked, every scenario still canonical\n", requirements)
		return 0
	}
	fmt.Fprintf(w, "spectrace: %d scenario(s) an archived restatement listed are not in the canonical spec.\n", len(findings))
	fmt.Fprintln(w, "Compare this list with the one from before the archive. A line that is NEW is a scenario this archive")
	fmt.Fprintln(w, "discarded, which is what archiving out of order does. A line that was already there is either an older")
	fmt.Fprintln(w, "loss or a scenario a later change retired, which this cannot tell apart: openspec stamps one batch with")
	fmt.Fprintln(w, "one date, so the order within it is not recoverable.")
	for _, l := range findings {
		fmt.Fprintf(w, "  %s\n", l)
	}
	return 0
}

// archiveDate is the YYYY-MM-DD an archive folder is prefixed with, or the whole name when it carries no date.
//
// Prefix rather than a parse, which also handles the malformed double-date folders that predate this (`2026-06-09-2026-06-09-x`):
// their first ten characters are still the date, and a stricter reader would have to special-case them for no gain.
func archiveDate(folder string) string {
	const dateLen = len("2006-01-02")
	if len(folder) < dateLen {
		return folder
	}
	return folder[:dateLen]
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
