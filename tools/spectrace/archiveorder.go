package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// archiveConstraint is one ordering the batch archive must respect: `before` has to be applied ahead of `after`, because both
// touch `requirement` and one of them creates it.
type archiveConstraint struct {
	before      string
	after       string
	requirement string
}

// archiveConstraints derives the order the release archive must apply pending changes in.
//
// `openspec archive` applies a `## MODIFIED Requirements` entry by REPLACING the canonical requirement whole, and the changes
// accumulate unarchived across a release cycle (docs/release-checklist.md). So when one pending change ADDS a requirement and
// another MODIFIES it, the order decides the outcome and only one order is right: applied add-then-modify the requirement is
// created and then refined; applied modify-then-add the refinement is replaced by the original body and is silently gone.
//
// This is the half findRestatementConflicts cannot see. That gate requires concurrent restatements to be IDENTICAL, which makes
// "the last one wins" harmless between two MODIFIEDs. It compares MODIFIED against MODIFIED only, and an ADDED beside a MODIFIED
// is the commoner shape: one change introduces a requirement, a later one refines it, and both wait for the release (issue #901).
//
// A REMOVED is constrained the same way and for a sharper reason: applied before the MODIFIED of the same requirement, the
// requirement is deleted and then re-created by the restatement, so a retirement silently does not happen.
//
// Reported rather than forbidden. Two changes legitimately touching one requirement is ordinary in a batched-archive model, which
// is the same reasoning findRestatementConflicts gives for not banning concurrent restatements.
func archiveConstraints(d *deltaSections) []archiveConstraint {
	var out []archiveConstraint
	for requirement, adders := range d.addedBy {
		var laters []string
		for change := range d.modifiedRestatements[requirement] {
			laters = append(laters, change)
		}
		for change := range d.removedBy[requirement] {
			laters = append(laters, change)
		}
		for _, adder := range sortedKeys(adders) {
			for _, later := range sortedUnique(laters) {
				if adder == later {
					// One change that both adds and modifies the same requirement is not an ordering problem: openspec applies
					// its sections in file order, and there is nothing to sequence against.
					continue
				}
				out = append(out, archiveConstraint{before: adder, after: later, requirement: requirement})
			}
		}
	}
	// A REMOVED beside a MODIFIED, with no ADDED among the pending changes, still has to be sequenced: the requirement is already
	// canonical, so the restatement must land before the retirement or the retirement is undone.
	for requirement, removers := range d.removedBy {
		if len(d.addedBy[requirement]) > 0 {
			continue
		}
		for _, remover := range sortedKeys(removers) {
			for _, modifier := range sortedKeysOfRestatements(d.modifiedRestatements[requirement]) {
				if remover == modifier {
					continue
				}
				out = append(out, archiveConstraint{before: modifier, after: remover, requirement: requirement})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].before != out[j].before {
			return out[i].before < out[j].before
		}
		if out[i].after != out[j].after {
			return out[i].after < out[j].after
		}
		return out[i].requirement < out[j].requirement
	})
	return out
}

// archiveOrder returns an order for changes that satisfies every constraint, or the changes that form a cycle when none exists.
//
// Deterministic: among the changes whose prerequisites are all applied, the alphabetically first is taken next. Two runs on one
// tree therefore print the same order, which is what makes it something a release checklist can tell someone to follow.
//
// A cycle means two changes each have to precede the other, which no order fixes: change A adds one requirement that B modifies
// while B adds another that A modifies. The archive cannot resolve that and neither can this, so it is reported as the conflict it
// is rather than broken arbitrarily.
func archiveOrder(changes []string, constraints []archiveConstraint) (order []string, cycle []string) {
	blockers := make(map[string]map[string]struct{}, len(changes))
	known := make(map[string]struct{}, len(changes))
	for _, c := range changes {
		known[c] = struct{}{}
		blockers[c] = make(map[string]struct{})
	}
	for _, c := range constraints {
		// A constraint naming a change that is not pending is dropped rather than treated as an unsatisfiable prerequisite: it
		// means the delta references something already archived, which is not this pass's problem.
		if _, ok := known[c.before]; !ok {
			continue
		}
		if _, ok := known[c.after]; !ok {
			continue
		}
		blockers[c.after][c.before] = struct{}{}
	}

	remaining := append([]string(nil), changes...)
	sort.Strings(remaining)
	for len(remaining) > 0 {
		next := -1
		for i, c := range remaining {
			if len(blockers[c]) == 0 {
				next = i
				break
			}
		}
		if next == -1 {
			// Everything left is blocked by something else left.
			return order, remaining
		}
		picked := remaining[next]
		order = append(order, picked)
		remaining = append(remaining[:next], remaining[next+1:]...)
		for _, c := range remaining {
			delete(blockers[c], picked)
		}
	}
	return order, nil
}

// printArchiveOrder renders the order and the constraints that shaped it.
//
// The constraints are printed as well as the order because the order alone is not checkable: a reader following it has no way to
// tell a real prerequisite from an alphabetical accident, and the whole point is that they can see why two changes are sequenced
// before they archive 87 of them.
func printArchiveOrder(w io.Writer, changes []string, constraints []archiveConstraint) bool {
	order, cycle := archiveOrder(changes, constraints)

	if len(constraints) == 0 {
		fmt.Fprintf(w, "spectrace: %d pending change(s), no ordering constraints between them\n", len(changes))
		fmt.Fprintln(w, "Any order archives correctly; alphabetical is fine.")
		return true
	}

	fmt.Fprintf(w, "spectrace: %d pending change(s), %d ordering constraint(s)\n\n", len(changes), len(constraints))
	fmt.Fprintln(w, "Constraints. The first change creates or restates a requirement the second replaces or retires, so applying")
	fmt.Fprintln(w, "them the other way round discards the second's text without an error:")
	for _, c := range constraints {
		fmt.Fprintf(w, "  %s\n    must be archived before %s\n    because both touch %s\n", c.before, c.after, c.requirement)
	}

	if cycle != nil {
		sort.Strings(cycle)
		fmt.Fprintln(w, "\nNo order satisfies all of them. These changes each have to precede another in the set:")
		for _, c := range cycle {
			fmt.Fprintf(w, "  %s\n", c)
		}
		fmt.Fprintln(w, "\nSplit one of them, or reconcile the requirements they contend over, before archiving.")
		return false
	}

	fmt.Fprintln(w, "\nArchive in this order:")
	for i, c := range order {
		fmt.Fprintf(w, "  %3d. %s\n", i+1, c)
	}
	return true
}

// sortedKeys returns a set's keys in a stable order.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeysOfRestatements is sortedKeys for the restatement index, whose value type differs.
func sortedKeysOfRestatements(m map[string]restatement) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedUnique returns the distinct values in a stable order.
func sortedUnique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// runArchiveOrder prints the order the release archive must apply the pending changes in.
//
// Its own subcommand rather than output on `check`, because it answers a question asked once per release and `check` runs on every
// PR: printing nine standing constraints on every run would train a reader to skip them, which is how the ordering hazard would
// stay unread even after being reported.
func runArchiveOrder(args []string) int {
	fs := flag.NewFlagSet("archive-order", flag.ContinueOnError)
	changesDir := fs.String("changes-dir", defaultChangesDir, "openspec/changes tree holding the pending changes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := userSetFlagNames(fs)
	*changesDir = resolvePathFlag(*changesDir, setFlags["changes-dir"])

	sections, err := parseDeltaSections(*changesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-order: %v\n", err)
		return 2
	}
	var changes []string
	if err := forEachInFlightChangeDir(*changesDir, func(dir string) error {
		changes = append(changes, filepath.Base(dir))
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-order: %v\n", err)
		return 2
	}

	if printArchiveOrder(os.Stdout, changes, archiveConstraints(sections)) {
		return 0
	}
	return 1
}
