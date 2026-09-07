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
	// A REMOVED after a MODIFIED, always. The restatement re-creates the requirement it replaces, so a retirement applied before it
	// is undone by it.
	//
	// This edge is emitted whether or not an ADDED is also pending, and skipping it when one was is the bug review found: with an
	// add, a remove and a modify in three separate changes, the adder-first edges alone leave add-remove-modify a legal order, and
	// the modify then recreates the requirement the remove had retired. Constraining the pair directly is what closes it, because
	// the ordering is transitive only if every edge is present.
	for requirement, removers := range d.removedBy {
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
			// Everything left is blocked by something else left, but that set is wider than the cycle: a change that merely
			// depends on a cycle member is stuck too, and naming it would send someone to split a delta that is not the problem.
			return order, onlyCycles(remaining, blockers)
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

// onlyCycles narrows a stalled set to the changes actually ON a cycle.
//
// Kahn's algorithm stalls with everything that still has a prerequisite, which includes the descendants of a cycle as well as its
// members. Those descendants are stuck but blameless, and reporting them invites reconciling the wrong delta.
//
// A change is on a cycle exactly when it can reach itself, which is exactly membership of a strongly connected component of more
// than one node. That is what this computes, by Tarjan.
//
// It used to peel sinks instead, on the reasoning that a descendant has no dependents inside the residual and a cycle member
// always has one. Review showed that is a different property: with two cycles joined by a path, a↔b and d↔e with b to c to d, the
// node c has both a prerequisite and a dependent and survives the peel, while being on no cycle at all. Having an edge in each
// direction is not the same as being able to get back.
func onlyCycles(stalled []string, blockers map[string]map[string]struct{}) []string {
	inSet := make(map[string]struct{}, len(stalled))
	for _, c := range stalled {
		inSet[c] = struct{}{}
	}
	// Edges point from a change to the ones that must precede it, which is the direction blockers already holds. Tarjan does not
	// care which way round they are: a component that is strongly connected one way is strongly connected the other.
	edges := func(c string) []string {
		var out []string
		for b := range blockers[c] {
			if _, ok := inSet[b]; ok {
				out = append(out, b)
			}
		}
		sort.Strings(out)
		return out
	}

	index := make(map[string]int, len(inSet))
	low := make(map[string]int, len(inSet))
	onStack := make(map[string]bool, len(inSet))
	var stack []string
	next := 0
	cyclic := make(map[string]struct{})

	var strongConnect func(v string)
	strongConnect = func(v string) {
		index[v] = next
		low[v] = next
		next++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range edges(v) {
			switch {
			case func() bool { _, seen := index[w]; return !seen }():
				strongConnect(w)
				low[v] = min(low[v], low[w])
			case onStack[w]:
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] != index[v] {
			return
		}
		var component []string
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			component = append(component, w)
			if w == v {
				break
			}
		}
		// A component of one is only a cycle if it points at itself, which a constraint from a change to itself would be. Those
		// are dropped upstream, so this is belt and braces rather than a reachable case.
		if len(component) > 1 {
			for _, c := range component {
				cyclic[c] = struct{}{}
			}
			return
		}
		for _, w := range edges(v) {
			if w == v {
				cyclic[v] = struct{}{}
			}
		}
	}

	for _, c := range sortedKeys(inSet) {
		if _, seen := index[c]; !seen {
			strongConnect(c)
		}
	}
	return sortedKeys(cyclic)
}

// printArchiveOrder renders the order and the constraints that shaped it.
//
// The constraints are printed as well as the order because the order alone is not checkable: a reader following it has no way to
// tell a real prerequisite from an alphabetical accident, and the whole point is that they can see why two changes are sequenced
// before they archive 87 of them.
func printArchiveOrder(w io.Writer, changes []string, constraints []archiveConstraint) bool {
	order, cycle := archiveOrder(changes, constraints)

	// Every write is checked, and a failed one fails the command. The caller is a release engineer following this list to archive
	// 88 things; a plan truncated by a broken pipe while the exit status says it succeeded is the one way this tool could cause the
	// loss it exists to prevent.
	var werr error
	p := func(format string, args ...any) {
		if werr != nil {
			return
		}
		_, werr = fmt.Fprintf(w, format, args...)
	}

	if len(constraints) == 0 {
		p("spectrace: %d pending change(s), no ordering constraints between them\n", len(changes))
		p("Any order archives correctly. This one is alphabetical:\n\n")
	} else {
		p("spectrace: %d pending change(s), %d ordering constraint(s)\n\n", len(changes), len(constraints))
		p("%s\n%s\n", "Constraints. The first change creates or restates a requirement the second replaces or retires, so applying",
			"them the other way round discards the second's text without an error:")
		for _, c := range constraints {
			p("  %s\n    must be archived before %s\n    because both touch %s\n", c.before, c.after, c.requirement)
		}
	}

	if cycle != nil {
		sort.Strings(cycle)
		p("\nNo order satisfies all of them. These changes each have to precede another in the set:\n")
		for _, c := range cycle {
			p("  %s\n", c)
		}
		p("\nSplit one of them, or reconcile the requirements they contend over, before archiving.\n")
		return false
	}

	// Printed even when nothing is constrained, because the checklist tells the operator to archive in the order this prints and
	// there is no other listing step left to fall back on.
	if len(constraints) > 0 {
		p("\nArchive in this order:\n")
	}
	for i, c := range order {
		p("  %3d. %s\n", i+1, c)
	}
	return werr == nil
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
