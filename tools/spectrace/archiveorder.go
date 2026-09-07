package main

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
func archiveConstraints(d *deltaSections, canonical map[string]struct{}) []archiveConstraint {
	out := append(adderBeforeTheRest(d, canonical), modifierBeforeRemover(d)...)
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

// adderBeforeTheRest sequences the change that CREATES a requirement ahead of every change that replaces or retires it.
//
// Except when the requirement is ALREADY in the canonical spec, where an `## ADDED` delta for it does not mean what it says and
// the order cannot be derived from the deltas alone. Review raised the pair: one author retiring a requirement while another
// re-introduces it wants remove-then-add, and the ordinary create-then-retire wants add-then-remove, and the two are the same two
// files. What separates them is whether the requirement exists yet, which is why this reads the canonical tree.
//
// A pending ADDED for a requirement that already exists is malformed rather than ambiguous: openspec has no "add it again", and
// whichever order such a PAIR is archived in, one of the two authors does not get what their delta says. So the edge is emitted in
// BOTH directions and the pair surfaces through the cycle path, whose message already says to reconcile and whose constraint
// listing already names the requirement they contend over. No pending pair is in this state today.
//
// The PAIR is the whole of it, and the narrowness is deliberate: a lone pending ADDED for an existing requirement, or one beside a
// MODIFIED, still orders cleanly and is not reported. Validating a delta against the canonical tree is `openspec validate`'s job
// and would be a second implementation of it here; what this command owns is the ORDER, and a lone ADDED does not make one
// ambiguous. Review asked for the claim to match the code, and this is the half that is true.
func adderBeforeTheRest(d *deltaSections, canonical map[string]struct{}) []archiveConstraint {
	var out []archiveConstraint
	for requirement, adders := range d.addedBy {
		var modifiers []string
		for change := range d.modifiedRestatements[requirement] {
			modifiers = append(modifiers, change)
		}
		_, alreadyExists := canonical[requirement]
		// Two changes ADDING the same requirement have no order either, and each delta validates on its own. Whichever is
		// applied second replaces the other's body outright, so one author's text is discarded with no error: the same loss
		// #815's identical-restatement rule exists to prevent, in the section that rule does not read. Reported rather than
		// sequenced, for the reason the pair below is. No pending pair is in this state today.
		sortedAdders := sortedKeys(adders)
		for i, adder := range sortedAdders {
			for _, other := range sortedAdders[i+1:] {
				out = append(out,
					archiveConstraint{before: adder, after: other, requirement: requirement},
					archiveConstraint{before: other, after: adder, requirement: requirement})
			}
		}
		for _, adder := range sortedAdders {
			// One change that both adds and modifies the same requirement is not an ordering problem: openspec applies its
			// sections in file order, and there is nothing to sequence against.
			for _, modifier := range sortedUnique(modifiers) {
				if adder != modifier {
					out = append(out, archiveConstraint{before: adder, after: modifier, requirement: requirement})
				}
			}
			out = append(out, adderAgainstRemovers(requirement, adder, sortedKeys(d.removedBy[requirement]), alreadyExists)...)
		}
	}
	return out
}

// adderAgainstRemovers pairs one adder with the changes retiring the same requirement, in one direction or in both.
//
// Both when the requirement already exists, because then the pair has no safe order: see adderBeforeTheRest.
func adderAgainstRemovers(requirement, adder string, removers []string, alreadyExists bool) []archiveConstraint {
	var out []archiveConstraint
	for _, remover := range removers {
		if adder == remover {
			continue
		}
		out = append(out, archiveConstraint{before: adder, after: remover, requirement: requirement})
		if alreadyExists {
			out = append(out, archiveConstraint{before: remover, after: adder, requirement: requirement})
		}
	}
	return out
}

// modifierBeforeRemover sequences a restatement ahead of the retirement of the same requirement, always.
//
// The restatement re-creates the requirement it replaces, so a retirement applied before it is undone by it. This edge is emitted
// whether or not an ADDED is also pending, and skipping it when one was is the bug review found: with an add, a remove and a
// modify in three separate changes, the adder-first edges alone leave add-remove-modify a legal order, and the modify then
// recreates the requirement the remove had retired. Constraining the pair directly is what closes it, because the ordering is
// transitive only if every edge is present.
func modifierBeforeRemover(d *deltaSections) []archiveConstraint {
	var out []archiveConstraint
	for requirement, removers := range d.removedBy {
		for _, remover := range sortedKeys(removers) {
			for _, modifier := range sortedKeys(d.modifiedRestatements[requirement]) {
				if remover != modifier {
					out = append(out, archiveConstraint{before: modifier, after: remover, requirement: requirement})
				}
			}
		}
	}
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
	t := &tarjan{
		inSet:    make(map[string]struct{}, len(stalled)),
		blockers: blockers,
		index:    make(map[string]int, len(stalled)),
		low:      make(map[string]int, len(stalled)),
		onStack:  make(map[string]bool, len(stalled)),
		cyclic:   make(map[string]struct{}),
	}
	for _, c := range stalled {
		t.inSet[c] = struct{}{}
	}
	for _, c := range sortedKeys(t.inSet) {
		if _, seen := t.index[c]; !seen {
			t.visit(c)
		}
	}
	return sortedKeys(t.cyclic)
}

// tarjan is one run of the strongly-connected-components search over the stalled set.
type tarjan struct {
	inSet    map[string]struct{}
	blockers map[string]map[string]struct{}
	index    map[string]int
	low      map[string]int
	onStack  map[string]bool
	stack    []string
	next     int
	cyclic   map[string]struct{}
}

// edges point from a change to the ones that must precede it, which is the direction blockers already holds. Tarjan does not care
// which way round they are: a component that is strongly connected one way is strongly connected the other.
func (t *tarjan) edges(c string) []string {
	var out []string
	for b := range t.blockers[c] {
		if _, ok := t.inSet[b]; ok {
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out
}

func (t *tarjan) visit(v string) {
	t.index[v] = t.next
	t.low[v] = t.next
	t.next++
	t.stack = append(t.stack, v)
	t.onStack[v] = true
	for _, w := range t.edges(v) {
		if _, seen := t.index[w]; !seen {
			t.visit(w)
			t.low[v] = min(t.low[v], t.low[w])
			continue
		}
		if t.onStack[w] {
			t.low[v] = min(t.low[v], t.index[w])
		}
	}
	if t.low[v] == t.index[v] {
		t.closeComponent(v)
	}
}

// closeComponent pops the component rooted at v. A component of one is not a cycle: the only way it could be is a change
// constrained against itself, and both constraint passes skip that pair before it reaches the graph.
func (t *tarjan) closeComponent(v string) {
	var component []string
	for {
		w := t.stack[len(t.stack)-1]
		t.stack = t.stack[:len(t.stack)-1]
		t.onStack[w] = false
		component = append(component, w)
		if w == v {
			break
		}
	}
	if len(component) == 1 {
		return
	}
	for _, c := range component {
		t.cyclic[c] = struct{}{}
	}
}

// printArchiveOrder renders the order and the constraints that shaped it.
//
// The constraints are printed as well as the order because the order alone is not checkable: a reader following it has no way to
// tell a real prerequisite from an alphabetical accident, and the whole point is that they can see why two changes are sequenced
// before they archive a release's worth of them.
func printArchiveOrder(w io.Writer, changes []string, constraints []archiveConstraint) int {
	order, cycle := archiveOrder(changes, constraints)

	// Every write is checked, and a failed one fails the command with 2 rather than the 1 a cycle uses. The caller is a release
	// engineer working down this list one change at a time; a plan truncated by a broken pipe while the exit status says it
	// succeeded is the one way this tool could cause the loss it exists to prevent.
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
		if werr != nil {
			return writeFailure(werr)
		}
		return 1
	}

	// Printed even when nothing is constrained, because the checklist tells the operator to archive in the order this prints and
	// there is no other listing step left to fall back on.
	if len(constraints) > 0 {
		p("\nArchive in this order:\n")
	}
	for i, c := range order {
		p("  %3d. %s\n", i+1, c)
	}
	if werr != nil {
		return writeFailure(werr)
	}
	return 0
}

// writeFailure separates a broken pipe from a dependency cycle, which review caught sharing exit 1 with no diagnostic. The usage
// text and the checklist both define 1 as "split or reconcile a cycle", so a full disk reading as one sends the release engineer
// looking for a cycle that is not there.
func writeFailure(err error) int {
	fmt.Fprintf(os.Stderr, "spectrace archive-order: write output: %v\n", err)
	return 2
}

// sortedKeys returns a map's keys in a stable order, whatever the map holds. Generic because the two callers here differ only in
// the value type, and two copies of this that agree until one is edited is the shape this codebase keeps paying for.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
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
	specsDir := fs.String("specs-dir", defaultSpecsDir,
		"root of the openspec/specs tree, read to tell a new requirement from an existing one")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := userSetFlagNames(fs)
	*changesDir = resolvePathFlag(*changesDir, setFlags["changes-dir"])
	*specsDir = resolvePathFlag(*specsDir, setFlags["specs-dir"])
	// Both roots, because a --specs-dir that is not a directory yields an EMPTY canonical set rather than an error, and an empty
	// one classifies every pending ADDED as creating a new requirement. Review caught it: that is how a pair with no safe order
	// gets printed as a safe one.
	for _, dir := range []string{*changesDir, *specsDir} {
		if err := requireDir(dir); err != nil {
			fmt.Fprintf(os.Stderr, "spectrace archive-order: %v\n", err)
			return 2
		}
	}
	scenarios, specErr := ParseAllSpecs(*specsDir)
	if specErr != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-order: %v\n", specErr)
		return 2
	}
	canonical := canonicalRequirements(scenarios)

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

	return printArchiveOrder(os.Stdout, changes, archiveConstraints(sections, canonical))
}
