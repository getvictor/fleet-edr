package sigma

// This file answers one question: which of a rule's searches does every event carrying their fields satisfy?
//
// It lives with the matcher because it is a question about COMPILED structure, and nothing outside this package can answer it
// without re-parsing the rule, which would be a second implementation of matching semantics to keep in step with the first.
//
// The point is precision rather than alarm. A warning that fires on rules an operator wrote deliberately gets ignored, and is
// then worth nothing on the day it matters, so each predicate below is written to the exact shape that matches everything and
// not to a family of shapes that look broad.

// matchesAnyValue reports whether this glob is satisfied by every string.
//
// True only for a pattern that is all stars: `*` compiles to TWO empty segments, one either side of the star, and match walks the
// first from the start and the last to the end with nothing in between, so anything satisfies it. `**` collapses to the same
// shape.
//
// The `len(g.segs) > 1` guard is doing real work and is not defensive. An EMPTY pattern compiles to ONE empty segment, and a
// single segment has to account for every byte (see match), so it matches only the empty string: the narrowest pattern there is.
// A predicate written as "every segment is empty" would call that undiscriminating, which is exactly backwards.
func (g glob) matchesAnyValue() bool {
	if len(g.segs) < 2 {
		return false
	}
	for _, s := range g.segs {
		if len(s.atoms) > 0 {
			// A middle segment with atoms requires those atoms to appear, and a first or last one anchors an end. `*?*` lands
			// here: narrow, but not nothing.
			return false
		}
	}
	return true
}

// matchesAnyValue reports whether this value test is satisfied by every value.
//
// Only the glob form can be. A literal matches that literal and nothing else.
//
// The regexp form deliberately answers false rather than guessing. Deciding whether a regular expression matches every string is
// a question about that engine and not about globs, and a predicate that quietly said false for `.*` while claiming to cover
// regexps would be worse than one that does not claim to: the operator would read the absence of a warning as reassurance.
func (v valueTest) matchesAnyValue() bool {
	return v.glob != nil && v.glob.matchesAnyValue()
}

// discriminatesNothing reports whether every event carrying this field satisfies the test.
//
// It composes the way match does, which is the only way to stay exact:
//
//   - The default form is satisfied when ANY listed value matches, so one unrestrictive value is enough to decide the whole test.
//   - The `|all` form needs EVERY listed value to match, so it takes all of them being unrestrictive.
//
// `Field: null` needs no clause of its own, which is worth stating because the obvious version of this function has one.
// compileFieldTest sets absent and returns immediately, before any value is compiled, so an absent test always carries zero
// values and the empty-list guard below already answers it. An explicit `f.absent` check would be a second condition that cannot
// disagree with the first, which is dead code rather than robustness. The invariant it leans on is pinned by
// TestFieldTest_AbsentCarriesNoValues so a change to compileFieldTest breaks a test rather than this predicate quietly.
//
// Presence is still required, which is why the caller words the warning as being about events that carry the field rather than
// about every event. For an exec event's Image that is a distinction without a difference, and for a field only some events carry
// it is not.
func (f fieldTest) discriminatesNothing() bool {
	if len(f.tests) == 0 {
		return false
	}
	if f.all {
		for _, t := range f.tests {
			if !t.matchesAnyValue() {
				return false
			}
		}
		return true
	}
	for _, t := range f.tests {
		if t.matchesAnyValue() {
			return true
		}
	}
	return false
}

// discriminatesNothing reports whether every event carrying the relevant fields satisfies this search.
//
// A search holds ALTERNATIVES (Sigma's list-of-maps form), and is satisfied when any one of them is. So the search discriminates
// nothing as soon as one alternative's every field test does; the others cannot narrow it, because they are not required to hold.
func (s search) discriminatesNothing() bool {
	for _, alt := range s.alternatives {
		if len(alt) == 0 {
			continue
		}
		undiscriminating := true
		for _, f := range alt {
			if !f.discriminatesNothing() {
				undiscriminating = false
				break
			}
		}
		if undiscriminating {
			return true
		}
	}
	return false
}

// UndiscriminatingSearches returns the names of this rule's searches that every event carrying their fields satisfies.
//
// Names rather than a boolean, because an operator fixing this needs to know where to look: a rule with six searches and one
// wildcard is a different problem from one that is wildcards throughout, and a bare "this rule is too broad" makes them find out
// which for themselves.
//
// Nil when every search restricts something, so a caller can treat the result as the warning list directly.
//
// Note what this does NOT consider: the condition. A search that discriminates nothing is worth reporting even inside a condition
// that narrows it, because it contributes nothing there either, and reasoning about whether `a and not b` is broad overall means
// reasoning about the whole boolean expression rather than about one search. Reporting the search is the honest claim.
func (r *Rule) UndiscriminatingSearches() []string {
	var names []string
	for _, s := range r.searches {
		if s.discriminatesNothing() {
			names = append(names, s.name)
		}
	}
	return names
}
