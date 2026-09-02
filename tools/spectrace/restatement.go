package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// restatementConflict is one requirement that concurrent in-flight changes restate differently.
type restatementConflict struct {
	// requirement is the "<capability>/<requirement-slug>" key.
	requirement string
	// versions groups the changes by the normalised text they restate, so a report can say "these three agree, that one does not"
	// rather than listing every pair.
	versions []restatementVersion
}

// restatementVersion is one distinct text and the changes that state it.
type restatementVersion struct {
	normalised string
	changes    []string
}

// findRestatementConflicts reports every requirement that more than one in-flight change restates, where the restatements are not
// all identical.
//
// IDENTICAL is the invariant, which is worth justifying because it looks needlessly strict. `openspec archive` applies a
// `## MODIFIED Requirements` entry by replacing the canonical requirement WHOLE, and archiving is batched at release
// (docs/release-checklist.md), so several in-flight changes can restate one requirement before any is applied. They are then
// applied in sequence and the last one survives outright: every scenario and every word of normative text the others contributed
// is deleted, at release, with no error and nothing in the output. That is issue #815, with a reproduction.
//
// openspec is a third-party tool, so its merge semantics are not ours to change. What is ours is the input: if every concurrent
// restatement is identical, "the last one wins" stops being lossy. Each author therefore has to state the requirement as it will
// read once ALL the in-flight changes have landed, which is the thing they can actually know and the thing a reviewer can check.
//
// Two alternatives were considered and rejected. Unioning the restatements here would make the gate agree with itself while the
// archive still discarded text, which is the failure #814's review caught. Forbidding concurrent restatements outright would block
// ordinary work, since two changes legitimately touching one requirement is normal in a batched-archive model.
func findRestatementConflicts(d *deltaSections) []restatementConflict {
	var out []restatementConflict
	for requirement, byChange := range d.modifiedRestatements {
		if len(byChange) < 2 {
			continue
		}
		grouped := make(map[string][]string, len(byChange))
		for change, r := range byChange {
			grouped[normaliseRestatement(r.lines)] = append(grouped[normaliseRestatement(r.lines)], change)
		}
		if len(grouped) < 2 {
			continue
		}
		conflict := restatementConflict{requirement: requirement}
		for text, changes := range grouped {
			sort.Strings(changes)
			conflict.versions = append(conflict.versions, restatementVersion{normalised: text, changes: changes})
		}
		// Sorted by the first change in each version, so the report is stable across runs rather than following map order.
		sort.Slice(conflict.versions, func(i, j int) bool {
			return conflict.versions[i].changes[0] < conflict.versions[j].changes[0]
		})
		out = append(out, conflict)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].requirement < out[j].requirement })
	return out
}

// normaliseRestatement reduces a restatement to the form two authors must match.
//
// Only whitespace-shaped differences are absorbed: trailing whitespace per line, runs of blank lines, and blank lines at either
// end. Nothing else, deliberately. These files are Prettier-formatted so cosmetic variance is already rare, and every further
// normalisation is a way for the gate to pass over texts that will not both survive the archive. Case is significant: a difference
// in case is a real difference in prose, and often a typo worth surfacing.
func normaliseRestatement(lines []string) string {
	out := make([]string, 0, len(lines))
	prevBlank := false
	for _, l := range lines {
		trimmed := strings.TrimRight(l, " \t")
		if trimmed == "" {
			if prevBlank || len(out) == 0 {
				continue
			}
			prevBlank = true
		} else {
			prevBlank = false
		}
		out = append(out, trimmed)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return strings.Join(out, "\n")
}

// printRestatementConflicts renders the conflicts with the first line on which each version diverges from the first.
//
// The first divergence rather than a whole diff, because the fix is not "apply this patch": it is to decide what the requirement
// should say once every in-flight change has landed and then write that same text into each of them. One concrete line is enough
// to see what the disagreement is about, and a full diff of four versions of a forty-line requirement buries that.
func printRestatementConflicts(conflicts []restatementConflict) {
	fmt.Printf("spectrace: %d requirement(s) restated DIFFERENTLY by concurrent in-flight changes:\n", len(conflicts))
	for _, c := range conflicts {
		fmt.Printf("  %s, restated %d ways:\n", c.requirement, len(c.versions))
		reference := c.versions[0]
		for i, v := range c.versions {
			fmt.Printf("    [%d] %s\n", i+1, strings.Join(v.changes, ", "))
			if i == 0 {
				continue
			}
			line, a, b := firstDivergence(reference.normalised, v.normalised)
			fmt.Printf("        first differs from [1] at line %d:\n", line)
			winA, winB := divergenceWindows(a, b)
			fmt.Printf("          [1] %s\n", winA)
			fmt.Printf("          [%d] %s\n", i+1, winB)
		}
	}
	fmt.Println("  Concurrent restatements MUST be identical. `openspec archive` replaces a requirement whole and applies changes")
	fmt.Println("  in sequence, so the last to archive silently discards the others' scenarios and normative text. Each change must")
	fmt.Println("  state the requirement as it will read once ALL of them have landed (issue #815).")
}

// firstDivergence returns the 1-based line number where a and b first differ, and both lines. A line absent from one side is
// reported as an empty string, which is what a shorter restatement looks like to a reader.
func firstDivergence(a, b string) (int, string, string) {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return i + 1, x, y
		}
	}
	// Unreachable for two texts the caller has already established differ, and cheaper than returning an error nobody can act on.
	return 0, "", ""
}

// divergenceWindows renders the two differing lines as a window around the point they first differ.
//
// Truncating from the start was the obvious approach and it was useless: Markdown here is not hard-wrapped, so a requirement's
// prose is one long line, and two versions of it typically agree for the first hundred characters and differ deep inside. The
// report then printed two identical-looking prefixes and told the reader nothing, which was the state this function replaced.
func divergenceWindows(a, b string) (string, string) {
	if a == "" {
		return "(no such line)", clampLine(b, 0)
	}
	if b == "" {
		return clampLine(a, 0), "(no such line)"
	}
	start := max(firstDifferingRune(a, b)-windowContext, 0)
	return clampLine(a, start), clampLine(b, start)
}

// windowContext is how much of each line is shown before the point of disagreement, and windowWidth the total shown. Constants
// rather than parameters because every caller wants the same window; a width argument that only ever receives one value is
// flexibility no caller asked for.
const (
	windowContext = 55
	windowWidth   = 2 * windowContext
)

// firstDifferingRune returns the byte offset at which a and b first differ. Byte offset rather than rune index because it is used
// only to position a window, and clampLine snaps to a rune boundary.
func firstDifferingRune(a, b string) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// clampLine returns at most width bytes of s from start, marked with ellipses where it has cut, and snapped to rune boundaries so
// a window landing mid-rune cannot print a replacement character.
func clampLine(s string, start int) string {
	for start > 0 && start < len(s) && !utf8.RuneStart(s[start]) {
		start--
	}
	if start >= len(s) {
		return "(line ends before this point)"
	}
	end := min(start+windowWidth, len(s))
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end++
	}
	out := s[start:end]
	if start > 0 {
		out = "..." + out
	}
	if end < len(s) {
		out += "..."
	}
	return out
}
