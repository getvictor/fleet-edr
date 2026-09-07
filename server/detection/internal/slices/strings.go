// Package slices holds the small slice operations more than one detection-internal package needs.
//
// It exists because two of them had grown their own copy of the same order-preserving string deduplication: the alert store used
// one to keep an alert's event ids a set, and the engine grew a second to merge a risk modifier's techniques into a finding's own.
// Two implementations of one set operation is the semantic duplication this codebase is most prone to, and the failure is quiet:
// both look right, and they only diverge once somebody changes one of them.
package slices

// Deduplicate returns ss with later repeats removed, preserving first-seen order.
//
// Order is preserved because both callers publish what they return. An alert's event ids are the evidence an analyst reads in the
// order the events happened, and a finding's techniques are rendered in the order the rule declares them, so a set that reordered
// would change what an operator sees for no reason.
func Deduplicate(ss []string) []string {
	if len(ss) <= 1 {
		return ss
	}
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
