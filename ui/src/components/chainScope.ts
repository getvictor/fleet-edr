// Every sentence the host timeline puts in front of an analyst about how far its alert-chain scope reaches, and the closed set of
// reasons it could not reach at all. Split out of HostTimeline.tsx because a component module that also exports constants breaks
// fast refresh, and because tests assert on this list rather than on the markup rendering it.

// ChainScopeGap says why the timeline could not reproduce the graph's alert-chain focus at all.
//
// Only one of these names a cause from the chain itself, deliberately. "no-generations" is provable: the chain resolved and not one
// of its processes carried the identifier the scope matches on. "tree-unavailable" is equally provable, from the other direction:
// the read failed, so there is no tree and no chain to look for. "chain-unresolved" is everything left, and it stays vague on
// purpose.
// Four review rounds went into trying to say WHY the chain came back empty, and each precondition turned out to admit a case it
// did not cover: a tree still loading, a failed read, a host with nothing in the window, and finally a TRUNCATED response,
// where the process is in the window but past the row limit BuildTree applies. A message that names the wrong cause sends the
// operator to fix the wrong thing, so this one reports what is certain (the chain could not be located in what was loaded) and
// leaves the cause to the operator, who can see the truncation notice and the time window for themselves.
//
// "tree-unavailable" was carved out of that vagueness because it is the one cause the page already knows for certain. Before it
// existed a failed read produced no note at all, so the graph showed its error while the timeline listed the whole host looking
// like a successful unscoped view: two surfaces of one page disagreeing about whether the read worked.
export type ChainScopeGap = "no-generations" | "chain-unresolved" | "tree-unavailable";

// scopeGapMessage is exhaustive over ChainScopeGap by construction: a Record, not a chain of ternaries, so adding a gap without a
// sentence fails the type check rather than silently falling through to whichever branch happened to be last.
//
// None of these claims more than the page knows. "tree-unavailable" in particular does NOT say the chain is absent, because a read
// that failed produced no tree for anything to be absent from.
export const scopeGapMessages: Record<ChainScopeGap, string> = {
  "no-generations": "Showing the whole host: this alert's processes carry no generation data, so the timeline cannot narrow to the chain.",
  "chain-unresolved": "Showing the whole host: this alert's process is not in the loaded process tree, so there is no chain to narrow to.",
  "tree-unavailable": "Showing the whole host: the process tree could not be loaded, so the timeline cannot narrow to this alert's chain.",
};

// partialScopeMessage is the fourth sentence rendered in the degraded style, and the only one not keyed by a ChainScopeGap: it
// describes a scope that IS in force but reaches only part of the chain, rather than one that could not be applied at all.
export const partialScopeMessage =
  "Scoped to part of the alert chain: some of its processes carry no generation data, so their events are not listed.";

// degradedScopeMessages is every sentence the timeline renders in the degraded style. Exported so a test asserting the timeline said
// nothing about its scope can enumerate them instead of naming a CSS class, which passes when the class is renamed, or a couple of
// literals, which passes when a sentence is added. A sentence added here is covered by those tests without editing them.
export const degradedScopeMessages: readonly string[] = [...Object.values(scopeGapMessages), partialScopeMessage];

export function scopeGapMessage(gap: ChainScopeGap): string {
  // gap is a three-value union rather than caller-supplied input, so the key cannot be anything the Record does not declare: the
  // type checker rejects a fourth value before this line can run.
  // eslint-disable-next-line security/detect-object-injection -- closed union key, not external input
  return scopeGapMessages[gap];
}
