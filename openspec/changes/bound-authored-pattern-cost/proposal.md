# An authored pattern cannot make matching arbitrarily expensive

Part of #767.

## What changes when operators author rules

#787 bounded what an attacker-supplied VALUE can do against a rule's pattern, and stated its premise while doing it: "a value is attacker-supplied and a pattern is not". #767 retires that premise. Once an operator writes patterns, the pattern is untrusted input too, and the cost it imposes is paid once per value, per field, per rule, for every event. `glob.go` already recorded the residual this leaves and deferred it here by name.

## Catastrophic backtracking is not the threat, and building for it would be theatre

The issue names catastrophic backtracking as the denial of service. It does not exist here, for two independent reasons, both checked rather than assumed:

- Sigma's `|re` compiles through Go's `regexp`, which is RE2. `(a+)+$` compiles in 6us and matches a 4096-byte value in 39us. There is no backtracking to make catastrophic, and a test asserts that pattern is ACCEPTED so the absence of a defence is recorded rather than looking like an oversight.
- Wildcard patterns stopped backtracking in #787.

## What the measurements say

All against the real matcher, on a 4096-byte value unless stated. These are the final numbers; earlier drafts of this proposal carried two overlapping measurement sections that drifted apart, which is how it came to contradict itself.

**A segment with a star on either side is the driver, and its LENGTH is the unit.** Cost is linear in that length whether it is written as wildcards or as literal characters: 1024 `?` cost 4.10ms and 1024 literal characters cost 1.41ms, the same order. Four milliseconds per event per rule is a denial of service at batch scale.

**A regular expression's cost tracks its compiled PROGRAM, not its source.** `(abcd){1000}` is twelve source bytes and 6002 instructions; `a{1000}` is seven bytes and 1002. `(a|b)` repeated 500 times compiles to 2500 instructions and matches in 2.1ms. The corpus's longest expression is 32 bytes and 12 instructions.

**A field's values are additive.** 512 individually affordable values on one field cost 100ms per event, because every value is tried before a non-match is concluded.

**Every value costs something even when its shape costs nothing.** A plain literal comparison is about 4.7ns, so 65536 of them cost 309us per event: cheap each, unbounded in total.

**A portion anchored to an end of the pattern is bounded by the EVENT, not by the author.** An anchored prefix costs 527ns at 4096 atoms, 527ns at 65536 and 557ns at a million against a fixed 256-byte value, because the comparison abandons when the value runs out. A plain literal behaves identically: 27ns at 64 bytes, 22ns at a million. Charging the author for that length would refuse patterns that are free.

**Star count needs no limit, but consecutive stars did.** Alternating `*x` is flat from 119ns at one star to 129ns at 256. Actual adjacent stars grow linearly, 19ns at two and 40us at 8192, because each leaves an empty segment the search walks.

**Nested-repeat compile blowup needs no limit.** Go refuses `(a{1000}){100}` outright with "invalid repeat count", and a test records that this is Go's work rather than crediting these bounds for it.

## Approach

One cost model, in units of "atoms or instructions compared per candidate position", bounded twice:

- **Per pattern.** The length of any segment with a star on either side; for `|re`, the compiled program size, asked of `regexp/syntax`.
- **Per field, summed across its values,** plus a base cost every value pays for being compared at all. That base is what makes one budget bound both how complex a field's patterns are and how many there are, instead of needing a separate count.

Adjacent stars are collapsed at compile time rather than bounded, because `**` means what `*` means and removing a cost beats refusing a pattern.

Both bounds live in the one function every pattern passes through, so the loader CI runs and the loader a publish runs cannot disagree. Refusals name the field, the limit, and whether one pattern or the field's total reached it, following `maxConditionDepth`, whose own comment already anticipated operator-authored input.

## What review corrected

Four of the design's decisions were wrong before review, and the pattern in all four is the same: I bounded what a pattern LOOKS like instead of what matching it costs. Counting `?` ignored literals in the same position. Bounding regex source ignored that counted repetition expands. Bounding each value ignored that a field pays for all of them. Estimating literals at zero ignored that every value is still compared, a hole a test of mine had turned into a documented guarantee.

Two of the measurements above also came from review reading code my probes had measured around: consecutive stars, because my probe alternated `*x`, and literal segments, because my probe used one-character literals.

## What these bounds do not cover, and why that is PR 2's job

Two event-side factors, both measured as event-bounded rather than author-bounded. A field's authored values are each compared against every value the EVENT supplies, and some event fields carry as many values as a process had arguments. Separately, comparing one value costs in proportion to the event's string: a literal or an end-anchored portion stops as soon as the event's string ends.

So the per-field limit bounds what an author can impose, not the total an arbitrary event can provoke, and the spec says so rather than leaving it implied. Bounding the event side means timing an evaluation rather than estimating a pattern, which is the per-rule evaluation budget. That makes PR 2 the only thing that bounds this factor, not merely a backstop for a proxy.

## Rejected

**Bounding star count, and bounding nested repeats.** Measured above as costing nothing and as already refused by Go. Shipping them would look prudent and constrain nothing, which is worse than shipping neither: a limit nobody can trip trains a reader to treat the limits as decorative.

**Charging an author for an anchored or literal portion's length.** Measured above as free. It would refuse harmless patterns to bound a cost the event side already sets.

**Refusing `|re` entirely.** It would remove a Sigma feature the vendored corpus uses, to avoid a cost that bounding the compiled program already bounds.
