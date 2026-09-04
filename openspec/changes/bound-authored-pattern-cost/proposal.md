# An authored pattern cannot make matching arbitrarily expensive

Part of #767.

## What changes when operators author rules

#787 bounded what an attacker-supplied VALUE can do against a rule's pattern, and said so in terms that name the premise: "a value is attacker-supplied and a pattern is not". #767 retires that premise. Once an operator writes patterns, the pattern is untrusted input too, and `glob.go` already says where the residual lives and defers it here by name: "a middle segment carrying `?` cannot use the byte paths at all, so it walks candidate offsets and stays O(value x segment)".

## Catastrophic backtracking is not the threat, and building for it would be theatre

The issue names catastrophic backtracking as the denial of service. It does not exist here, for two independent reasons, and both were checked rather than assumed:

- Sigma's `|re` compiles through Go's `regexp`, which is RE2. `(a+)+$` compiles in 6us and matches a 4096-byte value in 39us. There is no backtracking to make catastrophic.
- Wildcard patterns stopped backtracking in #787.

So this change bounds the costs that are real, measured against the actual matcher on a 4096-byte value.

## What was measured, and what it rules out

**`?` in a middle segment is the one driver.** Per-match cost is linear in the count: 27.6us at one, 108.6us at 16, 1.35ms at 256, 4.10ms at 1024. Four milliseconds per event per rule is a denial of service at batch scale, and this is the residual #787 deferred.

**Star count needs no limit.** Flat from 119ns at one star to 129ns at 256: the runs between stars are short literals and the `minBytes` prune abandons a search that cannot fit. A star limit was in the first draft of this proposal and would have constrained nothing.

**Nested-repeat compile blowup needs no limit.** Go refuses `(a{1000}){100}` and `((a{100}){100}){100}` outright with "invalid repeat count".

**What `|re` does cost is program size times input.** `(a|b)` repeated 500 times compiles to a 2500-instruction program and matches in 2.1ms; `a{1000}` matches in 2.19ms. The lever is therefore the compiled program, and it is asked of `regexp/syntax` rather than inferred from the source: `(abcd){1000}` is twelve source bytes and 6002 instructions, so a source-length bound would have let the most expensive shape through. An earlier draft of this paragraph said source length was the lever, which review caught.

## Approach

One cost model rather than three independent limits, which is a correction: the first version bounded a `?` count, a regex source length and a value count separately, and review showed each was the wrong unit or the wrong scope.

Cost is estimated in units of "atoms or instructions compared per candidate position", and bounded twice:

- **Per pattern.** For a wildcard pattern, the LENGTH of any segment with a star on either side, because that segment is searched for at every candidate offset. For a regular expression, the size of the program Go compiles it to.
- **Per field, summed across its values.** A field's values are tried until one matches, so an event matching none pays for all of them.

Adjacent stars are collapsed at compile time instead of bounded, because `**` means what `*` means and refusing it would serve nobody.

Both bounds live in the one function every pattern passes through, so the loader CI runs and the loader a publish runs cannot disagree. Refusals name the field, the limit, and whether one pattern or the field's total reached it, following `maxConditionDepth`, whose own comment already anticipated operator-authored input.

## Three corrections review forced, each with the measurement

**Counting `?` was the wrong unit.** A middle segment of 1024 literal characters costs 1.41ms against a 4096-byte value, the same order as 1024 `?` at 4.10ms. The first bound counted only the wildcards, on the true-but-irrelevant reasoning that a literal segment can use the byte-comparison paths. It can, and it is still linear in the segment. The unit is now the segment's length.

**Bounding regex SOURCE length bounded nothing.** `(abcd){1000}` is 12 source bytes and compiles to 6002 instructions, because counted repetition expands at compile time; `a{1000}` is 7 bytes and 1002 instructions. `regexp/syntax` compiles the same program the matcher runs, so the bound now asks it instead of guessing from the source. For scale, the vendored corpus's longest expression is 32 bytes and 12 instructions.

**Per-value limits compose.** 512 individually legal values on one field measured at 100ms per event, because every value is tried before a non-match is concluded. The per-field sum is what closes that, and it is why a field of 4096 plain literals is still accepted: they cost nothing each, so the sum stays small.

**Consecutive stars were an unbounded cost I had measured around.** My first measurement used `*x` repeated, which keeps every segment non-empty and reported flat cost. Actual consecutive stars grow linearly: 19ns at two, 40us at 8192. Collapsing them removes the growth without refusing anything.

## What these bounds do not cover, and why that is PR 2's job

A field test compares each authored value against every value the EVENT supplies, and some event fields are argv-derived slices with no cap of their own. So the cost of a field is authored-cost times event-cardinality, and this change bounds only the first factor. Review raised it and it is worth stating rather than leaving implied: the per-field limit bounds what an author can impose, not the total an arbitrary event can provoke.

That is deliberate. The event side is agent-supplied rather than authored, it was uncapped before this change and is unchanged by it, and bounding it well means measuring the thing itself rather than a proxy, which is exactly what the per-rule evaluation budget does. Capping the authored side is what #767 asks for; capping the product is what the budget is for.

## Not in this change

A per-rule evaluation budget. Every bound here is a proxy for cost, and a proxy cannot anticipate the combination an author actually writes; a budget measures the thing itself and is the backstop these bounds sit in front of. It is the next PR, and the measurements argue it matters more than this one.

## Rejected

**Bounding star count, and bounding nested repeats.** Both measured above as costing nothing or being handled already. Shipping them would look prudent and constrain nothing, which is worse than shipping neither: a limit nobody can trip trains a reader to assume the limits are decorative.

**Refusing `|re` entirely.** It would remove a Sigma feature the vendored corpus uses, to avoid a cost that bounding the source length already bounds.
