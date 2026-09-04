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

**What `|re` does cost is program size times input.** `(a|b)` repeated 500 times compiles to a 2500-instruction program and matches in 2.1ms; `a{1000}` matches in 2.19ms. The lever is source length, which bounds the program.

## Approach

Three bounds, at the one place every pattern passes through on its way to being matched, so validation and load cannot disagree about what is acceptable:

- The number of `?` in a segment that is not anchored to either end of the pattern.
- The length of a `|re` pattern's source.
- The number of values a single field test may carry.

Each is a named constant with its reasoning beside it and an `ErrUnsupported` refusal naming the field and the limit, following `maxConditionDepth`, which is the same shape of bound already in this package and whose comment already anticipates operator-authored input.

## Not in this change

A per-rule evaluation budget. Every bound here is a proxy for cost, and a proxy cannot anticipate the combination an author actually writes; a budget measures the thing itself and is the backstop these bounds sit in front of. It is the next PR, and the measurements argue it matters more than this one.

## Rejected

**Bounding star count, and bounding nested repeats.** Both measured above as costing nothing or being handled already. Shipping them would look prudent and constrain nothing, which is worse than shipping neither: a limit nobody can trip trains a reader to assume the limits are decorative.

**Refusing `|re` entirely.** It would remove a Sigma feature the vendored corpus uses, to avoid a cost that bounding the source length already bounds.
