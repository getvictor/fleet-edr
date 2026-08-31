# Share one Sigma decode per event, not one per rule

## Why

The engine hands every rule the raw event batch and calls each rule's `Evaluate` separately, so a rule that reads Sigma fields has to build its own adapter. Each Sigma-backed rule therefore decoded every event it looked at, and decoded it a second time to read the subject pid back out. The rules that read `ParentImage` each issued their own pair of process-graph reads for the same event, which costs far more than the decode.

With five Sigma-backed rules registered this is measurable and tolerable. Issue #764 registers the imported corpus, where 66 rules key on `exec` and eleven read `ParentImage`, and the arithmetic stops being tolerable: the same event is decoded 132 times and the same parent looked up eleven times.

## What changes

The engine creates one scratch space per batch and offers it to any rule that asks. It stays opaque to the engine: what a rule derives belongs to the rules context, which owns both the store and the read. The obvious alternative, an optional interface handing rules a pre-built adapter, cannot be written, because detection cannot import the rules context's internal packages and the package defining the adapter imports `rules/api`, so declaring the type there closes an import cycle.

Every Sigma-backed rule now reads its event through the shared adaptation: one decode and one graph lookup per event per batch, however many rules look at it. Each rule still gets its own resolver-error slot, because a resolver error discards that rule's findings for the whole batch and a rule that never read the field must not inherit another rule's failed lookup.

## Impact

No change to which findings are produced. Measured on one exec event across ten rules: 8042ns/19022B/250 allocs becomes 1430ns/4721B/43 allocs.
