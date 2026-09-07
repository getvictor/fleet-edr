# Load rule packs at runtime instead of compiling them in

Part of #756 (Phase 5). Implements #766, which depends on #764 (closed).

## Goal

Detections ship outside a release: a pack is loaded from storage at startup and on change, swapped atomically, and a load failure keeps the previous good set.

## Why this is three changes, sequenced

The engine's active rule set is replaced IN PLACE today:

```go
e.rules = append(e.rules[:0], cs.ActiveRules()...)
e.reindex()
```

`reindex` then rebuilds three derived fields. The `dispatch` field's own comment states the contract that makes this safe: "read-only during Evaluate, which the processor may call concurrently". That holds only because `LoadActive` runs at bootstrap, before serving. Calling it at runtime, which is the entire point of #766, overwrites the backing array a concurrent `Evaluate` is iterating, and `Evaluate` reads the indices from `dispatch` and then indexes into `rules` separately, so a swap between those two reads mismatches them.

So runtime loading cannot be built on the current seam, and making the seam safe is worth landing on its own: it closes a latent hazard rather than fixing a live bug, and it is reviewable without any storage or reload machinery in the diff.

1. **This change**: the active rule set becomes one immutable value swapped atomically, and `Evaluate` takes one consistent view per call.
2. Pack storage, seeded from the embedded corpus so behaviour is identical, with whole-pack validation.
3. Reload, the refresh loop, and multi-replica convergence, following the `detectionconfig` snapshot pattern.

## This change

`ruleSet` bundles the rules with the three indices derived from them and is immutable once built. The engine holds it in an `atomic.Pointer`, builds a replacement off to the side, and swaps in one store. `Evaluate` loads the pointer once and uses that view throughout, so the indices it dispatches on and the rules it indexes are always from the same set.

Nothing observable changes yet: the same rules load from the same place at the same time. What changes is that replacing them concurrently is now defined rather than a race waiting for a caller.

The derived indices remain a per-replica cache in ADR-0010's sense, safe to lose and rebuilt from the rules on load.

## Rejected

**A mutex around the rule set.** Correct and it puts a lock on the hottest read path in the server, taken per batch per worker, to serialize against a write that happens at most every refresh interval. The atomic pointer costs one load.

**Rebuilding indices lazily on first Evaluate after a swap.** The existing comment already rejects this for the same reason it is rejected again: the processor calls Evaluate from concurrent workers, so a lazily-populated map is a data race.
