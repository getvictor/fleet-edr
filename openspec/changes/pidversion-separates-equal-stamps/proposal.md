# Separate equal fork stamps by kernel generation

## Why

Two generations of one PID can carry the same `fork_time_ns`: `CloseStaleProcess` closes only rows stamped strictly earlier, and the extension stamps at handler time, so exact collisions are not prevented upstream either. When the parent-path lookup could not separate them it fell through to row id, which is ingest order, and ingest order being unreliable is the entire premise of issue #714: a later generation's fork is routinely materialized first. That was an arbitrary answer, not a resolution (issue #724, from the #723 review).

Measured on the dev database (755,465 process rows): 225 equal-stamp groups, of which only **16** have differing pidversions and are genuine collisions. The other 199 share one pidversion, meaning they are duplicate rows for a single generation, which is the issue #717 defect fixed in #719 rather than something an ordering can repair. `pidversion` is populated on 752,276 rows (99.6%), so the discriminator is available in practice.

## What changes

`pidversion`, the kernel's own generation counter, breaks the tie, in both implementations of the lookup: the store's `ORDER BY` and the batch overlay's comparator. A row carrying kernel evidence outranks one carrying none, since the column is nullable and 3,189 rows have no value.

## Where it sorts, which is the whole difficulty

`pidversion` increments on **exec**, not only on fork (measured; it is why issue #715 persists the exec's own pidversion on a re-exec row), so a re-exec chain carries **ascending** pidversions. Ranked before the image ordering it would pick the newest image in a chain regardless of the fork instant, undoing issue #723. It therefore sorts after the image ordering has resolved things within a chain, and decides only where that ordering cannot: rows sharing a stamp with no applied image to separate them.

## Deviation from the issue's suggested shape, stated plainly

Issue #724 proposed inverting the second assertion of `TestInheritedPathWhenTwoGenerationsShareAForkTimestamp` so the newer generation wins. **That is not achievable without undoing #723**, for the reason above: in that fixture the two generations have different exec times, so the image ordering separates them and pidversion never legitimately gets a vote. The assertion is kept and its comment now explains why, rather than being inverted or deleted.

That fixture is also physically contradictory, which is what makes it a poor case for pidversion to arbitrate: if the pidversion-9 generation really superseded the pidversion-7 one, the 7 generation cannot then exec after 9 already had. The new coverage uses the collision that actually occurs instead: two fork-only rows sharing a stamp.

## Why a new requirement

`Fork creates a process record` is the closest existing home and already carries an in-flight MODIFIED delta from `fork-inherits-live-parent-generation` (the #723 fix). Two in-flight deltas on one requirement is a known archive hazard here, where the second to archive silently drops the first's scenarios. This is also a property of the parent-path lookup rather than of fork handling.
