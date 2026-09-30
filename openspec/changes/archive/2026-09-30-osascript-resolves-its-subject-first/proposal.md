# osascript_network_exec waits for the temp exec it judges

## Why

`osascript_network_exec` walked the process graph upward from the temp exec with a plain lookup, and ended on a miss (issue #1170). The temp exec's own record is written by the graph builder, which a concurrently processed batch may not have committed yet, so a young miss dropped the chain for good instead of retrying it, and a record that never arrived was dropped without being counted. The rule's grace-aware resolution step, which would have done both, came after the walk and was unreachable.

## What changes

The rule resolves the temp exec through the grace-aware path before walking to an osascript ancestor. Inside the grace a missing record raises the retryable error, so the batch is re-evaluated. Past it, the rule counts the abandon as the other process-resolving rules do (issue #1158), and declares that it counts. An event with no pid is skipped. The walk's first step was the same lookup, so the reorder adds no graph read.

## Not changed

Ancestors are still looked up plainly, since a parent can predate the capture and never materialize. The rule's decision on a chain whose records are all present is unchanged.
