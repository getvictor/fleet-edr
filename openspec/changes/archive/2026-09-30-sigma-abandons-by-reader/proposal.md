# Charge a Sigma rule's abandon to the rule that read the process

## Why

The abandon count added for #1158 covered the hand-written rules and left the Sigma-backed ones reported as not measured (issue #1169). They share one memoized subject lookup per event, so counting at the lookup would charge every rule that looked at the event, including rules whose decision never touched the process.

Building it turned up a second defect. On an exec, the parent's image is found from the subject's row, and it was looked up separately from the subject, without the grace. A young subject therefore produced an absent `ParentImage`, which a detection reads as "no matching parent", and the event was dropped for good rather than retried.

## What changes

- The parent's image is read through the event's shared subject lookup. A young subject is now a retry, and the separate lookup is gone.
- A Sigma rule records an abandon when its subject never materialized and either its detection matched (the finding had no process to name) or its detection read the graph-resolved field (`Image` on a file event, `ParentImage` on an exec) and did not match. A rule that decided on the event's own fields is not charged, and a present subject whose parent is missing is not an abandon.
- Every Sigma-backed rule declares that it counts, so its Cost figure is measured rather than absent.

## Not changed

What each detection matches, and the parent lookup's time bracket, are unchanged.
