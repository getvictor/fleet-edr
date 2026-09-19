# Deliver the reachable-address set to contained hosts

Issue #1059, second of three. The set exists and is edited (#1106); nothing reaches a host yet. This delivers it and enforces it.

## What changes

- **The set rides the containment command.** A host is current only when its latest command carries both its containment state and the set in force, so a change to the set alone makes every contained host stale and the catch-up that already re-queues a missed containment re-queues it. That is the issue's "picks up a change without being released and contained again", and it needs no second converger and no command type of its own.
- **The agent passes it through.** No validation: the server validated the set before storing it, and an entry the agent judged for itself would be an entry the server and the host disagree about.
- **The extension enforces it** as part of the lifeline it already builds, one filter rule per entry, outbound only, both transports for an entry naming none.

## The trap this design walks into, and the fix

Changing the set does not change any host's containment version or epoch. So the command carrying the new set arrives at the extension at the SAME order as the one it already holds, and the extension accepts an update only when it is newer or refreshes the lifeline. Without teaching it that the set is part of the lifeline, the extension would discard the update while the command still completed: the operator would see success and nothing would have changed. That is the worst failure available here, because every layer reports it as working.

The agent has the same shape of trap. A lifeline refresh re-sends the whole document, so a refresh built without the allowances reaches the extension as the same containment with its allowances withdrawn, which the extension takes as a lifeline that moved and enforces. The manager therefore holds the set with the state, including when it adopts a state from a status, which carries the containment only.

## Out of scope

The console surface, which is the third change. Per-host sets and application-based exceptions remain out of scope for the issue.

## Delivery latency, stated rather than left to be discovered

A set change reaches already-contained hosts within one catch-up interval (five minutes by default) rather than immediately. A host contained after the change carries it at once, on its own command. Waking the catch-up on an edit would buy a few minutes at the cost of coupling the reachable service to the containment converger, which is not worth it for a set that changes during incident response, not continuously.
