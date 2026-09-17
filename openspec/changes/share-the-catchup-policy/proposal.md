# One catch-up policy for both pushed states

Issue #1071. Two contexts push a desired state to hosts as a command and then have to notice the hosts that did not get it: the watched-path set (#998) and host containment (#1068). Each carried its own copy of the same policy, deciding from a host's latest command whether the state is owed again, and each ran its own five-minute loop. A change to delivery or retry semantics made in one could silently miss the other, and the two copies had already drifted in one respect: one treated a failure with no completion time as retryable, the other did not.

## What changes

- **The decision moves to `server/catchup`.** Given a host's latest command of the type, whether that command carries the state the host should have now, the host's enrollment time and a clock, one function decides. The five-minute default and the six-hour failed-command window move with it, since they are the policy rather than either context's.
- **The sweep loop moves too.** One loop, taking the context's own sweep, its subject for the failure log, and its interval.
- **Each context keeps what is its own**: where the state comes from, what its command payload means, and how it queues one. A context maps its command onto the shared shape and asks.
- **A status neither context knows is left alone rather than resent.** That was already both implementations' behavior; it is now stated, and each context's mapping onto the shared vocabulary is written out and covered, so a rename on either side fails a test instead of silently stopping the catch-up for every host.

## Out of scope

- The application-control fan-out, which pushes a policy to hosts but has no per-host catch-up of this shape.
