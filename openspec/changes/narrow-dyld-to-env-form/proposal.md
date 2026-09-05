# Narrow the dylib-injection rule to the form it can actually detect

## Why

`dyld_insert` advertised two shapes: an `env VAR=x target` invocation, and a shell assignment `VAR=x /bin/true`. The second cannot fire, and never could.

The sensor records a process's ARGUMENTS. A shell applies its assignments without putting them there, so `DYLD_INSERT_LIBRARIES=x /bin/true` reaches the server as `argv == ["/bin/true"]` with the assignment absent from the event entirely. Issue #791 measured it: across 670,185 real exec events from a dev host, `argv[0]` was an assignment **zero** times, against 1,747 events carrying an assignment somewhere later in argv. The zero is structural rather than a small sample.

Advertising coverage that cannot fire is worse than a documented gap, because nobody goes looking for it. An operator reading the rule's description had no way to learn that half of what it claimed was unreachable.

## What changes

The computed `EnvAssignments` field stops reporting `argv[0]` for a non-`env` binary, and the rule's documentation says it detects the `env` form only. Nothing an agent can send changes behaviour, which is what the measurement establishes.

This is a NARROWING of what the rule claims, not of what it finds.

## Not doing

Capturing the exec environment, which is what would make the shell form detectable. That is an extension change plus an event-wire change requiring live macOS VM QA, tracked as #862. Note it would add a separate field rather than put assignments into argv, so the branch removed here stays unreachable even after it lands.

## Risks

Removing a branch that no production input reaches carries no detection risk by construction. The visible cost is in the test suite, where several fixtures used the shell form as a convenient way to exercise the rule and now use the `env` form. That churn is the honest signal that the shape was easy to write and impossible to observe.

The equivalence property against the frozen Go matcher gains a third documented divergence, in the removing direction, asserted by shape like the other two.
