# One exec-chain walk for both shell-chain rules

## Why

Issue #829. `suspicious_exec` and `shell_network_connect` both look for a shell generation on a PID's own exec chain, the shape where a shell replaced itself with its payload rather than forking it. Issue #776 split the rules and deliberately kept the ancestor walk shared, because two copies of a graph walk drift; #713 is what that drift already cost, when the exec-chain walk existed on one arm and not the other for months.

The walk was shared, but this one step was not: the temp arm had its own copy inside `evalExecArm2`, and the copies had diverged in two ways that both changed which chains get reported.

**Oldest-first.** The temp arm took the first suitable shell from the oldest end of the chain and gave up if it failed the window. For `zsh -c 'bash -c "/tmp/payload"'`, where both shells exec in place at one PID, the oldest generation is exactly the one most likely to be stale, so a chain whose newer shell was well inside the window reported nothing.

**Firing on unresolved ancestry.** The temp arm fired on a shell whose claimed parent was absent from the graph, producing an alert whose parent reads `(unknown)`. Parent exclusions match on the parent's path, so an operator who had correctly configured one received that alert anyway, every time, with no way to suppress it short of disabling the rule. The chain is now dropped instead. Stated plainly, because an earlier draft of this proposal claimed the deferral was recoverable and it is not: ancestor and parent-chain lookups keep skip semantics by design, so no later parent record brings the detection back. What justifies dropping it is that an alert nobody can silence tends to get the whole rule disabled, which costs every detection the rule makes rather than this one.

A third divergence was claimed when the issue was filed and does not exist. Neither arm walks past a candidate that fails the mode and window gate; they differ only in where that check sits, which has no observable effect. Recorded on the issue rather than quietly dropped.

## What changes

`evalExecArm2` calls `findShellOnExecChain`, the walk the connect arm already used. The temp arm therefore takes the newest suitable generation and reports nothing on incomplete ancestry.

Both are behaviour changes to `suspicious_exec`, in opposite directions, and each ships with a test that fails against the previous behaviour:

- A chain whose newest shell is in-window and whose oldest is not now reports; before, it did not.
- A chain whose shell has no resolvable parent now reports nothing; before, it raised an unsuppressable alert.

## Impact

The first change can only add detections. The second removes one class permanently: a chain whose shell's parent is genuinely missing from the graph. That is the trade the connect arm already made, and it is made here for the same reason. It is a real cost, not a deferral.

No configuration, wire format, or persisted data changes. `shell_network_connect` is unaffected; it was already the reference behaviour.
