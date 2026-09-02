# Tasks

- [x] Replace `evalExecArm2`'s own chain loop with a call to the shared `findShellOnExecChain`.
- [x] Test that a chain whose newest shell is in-window and oldest is not now reports, naming the newer generation.
- [x] Test that a chain whose shell has no resolvable parent reports nothing rather than raising an unsuppressable alert.
- [x] Verify each test fails against the behaviour it replaces, by reverting that behaviour in the shared walk.
- [x] Correct the third divergence claimed on #829, which does not exist.
- [x] Confirm on a running server that the temp arm still reports the ordinary re-exec chain.
- [x] State the drop accurately everywhere: it is a skip, not a retry, per the canonical ancestor-lookup contract.
- [x] Report the decline from the walk, record it per rule, and put the per-rule count on the engine's existing span.
- [x] Adopt ScopedRule on both rules, with Evaluate delegating, and pin that both entry points behave identically.

