# Tasks

- [x] Replace `evalExecArm2`'s own chain loop with a call to the shared `findShellOnExecChain`.
- [x] Test that a chain whose newest shell is in-window and oldest is not now reports, naming the newer generation.
- [x] Test that a chain whose shell has no resolvable parent defers rather than raising an unsuppressable alert.
- [x] Verify each test fails against the behaviour it replaces, by reverting that behaviour in the shared walk.
- [x] Correct the third divergence claimed on #829, which does not exist.
- [x] Confirm on a running server that the temp arm still reports the ordinary re-exec chain.
