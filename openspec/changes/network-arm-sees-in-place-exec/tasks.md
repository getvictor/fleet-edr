# Tasks

- [x] Add `findShellOnExecChain` to the network arm, mirroring `evalExecArm2`
- [x] Gate the fall-through on "no usable shell" rather than "no shell", so the stale interactive shell does not mask the chain
- [x] Resolve the connecting process before the shell decision so the chain walk has a generation to start from
- [x] Table-driven tests: zsh in place, bash in place, the fork control, a chain shell outside the window, and a non-shell chain
- [x] Efficacy corpus scenario `T1059.004-shell-inplace-exec-network`, verified to fail without the change
- [x] Spec delta with the new requirement and its scenarios
