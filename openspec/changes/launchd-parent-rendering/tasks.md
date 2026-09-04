# Tasks

- [x] A shell whose PPID is 1 has its parent named `/sbin/launchd` rather than reported as unnameable, in both rules that share the walk.
- [x] The parent-path-glob exclusion is consulted for that case, which previously returned false before reaching any resolver because every match type needed a process row.
- [x] A claimed PPID of 0 stays unnameable, because pid 0 is the kernel and naming it launchd would be false as well as over-suppressing.
- [x] Signature exclusions are unchanged: with no process row there is no signing identity to match, which the existing signature requirement already states.
- [x] Both rules' limitations state the breadth an operator is buying, since an exclusion for pid 1 covers every launchd-started chain including real persistence execution.
- [ ] Fixtures for a launchd-parented chain on both rules, covering the naming and the suppression.
- [ ] Mutation-tested: the pid 1 rendering removed, the exclusion consult removed, and the pid 0 case folded into pid 1.
