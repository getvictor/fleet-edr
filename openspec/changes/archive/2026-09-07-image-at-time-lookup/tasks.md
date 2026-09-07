# Tasks

- [x] Bracket and order the by-pid lookup on the image's own start instant rather than the process's fork.
- [x] A reproducer that produces the ordering the existing tests never did: a parent that forks a child and then re-executes before evaluation.
- [x] A pure-fork generation stays reachable, which is what the COALESCE fallback is for.
- [x] Mutation-tested: the original bracket, a half-fix that orders but does not bracket, and dropping the fallback.
