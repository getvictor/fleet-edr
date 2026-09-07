# Tasks

## 1. Scope the earliest-image key to the group it was written for

- [x] 1.1 Guard the key with the same predicate the applied/not-applied split uses, so it is null for every applied record and the group ties into the kernel generation.
- [x] 1.2 Apply it to both queries that carry the ordering. `GetProcessByPIDVersion` does NOT: the issue named three functions, and only two have the clause.
- [x] 1.3 Answer the open question the comment on `GetProcessByPID` filed, rather than leaving it pointing at a closed issue.

## 2. Tests

- [x] 2.1 Seed the tie and assert through the helper that drives BOTH implementations, since the disagreement between them is the point.
- [x] 2.2 Mutation-test each side ALONE: reverting the query fails on the store arm, and making the overlay prefer a never-exec'd record fails on the overlay arm.
- [x] 2.3 Seed the records directly. The shape needs ingest ordering the builder does not normally produce, because the first exec after a fork updates that row in place.
