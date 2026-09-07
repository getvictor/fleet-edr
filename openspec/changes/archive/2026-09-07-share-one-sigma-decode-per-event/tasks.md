# Tasks

- [x] Add `BatchScope` and the optional `ScopedRule` interface to `server/rules/api`.
- [x] Create one scope per `Evaluate` call in the engine and route scoped rules through it.
- [x] Add `sigmabind.Event.WithResolver`, so copies share the decode and the lookup but not the error.
- [x] Carry the subject pid on the adapter's single decode, replacing each rule's second unmarshal.
- [x] Add the per-batch memo keyed by event id, with memoized image and subject lookups.
- [x] Move the five registered Sigma-backed rules and the imported rule onto it.
- [x] Delete the per-rule helpers and payload structs the shared path replaces.
- [x] Benchmark the shared and unshared cases; pin the decode count, the lookup count, and the error isolation.
