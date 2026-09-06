# Tasks

- [x] `observability` is registered with the standalone migrator, which was applying seven of eight contexts and exiting 0.
- [x] The registration is checked from the TREE, not against a hardcoded list. A hardcoded expectation is the same defect one level up: a context added without an entry would be missing from the expectation too, and the test would agree with the bug.
- [x] Both directions are checked. A registered context whose migrations were renamed or removed applies nothing and reports success, so the CLI would exit 0 having done less than its name says.
- [x] The test fixture is covered by the same guard, because it is the list that was also missed when `rulecontent` was added. A context missing there yields a database without the tables the fixture promises, and the symptom is a test hand-applying a schema rather than anything failing.
- [x] The fixture's step list moved into a function so it can be enumerated. It was a literal inside the applier, which is exactly why nothing could check it.
- [x] Both guards were confirmed to catch the real defect by removing `observability` from each list in turn.
- [x] The canonical requirement's hand-written list of contexts had gone stale by three (`rulecontent`, `observability`, `visibility`). Replaced with the property rather than an enumeration, so it cannot drift again.
- [x] Verified end to end: the CLI against a fresh database creates every context's tracking table, `observability_goose_db_version` included, and `trace_sampler_settings` exists afterwards.
