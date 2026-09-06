# Tasks

- [x] `observability` is registered with the standalone migrator, which was applying seven of eight contexts and exiting 0.
- [x] The registration is checked from the TREE, not against a hardcoded list. A hardcoded expectation is the same defect one level up: a context added without an entry would be missing from the expectation too, and the test would agree with the bug.
- [x] Both directions are checked. A registered context whose migrations were renamed or removed applies nothing and reports success, so the CLI would exit 0 having done less than its name says.
- [x] The test fixture is covered by the same guard, because it is the list that was also missed when `rulecontent` was added. A context missing there yields a database without the tables the fixture promises, and the symptom is a test hand-applying a schema rather than anything failing.
- [x] The fixture's step list moved into a function so it can be enumerated. It was a literal inside the applier, which is exactly why nothing could check it.
- [x] Both guards were confirmed to catch the real defect by removing `observability` from each list in turn.
- [x] The canonical requirement's hand-written list of contexts had gone stale by three (`rulecontent`, `observability`, `visibility`). Replaced with the property rather than an enumeration, so it cannot drift again.
- [x] Verified end to end: the CLI against a fresh database creates every context's tracking table, `observability_goose_db_version` included, and `trace_sampler_settings` exists afterwards.
- [x] The tree scan has ONE definition, shared by both guards. Two copies of the rule that decides which contexts count can disagree, and then the two gates would police different sets: the defect they exist to catch, one level up. Review caught it, in a change about exactly that class.
- [x] The scan and the requirement are scoped to the RELATIONAL corpus. One context keeps a separate corpus for the columnar event store which the server applies at boot, because the tool takes a relational connection only; a guard counting it would demand the tool apply something it cannot reach. The release note said "every part of the schema" and now says what it means.
- [x] The registration tests compare NAMES, so pairing a name with the wrong applier, or one that does nothing, would satisfy them. Review pointed that out. The smoke test now asserts the table only observability's migrations create, and a no-op applier paired with that name fails it.

