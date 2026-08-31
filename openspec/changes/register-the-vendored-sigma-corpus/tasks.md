# Tasks

- [x] Move the corpus out of `testdata` and embed it, so the tests read the same bytes production loads.
- [x] Register every imported rule and declare `monitor` as its default mode.
- [x] Mark coverage that comes only from non-alerting rules apart, in the ATT&CK export and the generated reference.
- [x] Skip vendored rules in the exported pack; serve their vendored bytes from the per-rule export endpoint.
- [x] Scope the authoring-standard guards to authored rules and pin every vendored exception by name.
- [x] Report the corpus outcome at start-up, including each refusal and its reason.
- [ ] Per-rule smoke fixtures: tracked under #773.
