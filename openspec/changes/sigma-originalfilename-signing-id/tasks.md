# Tasks

- [x] Decode the code-signing identifier from the exec payload
- [x] Supply it as `OriginalFileName` in the process_creation taxonomy
- [x] Absent, not empty, when the process is unsigned
- [x] Update the pinned import and refusal counts: 66 to 67 imported, 3 to 2 refused
- [x] Test the unsigned case explicitly, since that is the one that fails open
- [x] Mutation-check the absent-vs-empty distinction
- [x] Property-based round trip over the new wire member, covering the key omitted, an explicit null, an empty object, an empty identifier, and an arbitrary one
- [x] Regenerate `docs/detection-rules.md`: the rule leaves the "not run" table and gains its own entry, with the upstream author credited
