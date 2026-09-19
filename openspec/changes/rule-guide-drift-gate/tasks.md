# Tasks

- [x] Confirm the rule pack half already has a working gate, by changing a rule's `Doc()` and watching `TestPackHasNoDrift` fail.
- [x] Add a drift guard comparing `docs/detection-rules.md` against what `render` produces, failing with the file, the command and the first differing line.
- [x] Test the differ on documents of differing lengths in both directions.
- [x] Verify the guard fails on an unregenerated `Doc()` change and passes on a current tree.
- [x] Correct the stale claim in the two existing drift guards that CI does not run `./tools/...`.
