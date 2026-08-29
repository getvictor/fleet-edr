# Tasks

- [x] Add the opt-in `AlgorithmNamer` interface so a rule can name the evaluator that decides it.
- [x] Declare an algorithm on all ten detections, named from each rule's actual decision procedure.
- [x] Surface the algorithm on `RuleMetadata` and `GET /api/rules`.
- [x] Add the serialiser rendering one detection as a rule file.
- [x] Expose the pack renderer through `rules/bootstrap`, the seam tooling already uses.
- [x] Add `tools/gen-rule-pack` and the `docs:rule-pack` task.
- [x] Serve `GET /api/rules/{id}/export`.
- [x] Drift-check the committed pack against a fresh render, on content and not just the file list.
- [x] Assert every detection names a registered algorithm, and that no registered name is unclaimed.
