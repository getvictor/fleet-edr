# Tasks

- [x] Add the opt-in `AlgorithmNamer` interface so a rule can name the evaluator that decides it.
- [x] Declare an algorithm on all ten detections, named from each rule's actual decision procedure.
- [x] Carry the algorithm on `RuleMetadata` for the serialiser. Deliberately NOT surfaced on `GET /api/rules`: nothing
      consumes it there, and it belongs with the UI change that would display it.
- [x] Add the serialiser rendering one detection as a rule file.
- [x] Expose the pack renderer through `rules/bootstrap`, the seam tooling already uses.
- [x] Add `tools/gen-rule-pack` and the `docs:rule-pack` task.
- [x] Serve `GET /api/rules/{id}/export`.
- [x] Drift-check the committed pack against a fresh render, on content and not just the file list, from a package CI
      actually runs (`./server/...`, not `./tools/...`).
- [x] Assert every detection names a registered algorithm, and that no registered name is unclaimed.
- [x] Prune rule files for rules that are no longer registered, so a deleted rule does not leave the drift check demanding a
      regeneration that cannot fix it.
- [x] Refuse to render a rule missing its title, severity, or algorithm.
- [x] Document the endpoint in the OpenAPI spec and its embedded copy.
