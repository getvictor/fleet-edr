# Tasks

- [x] Add `getWatchedPaths` and `replaceWatchedPaths` to the UI API client, with wire tests.
- [x] Add the Watched file paths section to Detection tuning: stored set, always-watched paths, bound, last saved, draft editing, reason-gated save, push result, server refusal.
- [x] Resolve `updated_by_label` on the watched-path GET and PUT responses, and document it in the OpenAPI spec.
- [x] Refuse a watched-path replacement whose `expected_version` is out of date with 409, and send it from the console with a conflict message and a way to load the latest set.
- [x] Hide editing without `detection_config.write`.
- [x] Component tests referencing the delta's scenarios; mutation-check them.
- [x] Document watching more file paths in `docs/operations.md`.
- [x] QA the editor in Chrome against a dev server with an enrolled host.
