# Tasks

- [x] Add `getReachableAddresses` and `replaceReachableAddresses` to the UI API client, with the typed refusals mapped to what the operator can do about them.
- [x] Add `ReachableAddress` and `ReachableSet` to the UI types, and `containment_config.read` / `containment_config.write` to the permission actions.
- [x] Add the Containment section to admin settings: stored set, bound, last saved, contained-host count, draft editing, reason-gated save, server refusal.
- [x] Put the save through `useReauthRetry`, since `containment_config.write` requires a recent authentication.
- [x] Resolve `updated_by_label` on the reachable GET and PUT responses, and document it in the OpenAPI spec.
- [x] Send `expected_version` and handle the conflict with a message and a way to load the latest destinations.
- [x] Hide editing without `containment_config.write`.
- [x] Say on a contained host's page how many destinations it can still reach, alongside the name-filtering caveat.
- [x] Component tests referencing the delta's scenarios; mutation-check them.
- [x] Replace the console known limit in `docs/operations.md` with how to edit the set.
- [ ] QA the editor in Chrome against a dev server, with a contained host.
