# Tasks

- [x] Add `GET /api/v1/app-control/rules/{id}`, gated on the application-control read permission
- [x] Handler tests: found, not found, malformed id, and the read-permission denial (identical whatever the rule id, so a denied caller cannot use it as an existence oracle)
- [x] Unauthenticated rejection needs no per-route test: `mountAuthed` derives the session-protected set from what `RegisterAuthedRoutes` registers, covered by `TestMountAuthed_registeredRouteIsProtectedNotSPA`
- [x] UI api client: fetch one application-control rule
- [x] Alert breadcrumb resolves `app_control:<n>` to its policy and links there
- [x] Vitest covers all three title branches: app-control, documented detection rule, neither
- [x] Mutation-check the branch selection, not just that a link renders
