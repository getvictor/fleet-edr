# Tasks

## Server: resolve exclusion author to an email

- [x] Add `CreatedByEmail string` (json `created_by_email,omitempty`, `db:"-"`) to `api.DetectionExclusion`.
- [x] Add an optional `userEmailResolver` to the detection-config operator handler with a `SetUserEmailResolver` setter; resolve `created_by` (`user:<id>`) per request with memoization in `handleListExclusions`.
- [x] Wire `UserEmailByID` through `rules/bootstrap` Deps and `cmd/main` (`userEmailByIDFromIdentity` over `identityapi.Service.GetUser`).
- [x] Handler test: email filled + memoized per id, blank on resolver error and non-user actor, blank with a nil resolver.

## UI: show the resolved email

- [x] Add `created_by_email?: string` to `DetectionExclusion` in `ui/src/api.ts`.
- [x] Render `created_by_email || created_by` in the exclusions table.
- [x] Test: email shown when present, raw identifier otherwise.

## Drop operator-selectable monitor mode

- [x] `MODES = [alert, disabled]`; add `modeOptions` so a legacy `monitor` row still renders and can be migrated.
- [x] Simplify the reason modal to the disabled-only path.
- [x] Tests: monitor not offered for a normal rule; legacy monitor row still displays.
- [x] Keep the `mode` ENUM, server acceptance, and engine monitor handling unchanged (no migration).

## Default severity column

- [x] Show each rule's declared severity in the rule-modes table next to the override, ordered critical-first.

## Verification

- [x] `go build ./server/...`, `go test ./server/rules/internal/operator/`.
- [x] `vitest`, `tsc --noEmit`, `eslint` for the UI.
- [x] `task lint:dashes`.
