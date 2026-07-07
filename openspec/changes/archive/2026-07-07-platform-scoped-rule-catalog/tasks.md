# Tasks

## Interface and metadata

- [x] Add a `Platform` type, constants, and `IsValidPlatform` to `server/rules/api`.
- [x] Add `Platforms()` to the `Rule` interface and a `Platforms` field to `RuleMetadata`.
- [x] Declare `Platforms()` (darwin) for all ten catalog rules in `server/rules/internal/catalog/platforms.go`.
- [x] Populate `Platforms` in the three `RuleMetadata` constructors and surface it on `GET /api/rules`.

## Engine

- [x] Add `platformScopedEvents` and scope each rule's input in `evaluateRule` (platform-less events treated as darwin; skip a rule with no matching events).

## Tests

- [x] Catalog guard test: every registered rule declares a non-empty set of valid platforms.
- [x] Engine test: darwin and windows rules over a mixed batch each see only their platform's events; a platform-less event scopes as darwin; a rule with no matching events is skipped.
- [x] Operator handler test: `GET /api/rules` carries each rule's platforms.
- [x] Existing stub rules across engine and integration tests updated to implement `Platforms()`.
