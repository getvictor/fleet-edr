# Tasks

- [x] Add the optional `ModeDefaulter` interface and `DefaultModeOf` helper to `server/rules/api`.
- [x] Resolve against the caller-supplied rule default instead of a hardcoded `alert`, in both the no-setting and uninterpretable-mode paths.
- [x] Thread each rule's declared default through the engine, including the no-resolver path.
- [x] Mirror the declared default onto `RuleMetadata` and `GET /api/rules`, and describe it in the OpenAPI schema.
- [x] Guard test: every registered rule's declared default is a mode the engine can act on.
- [x] Correct `docs/operations.md`, which said every rule resolves to `alert` by default.
