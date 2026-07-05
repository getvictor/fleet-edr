## 1. Server API + generator

- [x] 1.1 `server/rules/api/types.go`: remove the `Documentation.Config` field and the `ConfigKnob` type.
- [x] 1.2 `tools/gen-rule-docs/main.go`: remove the `writeRuleConfig` call and function.
- [x] 1.3 `tools/gen-rule-docs/main_test.go`: remove `TestRenderConfigKnobsListed`.
- [x] 1.4 `server/rules/internal/catalog/registry_test.go`: remove the config-knob assertion loop. Retain the `spec:server-admin-surface/per-rule-documentation-endpoint/rule-with-config-knobs` marker transitionally (with an explanatory note), because a MODIFIED delta does not exempt a dropped scenario pre-archive; delete the marker at release archive when the canonical scenario is removed.

## 2. OpenAPI (both copies)

- [x] 2.1 `docs/api/openapi.yaml`: remove the `config` property from the rule `doc` schema and the `RuleConfig` schema.
- [x] 2.2 `server/apidocs/embed/openapi.yaml`: same removal (this is the `go:embed`ed spec served at `/api/docs`).

## 3. UI

- [x] 3.1 `ui/src/api.ts`: remove the `RuleConfig` interface and `RuleDoc.config`.
- [x] 3.2 `ui/src/components/RuleDetail.tsx`: remove the Configuration table (and scrub the header comment).
- [x] 3.3 `ui/src/components/RuleDetail.test.tsx`: remove the config-knob fixture and the "renders the config table" test.

## 4. Verify

- [x] 4.1 `go build ./...`, `go vet`; `go test` for `server/rules/...`, `tools/gen-rule-docs/...`, `server/metrics/...`.
- [x] 4.2 UI: `eslint`, `tsc --noEmit`, `vitest run src/components/RuleDetail.test.tsx`.
- [x] 4.3 `openspec validate --all --strict` passes; `spectrace --strict` passes (the dropped scenario's marker is retained transitionally rather than exempt, since exemption applies only to whole `## REMOVED` requirements).
- [x] 4.4 Regenerate `docs/detection-rules.md` if needed (no change: no rule declared a knob, so the generator never emitted a Configuration section).
