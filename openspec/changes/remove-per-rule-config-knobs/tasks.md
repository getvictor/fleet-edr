## 1. Server API + generator

- [ ] 1.1 `server/rules/api/types.go`: remove `RuleType.Config` field and the `ConfigKnob` type.
- [ ] 1.2 `tools/gen-rule-docs/main.go`: remove the `writeRuleConfig` call and function.
- [ ] 1.3 `tools/gen-rule-docs/main_test.go`: remove `TestRenderConfigKnobsListed`.
- [ ] 1.4 `server/rules/internal/catalog/registry_test.go`: remove the config-knob assertion loop and the `spec:server-admin-surface/per-rule-documentation-endpoint/rule-with-config-knobs` marker (the scenario is removed by this change's delta).

## 2. OpenAPI (both copies)

- [ ] 2.1 `docs/api/openapi.yaml`: remove the `config` property from the rule `doc` schema and the `RuleConfig` schema.
- [ ] 2.2 `server/apidocs/embed/openapi.yaml`: same removal (this is the `go:embed`ed spec served at `/api/docs`).

## 3. UI

- [ ] 3.1 `ui/src/api.ts`: remove the `RuleConfig` interface and `RuleDoc.config`.
- [ ] 3.2 `ui/src/components/RuleDetail.tsx`: remove the Configuration table.
- [ ] 3.3 `ui/src/components/RuleDetail.test.tsx`: remove the config-knob fixture and the "renders the config table" test.

## 4. Verify

- [ ] 4.1 `go build ./...`, `go vet`; `go test` for `server/rules/...`, `tools/gen-rule-docs/...`, `server/metrics/...`.
- [ ] 4.2 UI: `eslint`, `tsc --noEmit`, `vitest run src/components/RuleDetail.test.tsx`.
- [ ] 4.3 `openspec validate --all --strict` passes; spectrace passes (the removed scenario is exempt via this delta).
- [ ] 4.4 Regenerate `docs/detection-rules.md` if needed (no change expected: no rule declared a knob).
