# Tasks

## Server

- [x] `server/rules/api/navigator.go`: add exported `NavigatorLayer` / `NavigatorTechnique` / `NavigatorFilters` types, `BuildNavigatorLayer([]RuleMetadata)`, and `MarshalNavigatorLayerIndented`. The builder emits `filters.platforms: ["macOS"]` and a non-nil empty `techniques` slice for the no-rules case.
- [x] `server/rules/internal/operator/handler.go`: `handleATTACKCoverage` delegates to `api.BuildNavigatorLayer`; drop the inline structs and the now-unused `slices` / `strings` imports.

## Tooling + artifact

- [x] `tools/gen-attack-layer/main.go`: new generator that writes `docs/attack-navigator-layer.json` via the shared builder.
- [x] `Taskfile.yml`: add `docs:attack-layer`.
- [x] `docs/attack-navigator-layer.json`: generated and committed.
- [x] `server/rules/bootstrap/navigator_layer_test.go`: drift gate (runs in the `./server/...` CI job) byte-comparing the committed file to a fresh build.

## Contract docs

- [x] `server/apidocs/embed/openapi.yaml`: document `filters` on the `NavigatorLayer` schema.
- [x] `ui/src/api.ts`: add `filters` to the `AttackNavigatorLayer` interface; fix the `AttackCoverage.test.tsx` fixture.

## Verification

- [x] `go build ./...`, server rules/api + operator + bootstrap tests, integration `TestOperator_GetAttackCoverage` (asserts `filters.platforms == ["macOS"]`, carries the new scenario marker).
- [x] UI typecheck + `AttackCoverage` test.
- [x] `openspec validate attack-navigator-layer-artifact --strict`.
