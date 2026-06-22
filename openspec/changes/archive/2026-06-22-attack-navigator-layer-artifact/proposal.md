# Generate a committed ATT&CK Navigator layer from the detection catalog

## Why

Every detection rule already declares the MITRE ATT&CK techniques it maps to, and the server exposes that mapping live at `GET /api/attack-coverage` as a Navigator layer document. But there is no committed artifact: to hand someone a coverage map (a buyer's procurement questionnaire, a SOC analyst comparing vendors, an ATT&CKcon talk submission) you have to stand up a server and hit the endpoint. A checked-in `docs/attack-navigator-layer.json`, regenerated from the catalog the same way `docs/detection-rules.md` is, makes the coverage map a first-class repo artifact that reviewers can diff and anyone can drop straight into the upstream Navigator.

Two smaller gaps surface alongside it. The live endpoint builds the layer inline, so a committed file built by a separate code path could drift from what the server actually serves. And the endpoint never scoped the layer to a platform: Fleet EDR is macOS-only, yet the layer rendered the full cross-platform enterprise matrix.

## What changes

- **Shared builder.** The Navigator layer construction moves into `rules/api.BuildNavigatorLayer`, a pure function over the rule metadata. The `GET /api/attack-coverage` handler and the new generator both call it, so the live endpoint and the committed file are produced by one code path and cannot drift.
- **macOS platform scoping.** The layer now carries `filters.platforms: ["macOS"]`, so the Navigator renders only the macOS matrix Fleet EDR actually covers. This is an additive field on the existing endpoint response (and on the documented `NavigatorLayer` schema); existing clients that ignore unknown fields are unaffected.
- **Generator + committed artifact.** A new `tools/gen-attack-layer` (sibling to `tools/gen-rule-docs`) writes `docs/attack-navigator-layer.json`. A `task docs:attack-layer` regenerates it.
- **Drift gate.** A server-side test rebuilds the layer from the live catalog and byte-compares it to the committed file, failing CI when a rule's technique mapping changes without regenerating the artifact.

## Impact

- Affected spec: `server-admin-surface` (the ATT&CK coverage layer endpoint requirement gains a macOS-platform-scoping scenario).
- Affected code: `server/rules/api` (new builder), `server/rules/internal/operator` (handler delegates to it), `tools/gen-attack-layer` (new), `server/rules/bootstrap` (drift test), `docs/attack-navigator-layer.json` (new committed artifact), `Taskfile.yml`, `server/apidocs/embed/openapi.yaml`, `ui/src/api.ts`.
- No change to the agent, the wire/event format, or persistence. The endpoint change is additive and backward-compatible.
