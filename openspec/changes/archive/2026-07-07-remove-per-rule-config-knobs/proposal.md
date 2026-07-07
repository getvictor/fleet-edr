## Why

The per-rule documentation surface (`GET /api/rules` -> the admin rule-detail page) advertises optional operator-tunable env-var knobs: each rule could declare a `config` array of `ConfigKnob`s (`env_var`, `type`, `default`, `description`), which the API exposed as `doc.config`, the OpenAPI documented as `RuleConfig`, `gen-rule-docs` rendered as a "Configuration" table in `detection-rules.md`, and the UI rendered as a "Configuration" table on the rule-detail page.

That model predates #459, which moved all rule tuning off per-rule boot-time env vars and onto the DB-backed detection-config surface (`server/rules/internal/detectionconfig/`: exclusions + rule-mode), managed at runtime through the admin UI. Since #459, no catalog rule declares a config knob, so `doc.config` is always absent: the API field never serializes (`omitempty`), the OpenAPI schema documents a shape the server never emits, the generator's Configuration section never renders, and the UI table never appears. The capability is vestigial dead surface that misleads API consumers (the OpenAPI advertises operator env-var tuning that no longer exists) and future contributors.

This change retires the per-rule config-knob capability. It is a documented SHALL scenario (`server-admin-surface` "Rule with config knobs"; `web-ui` config-knob rendering), so the removal is expressed as an OpenSpec delta rather than a silent code deletion. False-positive sources and limitations (still populated by rules) are unaffected.

## What Changes

- **BREAKING (API surface, in practice inert):** `GET /api/rules` no longer includes `doc.config`, and the OpenAPI `RuleConfig` schema is removed. Because no rule has populated `config` since #459, the field was already never present on the wire, so no client observes a change.
- Remove the `config` clause from the per-rule documentation requirement, keeping `false_positives` and `limitations`.
- Remove the "Rule with config knobs" scenario (`server-admin-surface`) and the config-knob rendering from the web-ui rule-detail requirement.
- Remove the backing code: `rules/api` `Documentation.Config` field and the `ConfigKnob` type; the `gen-rule-docs` Configuration renderer; the UI `RuleConfig` type, `RuleDoc.config`, and the rule-detail Configuration table. Scrub the `RuleConfig` schema from BOTH OpenAPI copies (`docs/api/openapi.yaml` and the `go:embed`ed `server/apidocs/embed/openapi.yaml` served at `/api/docs`).

Out of scope: the DB-backed detection-config surface (#459) that replaced this is unchanged; rule false-positive/limitation documentation is unchanged.

## Capabilities

### Modified Capabilities

- `server-admin-surface`: the per-rule documentation endpoint no longer exposes `doc.config`; the "Rule with config knobs" scenario is removed. The catalog-read and false-positive/limitation exposure are unchanged.
- `web-ui`: the rule-detail page no longer renders a configuration-knobs section; title/summary/severity/techniques/event-types/description and the false-positive/limitation sections are unchanged.

## Impact

- Wire: `doc.config` and the OpenAPI `RuleConfig` schema removed. No observable change (field was never populated post-#459).
- Code: `server/rules/api`, `tools/gen-rule-docs`, `ui/src` (api types + RuleDetail), both OpenAPI copies, and the `rule-with-config-knobs` test + spectrace marker.
