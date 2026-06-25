# Detection tuning: resolve exclusion author to an email, drop operator-selectable monitor mode

## Why

Manual QA of the Detection tuning admin surface surfaced two rough edges:

- The exclusions table showed the raw principal identifier (`user:8`) in the "Created by" column. For a security-relevant suppression, an operator needs to see who created it; an opaque numeric id fails that accountability goal. The audit log already resolves a user id to an email at read time, so the pattern exists in the codebase.
- The per-rule mode offered three choices (alert / monitor / disabled). `monitor` is implemented in the engine (it suppresses the alert and emits a structured log signal), but there is no UI or dashboard to review what fired in monitor mode, so it has no operator-facing value today. Offering it invites confusion. We drop it from the operator surface while keeping the engine's handling of any persisted `monitor` row intact, so this is reversible and needs no migration.

## What changes

- The detection-config exclusions list resolves each entry's `created_by` (`user:<id>`) to a display email at read time and returns it as a new `created_by_email` response field. Resolution goes through identity's `Service.GetUser` via a cross-context closure (same posture as detection's `UserExists` dep), is memoized per request, and degrades to an empty value (UI falls back to the raw identifier) when the user cannot be resolved.
- The Detection tuning UI renders the resolved email in the Created by column, falling back to the raw identifier.
- `monitor` is removed from the operator-selectable per-rule modes (alert / disabled only). A legacy persisted `monitor` row is still displayed so an operator can migrate it to alert or disabled, but monitor cannot be chosen anew. The `mode` ENUM, the server's acceptance of a `monitor` value, and the engine's monitor handling are unchanged, so existing rows keep working.
- The rule-modes table also shows each rule's declared (default) severity next to the optional override, so the override's effect is legible.

## Impact

- Affected specs: `web-ui` (Detection configuration admin views).
- Affected code: `server/rules/api` (new `CreatedByEmail` field), `server/rules/internal/operator` (resolver + list wiring), `server/rules/bootstrap` + `server/cmd/fleet-edr-server` (dep wiring), `ui/src/api.ts`, `ui/src/components/DetectionConfig/*`.
- No database migration. No engine behavior change. The `created_by_email` field is additive and omitted when empty, so existing API consumers are unaffected.
