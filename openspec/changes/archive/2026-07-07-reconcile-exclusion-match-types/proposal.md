## Why

The detection-config exclusion editor (UI + API) offers every exclusion match type for every rule, but each rule only consults a fixed subset at evaluation time (issue #520). Of the 8 defined `ExclusionMatchType` values only 3 are consulted by any rule, and only 4 of the 10 catalog rules consult exclusions at all, yet the UI lists all 8 for every rule and the API validates only that the match type is a valid enum value and that `rule_id` is non-empty (it does not even check `rule_id` names a real rule). An operator can therefore create an exclusion whose `(rule_id, match_type)` pair no rule reads; it is accepted, stored, and shown as active while silently doing nothing.

This is also the blocker for the motivating use case: excluding a code-signed developer tool (for example Claude Code, `TeamIdentifier=Q6L2SF6YDW`) by its signing identity. `suspicious_exec` today consults only `parent_path_glob`, and because a path glob's `*` matches `/`, a leading-wildcard exclusion like `*/claude/versions/*` also matches `/tmp/claude/versions/payload`, so an attacker who can write to `/tmp` lands inside the exclusion. The non-spoofable, update-stable exclusion is `team_id=Q6L2SF6YDW`, but the rule cannot consult it. The parent's signing identity is already persisted on the process record (`Process.CodeSigning`, `Process.CDHash`); the rule just does not read it.

Industry practice (CrowdStrike Falcon, Microsoft Defender ASR, SentinelOne) surfaces only the exclusion dimensions a rule actually consumes, validates them server-side, and prefers signer/hash exclusions over path globs for signed tooling. This change reconciles the UI, API, and rules onto one model.

## What changes

- Each rule declares the exclusion match types it consults as a single source of truth (`SupportedExclusionMatchTypes() []ExclusionMatchType` on the rule interface), surfaced on `GET /api/rules`.
- The create-exclusion API validates `match_type` against the target rule's supported set and rejects an unsupported pair, and rejects a `rule_id` that does not name a registered rule, with a clear message.
- The admin UI's exclusion editor offers only the match types the selected rule supports, sourced from `GET /api/rules`, and resets the selection when the rule changes so a stale unsupported match type cannot be submitted.
- `suspicious_exec` gains signature-based parent exclusions (`team_id`, `signing_id`, `cdhash`) matched against the non-shell parent's already-persisted code-signing identity, in addition to `parent_path_glob`. No agent or event-wire change: the data is already stored.
- Rules that consult no exclusions offer none. No new exclusion capabilities are added to other rules in this change (candidates such as `domain` for `dns_c2_beacon` or `command_substring` for argv rules are out of scope).

Existing stored exclusions whose `(rule_id, match_type)` pair is unsupported under the new validation are already inert (they match nothing); they are left in place. Validation applies to new creates only; no migration touches stored rows.

## Capabilities

### Modified capabilities

- `server-detection-rules-engine`: the durable detection-configuration surface validates the `(rule_id, match_type)` pair on create and exposes each rule's supported exclusion match types; `suspicious_exec` suppresses by the non-shell parent's code-signing identity in addition to its path glob.
- `web-ui`: the detection-configuration exclusion editor offers only the selected rule's supported match types.

## Impact

- Code: `SupportedExclusionMatchTypes()` on `api.Rule` (`server/rules/api/types.go`) implemented by all 10 catalog rules; `api.RuleMetadata` + the `GET /api/rules` response gain the field; `suspicious_exec.parentExcluded` reads the parent's signing (`server/rules/internal/catalog/suspicious_exec.go`); the detection-config service validates against a per-rule capability map injected by bootstrap (`server/rules/internal/detectionconfig/service.go`, `server/rules/bootstrap/bootstrap.go`); the admin UI filters the match-type picker (`ui/src/api.ts`, `ui/src/components/DetectionConfig/DetectionConfig.tsx`).
- Data: none. No migration. No wire or event-schema change. No agent change.
- Behavior: creating an exclusion for an unsupported pair or an unknown rule now returns HTTP 400 where it previously succeeded; this is the intended fix. Existing inert rows are unaffected.
- Rollback is a code revert; no data to unwind.
