# Application Control: per-rule Detect mode + closed-loop telemetry

## Why

Phase A of `add-application-control` shipped a Santa-shaped block engine sitting on EDR-shaped
plumbing: named policies, per-rule lifecycle metadata, blocked-exec events flowing through the
unified detection-rules pipeline. Phase A is operationally a blocklist - every rule, when matched,
denies the exec and notifies. That is a faithful Santa port. It is not the EDR-grade differentiator
the plan calls for in `ai/policy/plan.md:5-20`.

The EDR-grade differentiator is **per-rule Detect mode**: an operator authors a rule, marks it
Detect, watches the would-have-blocked alerts for a week, promotes the rule to Protect when
confident. CrowdStrike and SentinelOne both have this as a first-class control. Santa has
global-mode Monitor/Lockdown only. The `enforcement` column has been in the schema since the demo
cut shipped; the decision engine has never consulted it (`ESFSubscriber.swift:127` only branches on
`PROTECT`). This change activates `DETECT` semantics end-to-end.

Two adjacent gaps are bundled into this change because they live on the same AUTH-path code that
Detect mode touches, and shipping them separately would require touching the AUTH callback three
times for changes that share a single design:

1. **Default Detect on rule creation.** The current default is `enforcement=PROTECT`. Shipping
   Detect as a feature but leaving the default at Protect means an operator who pastes a rule and
   forgets to flip the toggle bricks production execs on first matching boot. CrowdStrike's IOC
   Management defaults new IOCs to Detect for exactly this reason. The change makes Detect the new
   default; Protect requires an explicit operator step.

2. **Regular exec event emission on AUTH-deny.** The Phase A spec is self-contradictory on this
   point (MODIFIED `endpoint-event-collection` "Process exec authorization" implies no exec event on
   deny; ADDED scenario "the canonical exec channel observes the denied attempt for normal telemetry
   purposes" implies the opposite). Shipped behavior: only `application_control_block` is emitted on
   deny. The graph builder never materialises a process row; catalog rules
   (`suspicious_exec`, `shell_from_office`, etc.) never observe the attempted exec. The Detect-mode
   change fixes the spec contradiction by codifying that every AUTH_EXEC decision - allow, block, or
   detect - emits a corresponding telemetry event so the regular detection pipeline observes the
   attempt regardless of outcome.

The result is a closed loop: an operator sees a `suspicious_exec` detection finding, clicks
"Create block rule" on the binary's SHA-256, the rule lands in Detect mode by default, the operator
watches `application_control_would_block` alerts accumulate over a week, promotes to Protect when
confident. Santa cannot offer this loop because the rules are external; in an EDR the rules are an
extension of the detection pipeline itself. That is the "best-class EDR, not just copying Santa"
arc the plan opens with.

This change is deliberately scoped to Detect mode only. Lockdown (`default_action=BLOCK`), allowlist
(`action=ALLOW`/`SILENT_BLOCK`), pre-deploy simulation, the server-pushed failsafe list, and the
CERTIFICATE/PATH rule types are tracked in a separate Phase B change so this PR fits the v0.1.0
release window.

## What Changes

- **Activate `enforcement=DETECT` in the extension decision engine.** When the precedence walk
  returns a `BLOCK` rule with `enforcement=DETECT`, the extension SHALL NOT deny the exec. It SHALL
  emit a new event of kind `application_control_would_block` carrying the same fields as
  `application_control_block` plus a discriminator, and SHALL allow the exec.
- **Default new rules to `enforcement=DETECT`.** Server validation continues to accept both values;
  the column default in `app_control_rules` flips from `'PROTECT'` to `'DETECT'`. Existing rules
  retain whatever value they were created with.
- **Closed-loop telemetry on every AUTH_EXEC.** When an AUTH_EXEC is denied because of a
  `PROTECT`+`BLOCK` rule, the extension SHALL emit a regular exec event alongside the
  `application_control_block` event so the graph builder and catalog detection rules observe the
  attempt. The exec event carries the standard fields plus a new `decision='blocked'` or
  `decision='would_block'` discriminator; absent for ordinary allowed execs to keep the wire shape
  stable for existing consumers.
- **Map `application_control_would_block` events to alerts** with `source='application_control'`
  and a new `subtype='would_block'` (alerts for actual blocks carry `subtype='block'`). Subtype is a
  string column on the alerts table; existing rows backfill to `'block'`. Alert dedup still keys on
  `(source, host_id, rule_id, process_id)` - would-block and block alerts for the same
  `(host, rule, process)` triple collapse, which is the behavior an operator wants while iterating
  on a rule's Detect-to-Protect promotion.
- **REST PATCH endpoint for rule enforcement.** `PATCH /api/v1/app-control/rules/{id}` accepts a
  partial body `{enforcement: "PROTECT"|"DETECT", reason: "..."}`. (The broader rule-mutation PATCH
  surface - every other mutable field - ships with the Phase A close-out PR.)
- **UI: enforcement selector + Promote-to-Protect.** The add-rule modal carries an explicit
  enforcement selector defaulting to `DETECT`. The policy-detail rules table shows the enforcement
  value per row. A `Promote to Protect` action appears per row for `DETECT` rules; clicking it opens
  a confirmation modal carrying a non-empty reason field and PATCHes the rule. The alerts table
  surfaces the new subtype with a distinct chip ("Would have blocked" vs "Blocked").
- **No new database tables.** The `enforcement` column already exists. The new `subtype` column on
  the alerts table is the only schema change.
- **No new agent command.** `set_application_control` snapshots already carry `enforcement` per
  rule; the extension's `ApplicationControlStore` already populates the field. The change is
  entirely in how the decision engine consumes it.

## Capabilities

### Modified Capabilities

- `server-application-control` - per-rule `enforcement=DETECT` becomes a first-class semantic; new
  `application_control_would_block` event ingest; default value for new rules flips to `DETECT`;
  PATCH endpoint for rule enforcement.
- `extension-application-control` - AUTH_EXEC decision engine consults `enforcement` and branches:
  `PROTECT` keeps today's deny+block-event behavior plus the new regular exec event; `DETECT`
  allows the exec and emits `application_control_would_block` plus the regular exec event.
- `endpoint-event-collection` - new event kind `application_control_would_block`; clarifies that
  AUTH-denied execs also emit a regular exec event with `decision='blocked'`; resolves the Phase A
  spec contradiction.
- `server-detection-rules-engine` - `application_control_would_block` events map to alerts with
  `source='application_control'` and `subtype='would_block'`; alerts table gains the subtype
  column.
- `web-ui` - add-rule modal carries an enforcement selector defaulting to DETECT; policy-detail
  rules table renders enforcement and exposes the Promote-to-Protect action; alerts table
  distinguishes block vs would_block subtypes.

### Unchanged Capabilities

- `agent-command-executor` - `set_application_control` snapshot already carries `enforcement` per
  rule. No protocol change.
- `server-rest-api` - the `/api/v1/app-control/rules/{id}` PATCH endpoint already exists in the
  Phase A spec; this change specifies the partial-body shape for the enforcement field.

## Impact

**Code:**

- `extension/edr/extension/ESFSubscriber.swift` - `handleAuthExec` branches on rule enforcement:
  `PROTECT` keeps today's path; `DETECT` allows + emits the new event. Both paths also emit the
  regular exec event so the graph builder and catalog rules observe the attempt.
- `extension/edr/extension/EventSerializer.swift` - new `ApplicationControlWouldBlockPayload`
  struct; `ExecPayload` gains an optional `decision` field.
- `server/rules/bootstrap/schema.go` - `app_control_rules.enforcement` default flips from
  `'PROTECT'` to `'DETECT'`. The `alerts` table gains a `subtype VARCHAR(32) NOT NULL DEFAULT 'block'`
  column.
- `server/rules/internal/catalog/application_control_would_block.go` - new catalog rule mirroring
  `application_control_block.go` for the would-block event kind. Maps to an alert with subtype.
- `server/rules/internal/appcontrol/handler.go` - PATCH handler for rule enforcement (partial
  body).
- `server/rules/api/types.go` - add the would-block payload type and the alert subtype constants.
- `ui/src/components/ApplicationControl/AddRuleModal.tsx` - enforcement selector, default DETECT.
- `ui/src/components/ApplicationControl/PolicyDetail.tsx` - enforcement column in the rules table
  plus Promote-to-Protect action.
- `ui/src/components/AlertList.tsx` - subtype-aware rendering ("Would have blocked" / "Blocked").
- `ui/src/api.ts` - `patchAppControlRule({id, enforcement, reason})`.

**Schema:**

- One column added to `alerts` (`subtype`).
- Default value flip on `app_control_rules.enforcement`.
- No new tables.

**Events schema:**

- New event kind `application_control_would_block` (same shape as `application_control_block`).
- Optional `decision` field on `exec` events (absent for ordinary allowed execs).

**Cross-context:**

- `rules` context owns the new event-type ingest mapping and the alert subtype.
- `detection` context reads `decision` from exec payloads where present.
- No new cross-context FKs.

**Rollback:**

- Schema: drop the `subtype` column and reset the enforcement default. Existing rules retain their
  individual enforcement values.
- Events schema: removing the `application_control_would_block` kind and the `decision` exec field
  is a server-tolerant revert; older agents emit the old shape, newer servers accept it.
- Persisted host token: untouched.
