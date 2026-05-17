# Application Control: Detect mode — design notes

## Context

The full Application Control plan lives at `ai/policy/plan.md` and the Phase A blueprint at
`openspec/changes/add-application-control/`. This change opens the Phase B arc by activating one
slice of it — per-rule Detect mode — and bundles two adjacent fixes that live on the same AUTH-path
code (default-Detect on rule creation; the AUTH-deny telemetry gap).

The remaining Phase B work — Lockdown (`default_action=BLOCK`), allowlist
(`action=ALLOW`/`SILENT_BLOCK`), pre-deploy simulation, server-pushed failsafe carve-outs,
CERTIFICATE/PATH rule types — lives in a separate change so this PR fits the v0.1.0 release window.

**Current state (after the Phase A close-out PR):**

- `app_control_rules.enforcement` is in the schema, default `'PROTECT'`, the column is propagated
  through the wire payload, written to the extension's snapshot, but never consulted by the AUTH
  decision engine.
- `ESFSubscriber.handleAuthExec` denies on BINARY/CDHASH/SIGNINGID/TEAMID match with
  `enforcement=PROTECT` (after the Phase A close-out's precedence-walker rewrite). The DETECT branch
  is missing.
- A denied AUTH_EXEC emits only `application_control_block`; no regular exec event is produced, so
  the graph builder doesn't materialise the attempted-process row and catalog detection rules
  (`suspicious_exec`, etc.) never observe the attempt.
- Alerts table carries `source='application_control'` for blocks but has no subtype dimension, so
  blocked and would-be-blocked rows can't be visually distinguished.

**Constraints:**

- ESF AUTH_EXEC deadline is a hard kernel-side limit. Adding the Detect branch adds zero map
  lookups — same precedence walk; only the post-walk action changes. No latency budget impact.
- Per ADR-0004, cross-context calls go through `api/` packages. The new event kind flows through
  the existing event channel between `endpoint` and `rules`/`detection`. No new cross-context calls.
- Per `CLAUDE.md` test-style matrix: PBT for the AUTH-path decision invariants; example-based for
  the PATCH endpoint wire shape; integration tests for the closed-loop alert + promote flow.

## Goals / Non-Goals

**Goals:**

- Activate per-rule `enforcement=DETECT` end-to-end so an operator can author rules in log-only
  mode, observe `application_control_would_block` alerts over time, and promote rules to PROTECT
  when confident.
- Make Detect the default for new rules so an operator who pastes a rule and forgets the toggle
  doesn't brick production on first matching boot. The plan calls this out as the EDR-grade
  rollout-safety norm.
- Resolve the Phase A spec contradiction on AUTH-deny exec event emission by codifying that every
  AUTH_EXEC decision emits a corresponding telemetry event so the regular detection pipeline
  observes the attempt regardless of decision.
- Surface the would-block subtype in the alerts UI so an operator iterating on a Detect-mode rule
  sees the "would have blocked" alerts distinctly from real blocks.

**Non-Goals:**

- Lockdown (`default_action=BLOCK` on policies). Requires failsafe carve-outs + pre-deploy
  simulation to ship safely. Phase B proper.
- `ALLOW` / `SILENT_BLOCK` rule actions. Phase B proper.
- Pre-deploy simulation (`POST /api/v1/app-control/policies/{id}/simulate`). Phase B proper.
- Server-pushed failsafe carve-out list. Phase B proper.
- Leaf-cert SHA-256 cache + CERTIFICATE rule type. Phase B proper.
- PATH rule type acceptance + Launch Services indirection handling. Phase B proper.
- "Rule from alert" workflow (operator clicks a button on a detection finding to auto-create an
  app_control_rule). Worth its own change once the closed-loop telemetry surface stabilises here.

## Decisions

### Distinct event kind `application_control_would_block`, not a flag on `application_control_block`

A new event kind keeps ingest, alert mapping, and visual distinction trivially separable. A flag
would force every consumer (event router, alert mapper, alert detail UI) to branch on the field
and risk silently treating one type as the other when the branch is forgotten. The wire-format
cost is one new event_type string; the rule shape is otherwise identical to `application_control_block`.

*Alternatives considered:* a discriminator field on `application_control_block`. Rejected — the
flag's default value becomes the "old shape" assumption and consumers that don't yet branch on it
silently misattribute. A new event kind makes the unknown-shape case loud.

### Default `enforcement='DETECT'` for new rules

The schema default flips. Existing rules retain whatever value they were created with. The UI's
add-rule modal carries an explicit enforcement selector defaulting to DETECT; the operator can
still pick PROTECT with one click. The PATCH endpoint accepts either value.

The rationale is the EDR-grade rollout-safety norm CrowdStrike's IOC Management embodies: the
*easy path* must be the *safe path*. An operator who pastes a rule and clicks Save lands in Detect
mode, sees would-block alerts, decides whether to promote. An operator who consciously authors a
PROTECT rule is making a deliberate choice. Inverting this — defaulting to PROTECT — means the
first mistake is a brick, not an alert.

*Alternatives considered:* keep the default at PROTECT and require operators to opt into Detect.
Rejected — that's the Santa posture, where "Monitor mode" is a global setting and individual rule
authoring assumes the operator knows what they're doing. The EDR-grade posture inverts the
relationship.

### Closed-loop telemetry: every AUTH_EXEC emits the regular exec event too

The Phase A spec is inconsistent here. The MODIFIED `endpoint-event-collection` "Process exec
authorization" requirement says `BLOCK`/`PROTECT` denies and "Otherwise the system MUST allow the
exec and emit an `exec` event describing the new image" — implying the deny path skips the exec
event. The ADDED scenario says "the canonical exec channel observes the denied attempt for normal
telemetry purposes" — implying the opposite. The shipped code follows the MODIFIED requirement.

The Detect-mode change reconciles by codifying that **every AUTH_EXEC decision emits a
corresponding telemetry event**, with a `decision` field discriminating among `allowed`, `blocked`,
and `would_block`. Reasoning:

- Without the regular exec event on deny, the graph builder never materialises a process row for
  the attempted-but-blocked exec. Catalog detection rules (which key on the process graph) don't
  observe the attempt. An attacker probing with a blocked binary triggers only the deduped block
  alert — the behavioral rules above don't fire on repetition because the events that would feed
  them never reach the pipeline.
- With the regular exec event on deny, repeated blocked attempts feed `suspicious_exec` and friends
  exactly the way an allowed exec would. Two unrelated detection paths (rule-based blocking +
  behavioral catalog rules) now compose instead of competing.
- The Detect path needs the same telemetry: when an exec is allowed-but-flagged, the regular exec
  event still fires (it's via NOTIFY_EXEC today). Adding `decision='would_block'` to the exec
  event's optional payload lets the graph + catalog see the flag without breaking the existing
  consumer shape.

The `decision` field is **optional** on exec events. It is absent for ordinary allowed execs (the
99.9% case) so the wire shape stays stable for every existing consumer. It is present only when
the AUTH path made a non-trivial decision.

*Alternatives considered:*

- Emit a separate `auth_decision` event for every AUTH_EXEC. Rejected — doubles the AUTH-path
  event volume and forces every catalog rule to join across two event kinds for what is logically
  one process exec.
- Keep AUTH-deny silent on the regular channel. Rejected — that's the status quo, and it's the bug
  this change fixes.

### Alert subtype, not a new source

Adding `subtype` to the alerts table preserves the source enum as `('detection',
'application_control')` and adds a free-form-but-disciplined string column for sub-classification.
Phase A blocks become `subtype='block'`; would-blocks become `subtype='would_block'`. Future
Phase B work (allow-with-warn, silent-block) extends the same subtype dimension.

*Alternatives considered:* extend the `source` ENUM to `('detection', 'application_control_block',
'application_control_would_block')`. Rejected — the source dimension communicates *which subsystem
produced the alert*, and both shapes are produced by application control. Subtype is the right
axis.

### Alert dedup still keys on `(source, host_id, rule_id, process_id)` — not `(source, subtype, ...)`

A would-block alert and a subsequent block alert for the same `(host, rule, process)` triple
collapse into one row. The alert's subtype reflects the most recent decision; older subtypes are
implicitly overwritten (or visible in audit history, depending on follow-on work).

The reasoning: when an operator promotes a Detect rule to Protect, the next exec of the same
binary on the same host should not produce a new alert row — it should update the existing one to
`subtype='block'`. The alert's lifecycle (would_block → block) matches the operator's mental
model. Separate rows per subtype would clutter the alert list with adjacent "would have blocked"
and "blocked" entries for the same logical incident.

*Alternatives considered:* include subtype in the dedup key. Rejected because of the post-promotion
clutter; Phase B simulation will need its own alert lifecycle anyway (would-allow vs would-block
in Lockdown), and we can revisit then.

### PATCH `/api/v1/app-control/rules/{id}` enforcement-only body

The Phase A close-out PR ships the full rule-mutation PATCH (every mutable field). This change
specifies the *contract* for the partial-body shape that Detect mode uses: a body containing only
`{enforcement, reason}` is valid; other fields default to "no change". Audit event is emitted with
the diff.

*Alternatives considered:* a dedicated `POST .../rules/{id}:promote` action endpoint. Rejected as
unnecessary RPC-ification; PATCH with a partial body is the standard REST way and aligns with the
generic rule PATCH already in scope.

## Risks / Trade-offs

- **Detect-mode noise.** A broad Detect rule on a high-frequency exec target floods the alerts
  view. Mitigation: same as Phase A blocks — alert dedup collapses repeats per
  `(source, host_id, rule_id, process_id)`. Operators iterating on a Detect rule see one alert per
  unique process triple, not one per exec.
- **Default-Detect regression risk.** A migrating Santa admin pastes their existing blocklist into
  the EDR expecting it to block on apply; instead it lands in Detect and silently logs. Mitigation
  is documentation + the explicit selector in the modal (the selector is non-defaultable, so the
  operator can't miss the value). The migration path (`add-application-control-import-santa` in
  Phase C) will set `enforcement=PROTECT` on imported rules to preserve the source-system
  semantics.
- **Telemetry-on-deny volume.** Adding the regular exec event to every blocked AUTH_EXEC roughly
  doubles the event count on the deny path. For typical fleets this is negligible (blocks are
  rare); for a misconfigured-broad-rule scenario the volume is bounded by the same alert dedup
  that bounds the block-event volume — both share the upload batch.
- **`decision` field absence semantics.** The field is absent for ordinary allowed execs and
  present for AUTH-flagged execs. Consumers that switch on `decision` see `nil` for the 99.9% case
  and one of `blocked`/`would_block` otherwise. This is the standard "optional field" Go/Swift
  pattern; the schema declares the field optional and ingest is tolerant.
- **Subtype value drift.** A new alert subtype landing in Phase B (e.g. `silent_block`,
  `would_allow`) needs to be coordinated with the UI rendering layer. The string-not-enum choice
  preserves forward-compat; the UI defaults to "Application Control" for unknown subtypes rather
  than rendering blank.
- **Rule promotion races.** A rule promoted from DETECT to PROTECT while an in-flight
  `application_control_would_block` event is on the upload queue produces a `would_block` alert
  *after* the rule already has `enforcement=PROTECT`. Operationally this is fine — the alert is
  historically accurate (the AUTH decision at the time was Detect), and the next exec will block.
  Worth documenting; not worth coordination.

## Migration Plan

No customer-facing migration. The product has not shipped its first release.

**Deploy:**

1. Apply the schema delta: add `alerts.subtype VARCHAR(32) NOT NULL DEFAULT 'block'`; flip
   `app_control_rules.enforcement` default to `'DETECT'`. Existing rules retain their individual
   enforcement values.
2. Land the extension change, the new event kind, the alert mapper, the PATCH endpoint, the UI.
3. Existing test databases re-bootstrap from the seed; the demo cut's existing fixtures keep their
   `enforcement='PROTECT'` value where set explicitly.

**Rollback** (pre-release):

- Schema: drop `alerts.subtype`; reset enforcement default.
- Events schema: server ingest tolerates unknown event types and unknown fields, so older agents
  emitting old shapes against newer servers and vice versa both work for the in-flight transition.
- Persisted host token: not touched.

## Open Questions

- **Alert subtype rendering.** The visual difference between "would have blocked" and "blocked" in
  the alerts list — distinct chip color? distinct icon? text-only? Defer to the UI implementation;
  the spec mandates that the two be visually distinguishable, not a specific palette.
- **Promote-to-Protect confirmation.** Does promoting a rule require an explicit reason field, or
  is the per-rule audit row sufficient? The spec mandates an audit event on enforcement change;
  the modal-confirmation question is a UI policy call. The current draft requires a non-empty
  reason. Worth reviewing once the alerts → promotion flow is on screen.
- **Future "rule from alert" workflow.** When an operator sees a `suspicious_exec` detection
  finding, should a button auto-create an `application_control_rule` with `enforcement=DETECT` from
  the offending binary's SHA-256? Out of scope here; tracked as a follow-on change once Detect mode
  is in operator hands.
