# Application Control Detect mode rollout tasks

This change layers per-rule Detect mode on the foundation shipped by `add-application-control`. It
assumes the Phase A close-out PR has landed (precedence walker honors all wired rule types, the
PATCH endpoint exists at least in skeleton, the `host_groups` + `app_control_assignments` tables
are seeded, `cdhash` is on exec events). Each task below cites the matching spec requirement.

## 1. Schema delta

- [ ] 1.1 Flip the default value of `app_control_rules.enforcement` from `'PROTECT'` to `'DETECT'`
  in `server/rules/bootstrap/schema.go`. Existing rows keep their stored value; only new rows
  default. (spec: `server-application-control` "Default Detect on rule creation".)
- [ ] 1.2 Add `subtype VARCHAR(32) NOT NULL DEFAULT 'block'` to the `alerts` table in the
  detection-context bootstrap. Existing rows backfill to `'block'`. Add a non-unique index on
  `(host_id, source, subtype)` so the alerts read API can filter without scanning. (spec:
  `server-detection-rules-engine` "Alert subtype distinguishes block from would-block".)
- [ ] 1.3 Enforce the source-dependent dedup key with a unique index (or indexes) that backs the
  ingest UPSERT. MySQL has no partial unique indexes, so pick one of:
  - two unique indexes - `UNIQUE (source, host_id, rule_id, process_id)` enforced only on
    `source='detection'` rows by writing a sentinel value (e.g. `''`) into `process_id` for
    `source='application_control'` rows, plus the natural collision check on the sentinel; OR
  - a synthetic `dedup_discriminator` column populated at write time as `process_id` for
    `source='detection'` and a fixed sentinel for `source='application_control'`, covered by a
    single `UNIQUE (source, host_id, rule_id, dedup_discriminator)`.
  Whichever shape lands, the schema integration test in 1.4 MUST exercise both
  insert-then-update-in-place and insert-twice-rejected paths for both sources. (spec:
  `server-detection-rules-engine` "Alert dedup key depends on source".)
- [ ] 1.4 Per-context integration test in `server/rules/internal/tests/` for the default flip:
  a new rule created without an explicit `enforcement` lands with `DETECT`.
- [ ] 1.5 Per-context integration test in `server/detection/internal/tests/` for the subtype
  backfill: a fresh schema bootstrap leaves `subtype='block'` on existing alert rows.
- [ ] 1.6 Per-context integration test in `server/detection/internal/tests/` for the dedup-index
  invariants: two `application_control_would_block` events with distinct `process_id` on the same
  `(host, rule)` produce one row; two `detection`-source findings on distinct `process_id` on the
  same `(host, rule)` produce two rows.

## 2. Extension decision engine

- [ ] 2.1 `extension/edr/extension/ESFSubscriber.swift:handleAuthExec`: branch on the matched
  rule's `enforcement`. `PROTECT` keeps today's path (deny + block-event + notification).
  `DETECT` calls `es_respond_auth_result(ALLOW)` and emits a new
  `application_control_would_block` event. The host-app notification fires only on PROTECT.
  (spec: `extension-application-control` "Detect mode allows the exec and emits a would-block
  event".)
- [ ] 2.2 In both `PROTECT` and `DETECT` branches, emit the regular exec event with a `decision`
  field of `'blocked'` or `'would_block'` respectively. Allowed-execs (no rule match) continue to
  emit the regular exec event with the `decision` field omitted. (spec: `endpoint-event-collection`
  "Every AUTH_EXEC decision emits a corresponding telemetry event".)
- [ ] 2.3 `extension/edr/extension/EventSerializer.swift`: add `ApplicationControlWouldBlockPayload`
  with the same shape as `ApplicationControlBlockPayload`. Add an optional `decision` field on
  `ExecPayload` (encoder omits it when nil; decoder accepts absence).
- [ ] 2.4 Swift unit tests for the new branch: a snapshot containing one DETECT rule and one
  PROTECT rule produces allow + would-block event for a DETECT match and deny + block event for
  a PROTECT match. Confirms the host-app modal does NOT fire on the DETECT path.

## 3. Agent + wire

- [ ] 3.1 Verify (test only, no code change) that the existing `set_application_control` snapshot
  format carries `enforcement` per rule and that the extension's `ApplicationControlStore`
  populates the field on apply. Round-trip PBT in
  `server/rules/internal/appcontrol/marshaltest.go` already covers this; add a fixture covering a
  rule with `enforcement=DETECT` so the regression is pinned.

## 4. Server domain and validation

- [ ] 4.1 `server/rules/internal/appcontrol/validate.go`: confirm `ValidateEnforcement` accepts
  both `PROTECT` and `DETECT`. Add scenario coverage for the empty-defaults-to-DETECT case.
- [ ] 4.2 `server/rules/internal/appcontrol/store.go:CreateRule`: when the request body omits
  `enforcement`, persist `'DETECT'`. (spec: `server-application-control` "Default Detect on rule
  creation".)
- [ ] 4.3 PATCH endpoint partial body: `PATCH /api/v1/app-control/rules/{id}` accepts a body
  containing one or more of `{enforcement, severity, custom_msg, custom_url, comment, enabled,
  reason}`. `reason` is required. Each mutation emits a single audit event with the diff. (spec:
  `server-application-control` "PATCH endpoint for enforcement change".)
- [ ] 4.4 Integration test: create a rule (lands in DETECT), PATCH it to PROTECT with a reason,
  observe the audit row, observe the fan-out command with the updated `enforcement` field, observe
  the next exec of the matching binary produces a `block` alert (not a `would_block`).
- [ ] 4.5 Integration test: malformed PATCH body (`enforcement="MAYBE"`, missing `reason`) returns
  a typed `application_control.invalid_request` error and does not mutate the rule.

## 5. Detection-pipeline wiring

- [ ] 5.1 New catalog rule `server/rules/internal/catalog/application_control_would_block.go`
  mirroring `application_control_block.go`. Maps the new event kind to an alert with
  `source='application_control'` and `subtype='would_block'`. Severity copied from the rule.
- [ ] 5.2 Update the `application_control_block` catalog rule to stamp `subtype='block'` on the
  alert it produces. (Today the column doesn't exist; this change adds the default and the explicit
  stamp.) (spec: `server-detection-rules-engine` "Alert subtype distinguishes block from
  would-block".)
- [ ] 5.3 Update the alerts read API filter parameters: `subtype` is a valid filter alongside
  `source`. (spec: `server-detection-rules-engine` "Alerts list filters by source and subtype".)
- [ ] 5.4 Integration test for the dedup interaction across a Detect-to-Protect promotion: a
  `would_block` alert exists for `(host_a, rule_X)` with `linked_process_id=process_42`; the rule
  is promoted to PROTECT; a subsequent `application_control_block` event for `(host_a, rule_X)`
  with a different `linked_process_id=process_99` (a separate exec) updates the existing alert row
  to `subtype='block'` and replaces `linked_process_id` with `process_99` without creating a new
  row. (Verifies the source-specific dedup key from spec "Alert dedup key depends on source".)
- [ ] 5.5 Integration test for the alert subtype filter:
  `GET /api/v1/alerts?source=application_control&subtype=would_block` returns only the would-block
  alerts on the host.

## 6. Web UI

- [ ] 6.1 `ui/src/components/ApplicationControl/AddRuleModal.tsx`: add an enforcement selector
  with PROTECT + DETECT options, defaulting to DETECT. Pass the value to the create-rule API call.
  (spec: `web-ui` "Add-rule modal carries an enforcement selector".)
- [ ] 6.2 `ui/src/components/ApplicationControl/PolicyDetail.tsx`: add an enforcement column to
  the rules table. For DETECT rules, render a `Promote to Protect` action.
- [ ] 6.3 Promote-to-Protect modal: confirmation modal carrying a non-empty reason field. Submit
  calls `PATCH /api/v1/app-control/rules/{id}` with `{enforcement: "PROTECT", reason}`. On
  success, optimistically updates the table row.
- [ ] 6.4 `ui/src/components/AlertList.tsx`: render the new subtype as a distinct chip. Block:
  red chip "Blocked". Would-block: yellow chip "Would have blocked". Unknown subtype falls back
  to "Application Control" so future Phase B subtypes don't render blank. (spec: `web-ui`
  "Alerts list distinguishes block vs would-block subtypes".)
- [ ] 6.5 React Testing Library coverage:
  - AddRuleModal renders with `enforcement=DETECT` selected by default; explicit PROTECT
    selection persists into the submitted request body.
  - PolicyDetail renders the enforcement column; the Promote-to-Protect button appears for DETECT
    rules and is absent for PROTECT rules.
  - Promote-to-Protect modal gates submission on a non-empty reason; happy path calls the PATCH
    client.
  - AlertList renders the correct chip for each subtype, including the unknown-subtype fallback.

## 7. End-to-end verification on edr-dev VM

- [ ] 7.1 Author a TEAMID rule for an arbitrary signed binary (e.g. Slack's team) with
  `enforcement=DETECT` (the new default). Exec the binary, verify it is *allowed* and that an
  `application_control_would_block` event lands in the events stream and an alert with
  `subtype='would_block'` appears in the alerts view.
- [ ] 7.2 Promote the rule to PROTECT via the UI. Exec the binary again; verify it is *denied*
  and the existing alert row updates to `subtype='block'` (the dedup-by-triple invariant in
  scenario 5.4). The host-app modal fires this time, not on the first exec.
- [ ] 7.3 Author a Detect rule against the agent's own team_id. Exec the agent. Verify the
  failsafe carve-out (currently hard-coded to `team_id == extensionTeamID`) overrides DETECT and
  the agent runs without an alert. (Documents that the failsafe is enforcement-agnostic.)
- [ ] 7.4 Confirm via SigNoz that the new event kind, the new alert subtype, and the
  enforcement-change audit row all surface on the existing telemetry pipeline, and that the
  `decision` field on exec events is queryable.

## 8. Documentation

- [ ] 8.1 Update `CLAUDE.md` to mention `enforcement=DETECT` as the v0.1.0 default and the
  Detect-to-Protect promotion workflow.
- [ ] 8.2 Update `docs/install-server.md` (or its app-control follow-on) with a "Rule rollout
  posture" section: new rules ship Detect by default; operators promote to Protect after
  observing would-block alerts. Add a screenshot of the alert chip pair.
- [ ] 8.3 Add a developer-facing note under `docs/` clarifying the `decision` field's semantics on
  exec events: absent for ordinary allowed execs, `'blocked'` for AUTH-denied execs, `'would_block'`
  for DETECT-allowed-but-flagged execs.
