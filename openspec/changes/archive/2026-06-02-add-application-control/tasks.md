# Application Control rollout tasks

## Status (2026-05-16)

The demo cut shipped via PRs #151 - #159 (`App control demo cut steps 1 - 9`). The slice that landed is a
BINARY-only, single-policy, all-hosts foundation that closes most of Phase A's *shape* but explicitly
punts three categories of work to a Phase A close-out PR before the change can be archived:

1. **The other five rule identifier types** (CDHASH, SIGNINGID, CERTIFICATE, TEAMID, PATH) - schema
   and snapshot maps exist for all six; the validator and the extension's precedence walk gate at
   BINARY only (`server/rules/internal/appcontrol/validate.go:25-83`,
   `extension/edr/extension/ESFSubscriber.swift:124-146`).
2. **`host_groups` + `app_control_assignments` tables + the `all-hosts` seed** - explicitly deferred
   with a comment in `server/rules/bootstrap/schema.go:11-13`. Fan-out (`appcontrol/service.go`)
   currently targets every enrolled host directly, bypassing the assignment layer the spec mandates.
3. **`cdhash` + `signing_id` + `team_id` + `leaf_cert_sha256` on every exec event** - `team_id` and
   `signing_id` ship today nested under `code_signing` (`extension/edr/extension/EventSerializer.swift`);
   `cdhash` and `leaf_cert_sha256` are not extracted from `es_process_t` at all.

These three categories are the entire remaining Phase A surface relative to the spec. They are
captured below as PR-1 close-out scope; the follow-on Phase B work (per-rule Detect mode, allowlist,
Lockdown, simulation, failsafes) lives in a separate change (`add-application-control-detect-mode`).

## 1. Demolition (single PR, delete the legacy scaffolding)

- [x] 1.1 Delete `server/rules/internal/policy/` package, the `policies` table from
  `server/rules/bootstrap/schema.go`, the `BlocklistPolicy` types from `server/rules/api/types.go`,
  and their tests. *Shipped: PR #151.*
- [x] 1.2 Delete the `GET /api/policy` and `PUT /api/policy` handlers and routes from
  `server/rules/internal/operator/handler.go` and the corresponding `server-rest-api` wiring.
  *Shipped: PR #151.*
- [x] 1.3 Delete the `set_blocklist` command type and the `setBlocklistPayload` codec from
  `agent/commander/commander.go`. Delete the `PolicySender` interface and any unit tests pinned to it.
  *Shipped: PR #151.*
- [x] 1.4 Delete `extension/edr/extension/PolicyStore.swift`, the `/var/db/com.fleetdm.edr/policy.json`
  read path, and the `Set<String>` blocklist lookup site in `extension/edr/extension/ESFSubscriber.swift`.
  Leave AUTH_EXEC as an unconditional allow until task 4.5 lands the new decision engine call site.
  *Shipped: PR #151.*
- [x] 1.5 Delete `ui/src/components/PolicyEditor.tsx`, the `/policy` route, and the `fetchPolicy` /
  `updatePolicy` clients from `ui/src/api.ts`. Remove the policy nav entry. *Shipped: PR #151.*
- [x] 1.6 Update `schema/events.json` to remove any references to the legacy blocklist payload (none
  expected, but verify). *Shipped: PR #151.*
- [x] 1.7 Run the test suite; expect the pre-existing policy tests to vanish and nothing else to fail.
  *Shipped: PR #151.*

## 2. Schema and seed

- [ ] 2.1 In `server/rules/bootstrap/schema.go`, create tables `app_control_policies`,
  `app_control_rules`, `host_groups`, and `app_control_assignments` with the columns described in the
  `server-application-control` capability spec. Include the reserved columns (`default_action`,
  `enforcement`, `source`, `source_ref`, `severity`, `expires_at`) and the
  `(policy_id, rule_type, identifier)` unique key. *Partial: `app_control_policies` + `app_control_rules`
  shipped in PR #152. `host_groups` + `app_control_assignments` deferred (`schema.go:11-13`) - PR-1
  close-out scope below.*
- [ ] 2.2 Add idempotent bootstrap that seeds the built-in `all-hosts` host group, the `Default`
  policy with zero rules and `default_action='NONE'`, and the assignment connecting them. *Partial:
  `Default` policy seed shipped in PR #152 (`appcontrol/store.go:30:EnsureDefaultPolicy`); `all-hosts`
  group + assignment row not yet seeded - PR-1 close-out scope below.*
- [x] 2.3 Per-context integration tests at `server/rules/internal/tests/` covering the seed shape, the
  unique-key dedup, the bootstrap idempotency, and the typed-enum constraints. *Shipped: PR #152
  (`server/rules/internal/tests/app_control_test.go`).*

## 3. Server domain and validation

- [ ] 3.1 New package `server/rules/internal/appcontrol/` with the policy, rule, host-group, and
  assignment store types and their persistence methods. *Partial: policy + rule store shipped in
  PR #155; host-group + assignment store deferred - PR-1 close-out scope below.*
- [ ] 3.2 Public surface on `server/rules/api/`: `ApplicationControlPolicy`, `ApplicationControlRule`,
  `RuleType`, `Action`, `Enforcement`, `Severity`, `Source`, `HostGroup`, `Assignment`, error sentinels
  for validation, and the `SetApplicationControlPayload` codec. *Partial: policy/rule/codec types
  shipped in PR #152; `HostGroup` + `Assignment` types deferred - PR-1 close-out scope below.*
- [ ] 3.3 Per-type identifier validators in `server/rules/internal/appcontrol/validate.go` per the rules
  in the `server-application-control` capability spec (`CDHASH` 40 hex, `BINARY`/`CERTIFICATE` 64 hex,
  `TEAMID` 10 of `[A-Z0-9]`, `SIGNINGID` `<TeamID|platform>:bundle.id`, `PATH` canonical absolute).
  *Partial: shape validators shipped for all six types in PR #152; BINARY accepts, the other five
  return `ErrAppControlUnsupportedRuleType` (`validate.go:25-83`) - PR-1 close-out scope below.*
- [x] 3.4 Path canonicalizer reused from the legacy module (the macOS `/tmp`, `/var`, `/etc` →
  `/private/...` rewrite), promoted into `server/rules/internal/appcontrol/`. *Shipped: PR #152
  (`appcontrol/validate.go:95-115:canonicalizePath`).*
- [ ] 3.5 Fuzz test (`go test -fuzz`) per identifier validator. *Partial: BINARY validator fuzzed;
  the other five wait on type acceptance - PR-1 close-out scope below.*
- [x] 3.6 PBT (`pgregory.net/rapid`) for the `(Marshal, Unmarshal)` round-trip on
  `SetApplicationControlPayload`. *Shipped: PR #152.*

## 4. Decision engine (extension)

- [x] 4.1 New `extension/edr/extension/ApplicationControl/` Swift sources for the typed snapshot, the
  per-`(inode, mtime)` caches for `file_sha256` and `leaf_cert_sha256`, and the precedence walker.
  *Partial: `ApplicationControlStore.swift` + `FileHashCache.swift` shipped in PRs #153 - #155. The
  `leaf_cert_sha256` cache class is not yet created (deferred with the CERTIFICATE rule type to
  Phase B).*
- [ ] 4.2 Implement the target-tuple builder per the `extension-application-control` capability spec:
  read `cdhash`, `team_id`, `signing_id` from `es_process_t`; compute or lookup `file_sha256` lazily;
  compute or lookup `leaf_cert_sha256` via `SecCodeCopySigningInformation` off the AUTH path.
  *Partial: `team_id` is read for the failsafe check and `file_sha256` is looked up for the BINARY
  match in `ESFSubscriber.swift:114-124`. `cdhash`, `signing_id`-as-tuple-component, and `leaf_cert_sha256`
  are not assembled into the target tuple - PR-1 close-out scope below (cdhash + signing_id), Phase B
  for leaf_cert_sha256.*
- [ ] 4.3 Implement the precedence walk in fixed order
  `CDHASH → BINARY → SIGNINGID → CERTIFICATE → TEAMID → PATH` returning on first match. Skip
  unpopulated tuple components. *Partial: walker only consults `binaryRules`
  (`ESFSubscriber.swift:124-146`). The other five maps are populated by `ApplicationControlStore` but
  never read - PR-1 close-out scope below.*
- [x] 4.4 Implement snapshot apply: validate `policy_version` is greater than the current value;
  atomically swap the in-memory snapshot; atomically write the disk snapshot with
  write-temp-then-rename to `/var/db/com.fleetdm.edr/application-control.json`. *Shipped: PR #153
  (`ApplicationControlStore.swift:apply`).*
- [ ] 4.5 Wire the decision engine into `ESFSubscriber.handleAuthExec()`. On match return deny and emit
  the `application_control_block` event; on miss return allow and emit the regular `exec` event.
  *Partial: deny + block-event emission shipped (PRs #153 - #154); the "on miss return allow and emit
  the regular `exec` event" half is met today via NOTIFY_EXEC; the spec's intent that a denied AUTH
  also emit a denied-exec telemetry event is unmet - addressed in the
  `add-application-control-detect-mode` change.*
- [ ] 4.6 Extend the regular `exec` event payload to carry the optional `cdhash`, `signing_id`,
  `team_id`, and `leaf_cert_sha256` fields when their cached values are available. *Partial: `team_id`
  and `signing_id` ship today nested under `code_signing` (`EventSerializer.swift:CodeSigning`);
  `cdhash` and `leaf_cert_sha256` are not on the payload - PR-1 close-out scope (cdhash), Phase B
  (leaf_cert_sha256).*
- [ ] 4.7 Unit tests for the precedence walker on a synthetic snapshot covering each rule type and the
  silent-miss-on-cold-cache path. Tag with `-tags=extensiontest` if needed by the existing Swift test
  harness. *Partial: BINARY-only coverage shipped; the precedence walker tests come with PR-1
  close-out.*
- [ ] 4.8 PBT for the precedence walk invariant: for any random snapshot and random target tuple, the
  walker's decision equals the obvious linear scan in precedence order. Implemented as a Go-side test
  against a port of the walker logic, since the project does not run rapid in Swift; the port is
  exercised by a fixture comparison test that re-runs the same inputs through the Swift walker via the
  extension test harness. *Deferred: lands with the precedence walker in PR-1 close-out.*

## 5. Agent command executor

- [x] 5.1 Add the `set_application_control` command type to `agent/commander/commander.go` with the
  decode-and-forward-to-extension path. Reject malformed payloads, missing `policy_id`, non-positive
  `policy_version`, and unknown `rule_type` values. *Shipped: PR #153.*
- [x] 5.2 Update the `Executor` interface and the agent-side wiring so the new command is recognized
  and the legacy `set_blocklist` is no longer accepted (the demolition step removed its codec; this
  step removes the routing). *Shipped: PRs #151 + #153.*
- [x] 5.3 Integration tests at `agent/internal/tests/` covering the happy path, missing extension
  bridge, malformed payload, and unknown rule type. *Shipped: PR #153.*

## 6. Server REST surface

- [ ] 6.1 New REST handlers under `server/rules/internal/operator/appcontrol_handler.go` covering the
  endpoints listed in the `server-application-control` capability spec (`policies`, `rules`,
  `host-groups`, `assignments`, `bulkUpsert`). *Partial: `GET /policies`, `GET /policies/{id}`,
  `POST /policies/{id}/rules` shipped in PR #155. `PATCH /policies/{id}`, `DELETE /policies/{id}`,
  `PATCH /rules/{id}`, `DELETE /rules/{id}`, `bulkUpsert`, `GET /rules`, `/host-groups/*`,
  `/assignments` not yet - Phase A close-out follow-on below.*
- [x] 6.2 Route registration under `/api/v1/app-control/` in `server/cmd/fleet-edr-server/main.go` (or
  the equivalent router-wiring file in the current layout). Reuse the existing session + CSRF
  middleware. *Shipped: PR #155.*
- [x] 6.3 Error responses follow the existing `ErrorResponse` shape with typed codes prefixed by
  `application_control.`. *Shipped: PR #155.*
- [x] 6.4 Audit-event emission per the `server-application-control` capability spec, including the
  single-event-per-bulk-upsert rule. *Shipped: PR #155 for the create path. Bulk-upsert audit lands
  with the bulk endpoint.*
- [ ] 6.5 Fan-out path: on mutation, gather hosts from every assigned host group, dedup by host id, and
  enqueue exactly one `set_application_control` command per unique host. Record `fanout_hosts` and
  `fanout_failed` as unique-host counts on the audit event. Use the existing command-enqueue path.
  *Partial: per-host enqueue shipped in PR #155, but the assignment-layer resolution is short-circuited
  to "every enrolled host" because `app_control_assignments` doesn't exist yet - PR-1 close-out scope
  below.*
- [ ] 6.6 Integration test for unique-host fan-out: a host that belongs to two assigned host groups
  receives exactly one command, and the audit event's `fanout_hosts` counts that host once. Failing this
  test guards against regression into the duplicate-enqueue shape that CodeRabbit flagged on the spec.
  *Deferred: lands with the assignment-layer in PR-1 close-out.*
- [x] 6.7 Ingest handler for `application_control_block` events binds the event to the host_id resolved
  by the existing host-token middleware. The handler MUST reject (with 4xx) any event whose envelope
  `host_id` does not match the authenticated host. *Shipped: PR #154.*
- [x] 6.8 Integration test for ingest authenticity binding: an authenticated agent posting an event
  with a forged envelope `host_id` (someone else's host) is rejected; an event whose envelope omits
  `host_id` is accepted and stamped with the authenticated host id. *Shipped: PR #154.*
- [x] 6.9 Cross-context integration test at `test/integration/app_control_test.go`: create a rule via
  the REST API, observe the audit event, observe the enqueued command for the test host, observe the
  extension applies the snapshot and denies the matching exec, observe the resulting alert appears via
  the alerts list endpoint with `source='application_control'`. *Shipped: PR #155
  (`test/integration/app_control_block_test.go`, `app_control_rest_test.go`).*

## 7. Detection-pipeline wiring

- [x] 7.1 Update `server/detection/internal/rules/` to recognize the `application_control_block`
  ingest event and map it to an alert per the `server-detection-rules-engine` delta spec.
  *Shipped: PR #154 (`server/rules/internal/catalog/application_control_block.go`).*
- [x] 7.2 Extend the persisted alert schema with a `source` column constrained to
  `('detection','application_control')`. Existing catalog-rule findings backfill to `'detection'`.
  *Shipped: PR #154.*
- [x] 7.3 Promote the alert dedup unique key from `(host_id, rule_id, process_id)` to
  `(source, host_id, rule_id, process_id)`. This is the schema half of the spec contract: a catalog rule
  and an application-control rule that happen to share an identifier never collapse into one row.
  *Shipped: PR #154.*
- [x] 7.4 Integration test for cross-source id collision: insert a `source='detection'` alert and a
  `source='application_control'` alert that share `(host_id, rule_id, process_id)` and assert two rows
  persist. Then re-fire each source against the same triple and assert dedup-within-source holds.
  *Shipped: PR #154.*
- [x] 7.5 Update the alerts read API (`server-rest-api` `Filterable alerts list`) so the `source`
  filter parameter accepts `application_control`. This is a no-op for the requirement text in the
  REST capability since the list is already filterable; verify the handler accepts the new value.
  *Shipped: PR #159 (alert-view source filter chip).*
- [x] 7.6 Integration test: post an `application_control_block` event, observe the persisted alert,
  re-post the same event, observe dedup, fetch via `GET /api/v1/alerts?source=application_control`.
  *Shipped: PR #154 + #159.*

## 8. Web UI

- [x] 8.1 Add the Application Control top-level nav entry and the `/app-control` route.
  *Shipped: PR #157.*
- [x] 8.2 Implement the policies list view at `ui/src/components/ApplicationControl/PoliciesList.tsx`
  showing every policy with its rule count, assigned host-group count, and last modified time.
  *Shipped: PR #157. Assigned host-group count column shows "all-hosts" placeholder until the
  assignment layer lands.*
- [ ] 8.3 Implement the policy detail view at
  `ui/src/components/ApplicationControl/PolicyDetail.tsx` with the filterable rules table, per-row
  enable/disable/edit/delete actions, and the assignment summary. *Partial: read-only table + add-rule
  button shipped in PR #157. Per-row enable/disable/edit/delete buttons render but are non-functional -
  Phase A close-out follow-on.*
- [ ] 8.4 Implement the add-rule modal at
  `ui/src/components/ApplicationControl/AddRuleModal.tsx` with the type selector, type-aware
  identifier validation, optional fields (`custom_msg`, `custom_url`, `severity`, `comment`), and the
  audit-reason gate. *Partial: modal + BINARY validator + custom_msg/custom_url/severity/reason fields
  shipped in PR #157. The other five rule types render with `available: false` and a "coming soon"
  badge - PR-1 close-out scope below (CDHASH/SIGNINGID/TEAMID), Phase B (CERTIFICATE), follow-on (PATH).*
- [ ] 8.5 Implement the paste-many flow at
  `ui/src/components/ApplicationControl/PasteManyModal.tsx` with the per-line type inference rules
  from the web-ui delta spec. *Deferred: lands when at least two rule types accept submission -
  PR-1 close-out scope below.*
- [x] 8.6 Typed API clients in `ui/src/api.ts` for the `/api/v1/app-control/*` endpoints.
  *Shipped: PR #157 for the demo subset; PATCH/DELETE/bulk clients land with the corresponding
  REST surface.*
- [x] 8.7 React Testing Library coverage for the rules-table filter, the add-rule validation, and the
  paste-many inference logic. *Partial: AddRuleModal + PoliciesList + PolicyDetail covered in PR #157;
  paste-many tests land with PR-1 close-out.*

## 9. End-to-end verification on edr-dev VM

- [x] 9.1 Build and install the agent, extension, and server changes onto the `edr-dev` VM following
  the established workflow (signed extension via `codesign --force --sign - --entitlements ...`,
  agent via `sudo ./agent`, server via `task dev:server`). *Shipped: demo dry-run per
  `ai/policy/demo-plan.md`.*
- [ ] 9.2 Author one rule of each `rule_type` against a real binary on the VM, exec the binary,
  verify the AUTH_EXEC denial, the structured `application_control_block` event, and the resulting
  alert in the alerts view. Capture screenshots / logs into `tmp/qa/app-control/` per the project's
  real-tool QA convention. *Partial: BINARY-only verified for the demo recording. The other five rule
  types verify against this checklist as they come online - PR-1 close-out scope below for CDHASH /
  SIGNINGID / TEAMID.*
- [x] 9.3 Confirm via SigNoz (using `mcp__signoz__*` tools) that the decision spans land under
  `service.name="fleet"` and that the new event kind is queryable. *Shipped: demo dry-run.*

## 10. Documentation

- [ ] 10.1 Update `CLAUDE.md` to mention the new bounded subdomain (`server/rules/internal/appcontrol/`)
  and the new event kind in the appropriate place. *Deferred: ride with PR-1 close-out so the
  Documentation section reflects the full Phase A surface, not the demo-cut subset.*
- [ ] 10.2 Add a developer-facing note under `docs/` describing the rule precedence, the lazy
  signing-info cache, and the deferred-failsafe caveat for Phase A. *Deferred: ride with PR-1
  close-out.*

## 11. Phase A close-out scope (PR-1)

A single PR closes out the remaining Phase A surface so this change can be archived. The bundling is
deliberate - every item below either (a) was punted by the demo cut with a comment in the shipped
code, or (b) is needed by the Phase B Detect-mode change (`add-application-control-detect-mode`).

### 11.1 `host_groups` + `app_control_assignments` tables (closes tasks 2.1, 2.2, 3.1, 3.2, 6.5, 6.6, 8.2)

- [ ] 11.1.1 Add `host_groups` and `app_control_assignments` to `schemaStatements` in
  `server/rules/bootstrap/schema.go`. Drop the "deferred to follow-on work" comment.
- [ ] 11.1.2 Extend `EnsureDefaultPolicy` in `server/rules/internal/appcontrol/store.go` to also
  insert the built-in `all-hosts` host group and the single assignment row connecting `Default` to it.
  Idempotent on repeated boot.
- [ ] 11.1.3 Public types `HostGroup` + `Assignment` on `server/rules/api/`.
- [ ] 11.1.4 Fan-out path: resolve hosts via the assignments → host-group → matching-host walk instead
  of "every enrolled host". The `all-hosts` group's criteria matches every host, so observable
  behavior is unchanged for the demo deployment; the code path is correct for future host-group work.
- [ ] 11.1.5 Per-context integration test for the unique-host fan-out across two assignments
  targeting overlapping groups (closes task 6.6).
- [ ] 11.1.6 PoliciesList.tsx: replace the hard-coded "all-hosts" placeholder with the real assignment
  count (still always 1 in Phase A; this is wiring, not visual change).

### 11.2 Three new rule types end-to-end (closes tasks 3.3, 3.5, 4.2, 4.3, 4.7, 4.8, 8.4, 8.5, 9.2)

CDHASH + SIGNINGID + TEAMID land together. CERTIFICATE + PATH stay deferred (CERTIFICATE needs the
`SecCodeCopySigningInformation` cache plumbing the demo cut also deferred; PATH has known Launch
Services indirection edge cases). Both stay in Phase B's scope.

- [ ] 11.2.1 `server/rules/internal/appcontrol/validate.go`: drop the `ErrAppControlUnsupportedRuleType`
  returns at lines 25-26 (for CDHASH/SIGNINGID/TEAMID only) and the matching returns at 59-78. Keep
  the unsupported returns for CERTIFICATE (line 64) and PATH (line 79).
- [ ] 11.2.2 Fuzz tests for the three new validators (closes task 3.5 for these three).
- [ ] 11.2.3 Extension target-tuple extraction: read `cdhash` (20 bytes → 40 hex string, only when
  `process.codesigning_flags & CS_HARD` indicates Hardened Runtime per the spec) and `signing_id` into
  the AUTH-path tuple. `team_id` is already read for the failsafe.
- [ ] 11.2.4 Replace the BINARY-only check in `ESFSubscriber.handleAuthExec` with the precedence walk:
  `CDHASH → BINARY → SIGNINGID → TEAMID → PATH` (skip CERTIFICATE - its map stays unwalked until
  Phase B lands the leaf-cert cache). PATH consulted as a no-op until the validator accepts it; the
  map is empty.
- [ ] 11.2.5 Swift unit tests for the precedence walker covering each of the four wired types and
  the CDHASH hardened-runtime gate.
- [ ] 11.2.6 Go-side PBT (`pgregory.net/rapid`) for the precedence-walk invariant (closes task 4.8).
- [ ] 11.2.7 `AddRuleModal.tsx`: flip `available: true` for CDHASH/SIGNINGID/TEAMID. Add type-aware
  client-side validators (40 hex / 10-char team / `(TeamID|platform):bundle.id` regex).
- [ ] 11.2.8 `PasteManyModal.tsx`: paste-shape inference per the `web-ui` delta spec (closes task 8.5).
  Inference: 10-char `[A-Z0-9]` → TEAMID; 40 hex → CDHASH; 64 hex → BINARY (with CERTIFICATE hint);
  `<TeamID|platform>:bundle.id` → SIGNINGID; absolute path → PATH (disabled, "coming soon").
- [ ] 11.2.9 Integration tests at `test/integration/app_control_block_test.go`: one fixture binary
  per new rule type, assert AUTH_EXEC deny + block event + alert with correct `rule_type`.
- [ ] 11.2.10 Real-tool QA on edr-dev for the three new types (closes task 9.2 for CDHASH/SIGNINGID/TEAMID).

### 11.3 `cdhash` field on every exec event (closes task 4.6 for cdhash)

- [ ] 11.3.1 Add `cdhash` (optional `String?`) to `EventSerializer.ExecPayload`. Populate from
  `target.cdhash` when the process is Hardened-Runtime. Encode with `encodeIfPresent`.
- [ ] 11.3.2 Add `cdhash` (`*string`) to `server/detection/internal/graph/builder.go:execPayload` and
  the corresponding `api.Process` field if downstream consumers need it. Tolerant of absence.
- [ ] 11.3.3 Update `schema/events.json` exec payload schema with optional `cdhash`.

`leaf_cert_sha256` stays deferred until Phase B lands the lazy `SecCodeCopySigningInformation` cache
(it ships paired with the CERTIFICATE rule type for the same reason - both need the same plumbing).

### 11.4 Full REST CRUD (closes task 6.1)

- [ ] 11.4.1 `PATCH /api/v1/app-control/policies/{id}` (rename, description, locked to
  `default_action='NONE'` in Phase A).
- [ ] 11.4.2 `DELETE /api/v1/app-control/policies/{id}` with rule cascade.
- [ ] 11.4.3 `POST /api/v1/app-control/policies` (create new policy beyond the seeded Default).
- [ ] 11.4.4 `PATCH /api/v1/app-control/rules/{id}` - every mutable field. Phase B Detect-mode change
  layers on the `enforcement` toggle; this PR delivers the generic PATCH path.
- [ ] 11.4.5 `DELETE /api/v1/app-control/rules/{id}`.
- [ ] 11.4.6 `POST /api/v1/app-control/policies/{id}/rules:bulkUpsert` with idempotent
  `(policy_id, rule_type, identifier)` semantics. One audit event for the logical operation.
- [ ] 11.4.7 `GET /api/v1/app-control/rules` cross-policy list with filters.
- [ ] 11.4.8 `/host-groups/*` CRUD endpoints. Phase A keeps these read-only-effective by gating
  mutation behind a 405 (Method Not Allowed) for non-`all-hosts` operations; the table exists, the
  full editing UX lands in Phase B.
- [ ] 11.4.9 `POST /api/v1/app-control/policies/{id}/assignments` (Phase A only ever creates the seed
  assignment; endpoint exists for completeness and the spec's API-first contract).
- [ ] 11.4.10 UI: per-row enable/disable/edit/delete actions in PolicyDetail.tsx wired to the new
  PATCH/DELETE endpoints (closes task 8.3).

### 11.5 Documentation (closes tasks 10.1, 10.2)

- [ ] 11.5.1 Add the new event kind, the new bounded subdomain, and the rule-precedence walk to
  `CLAUDE.md` in the appropriate place.
- [ ] 11.5.2 Developer-facing note under `docs/` covering rule precedence, the lazy file-hash cache,
  the deferred-failsafe caveat, and the deferred CERTIFICATE/PATH/leaf-cert work that lives in
  Phase B.

### Not in Phase A close-out, intentionally

- **Per-rule Detect mode semantics** - separate change
  (`openspec/changes/add-application-control-detect-mode/`). Implemented after this close-out PR.
- **Lockdown / allowlist / failsafe-list / pre-deploy simulation** - Phase B proper, separate
  change.
- **CERTIFICATE + PATH rule types** - Phase B (CERTIFICATE needs leaf-cert cache plumbing; PATH
  needs Launch Services indirection coverage).
- **Editable host groups + multi-policy assignments** - Phase B (UI work; schema is ready).
