# Application Control rollout tasks

## 1. Demolition (single PR, delete the legacy scaffolding)

- [ ] 1.1 Delete `server/rules/internal/policy/` package, the `policies` table from
  `server/rules/bootstrap/schema.go`, the `BlocklistPolicy` types from `server/rules/api/types.go`,
  and their tests.
- [ ] 1.2 Delete the `GET /api/policy` and `PUT /api/policy` handlers and routes from
  `server/rules/internal/operator/handler.go` and the corresponding `server-rest-api` wiring.
- [ ] 1.3 Delete the `set_blocklist` command type and the `setBlocklistPayload` codec from
  `agent/commander/commander.go`. Delete the `PolicySender` interface and any unit tests pinned to it.
- [ ] 1.4 Delete `extension/edr/extension/PolicyStore.swift`, the `/var/db/com.fleetdm.edr/policy.json`
  read path, and the `Set<String>` blocklist lookup site in `extension/edr/extension/ESFSubscriber.swift`.
  Leave AUTH_EXEC as an unconditional allow until task 4.5 lands the new decision engine call site.
- [ ] 1.5 Delete `ui/src/components/PolicyEditor.tsx`, the `/policy` route, and the `fetchPolicy` /
  `updatePolicy` clients from `ui/src/api.ts`. Remove the policy nav entry.
- [ ] 1.6 Update `schema/events.json` to remove any references to the legacy blocklist payload (none
  expected, but verify).
- [ ] 1.7 Run the test suite; expect the pre-existing policy tests to vanish and nothing else to fail.

## 2. Schema and seed

- [ ] 2.1 In `server/rules/bootstrap/schema.go`, create tables `app_control_policies`,
  `app_control_rules`, `host_groups`, and `app_control_assignments` with the columns described in the
  `server-application-control` capability spec. Include the reserved columns (`default_action`,
  `enforcement`, `source`, `source_ref`, `severity`, `expires_at`) and the
  `(tenant_id, rule_type, identifier)` unique key.
- [ ] 2.2 Add per-tenant idempotent bootstrap that seeds the built-in `all-hosts` host group, the
  `Default` policy with zero rules and `default_action='NONE'`, and the assignment connecting them.
- [ ] 2.3 Per-context integration tests at `server/rules/internal/tests/` covering the seed shape, the
  unique-key dedup, the bootstrap idempotency, and the typed-enum constraints.

## 3. Server domain and validation

- [ ] 3.1 New package `server/rules/internal/appcontrol/` with the policy, rule, host-group, and
  assignment store types and their persistence methods.
- [ ] 3.2 Public surface on `server/rules/api/`: `ApplicationControlPolicy`, `ApplicationControlRule`,
  `RuleType`, `Action`, `Enforcement`, `Severity`, `Source`, `HostGroup`, `Assignment`, error sentinels
  for validation, and the `SetApplicationControlPayload` codec.
- [ ] 3.3 Per-type identifier validators in `server/rules/internal/appcontrol/validate.go` per the rules
  in the `server-application-control` capability spec (`CDHASH` 40 hex, `BINARY`/`CERTIFICATE` 64 hex,
  `TEAMID` 10 of `[A-Z0-9]`, `SIGNINGID` `<TeamID|platform>:bundle.id`, `PATH` canonical absolute).
- [ ] 3.4 Path canonicalizer reused from the legacy module (the macOS `/tmp`, `/var`, `/etc` →
  `/private/...` rewrite), promoted into `server/rules/internal/appcontrol/`.
- [ ] 3.5 Fuzz test (`go test -fuzz`) per identifier validator.
- [ ] 3.6 PBT (`pgregory.net/rapid`) for the `(Marshal, Unmarshal)` round-trip on
  `SetApplicationControlPayload`.

## 4. Decision engine (extension)

- [ ] 4.1 New `extension/edr/extension/ApplicationControl/` Swift sources for the typed snapshot, the
  per-`(inode, mtime)` caches for `file_sha256` and `leaf_cert_sha256`, and the precedence walker.
- [ ] 4.2 Implement the target-tuple builder per the `extension-application-control` capability spec:
  read `cdhash`, `team_id`, `signing_id` from `es_process_t`; compute or lookup `file_sha256` lazily;
  compute or lookup `leaf_cert_sha256` via `SecCodeCopySigningInformation` off the AUTH path.
- [ ] 4.3 Implement the precedence walk in fixed order
  `CDHASH → BINARY → SIGNINGID → CERTIFICATE → TEAMID → PATH` returning on first match. Skip
  unpopulated tuple components.
- [ ] 4.4 Implement snapshot apply: validate `policy_version` is greater than the current value;
  atomically swap the in-memory snapshot; atomically write the disk snapshot with
  write-temp-then-rename to `/var/db/com.fleetdm.edr/application-control.json`.
- [ ] 4.5 Wire the decision engine into `ESFSubscriber.handleAuthExec()`. On match return deny and emit
  the `application_control_block` event; on miss return allow and emit the regular `exec` event.
- [ ] 4.6 Extend the regular `exec` event payload to carry the optional `cdhash`, `signing_id`,
  `team_id`, and `leaf_cert_sha256` fields when their cached values are available.
- [ ] 4.7 Unit tests for the precedence walker on a synthetic snapshot covering each rule type and the
  silent-miss-on-cold-cache path. Tag with `-tags=extensiontest` if needed by the existing Swift test
  harness.
- [ ] 4.8 PBT for the precedence walk invariant: for any random snapshot and random target tuple, the
  walker's decision equals the obvious linear scan in precedence order. Implemented as a Go-side test
  against a port of the walker logic, since the project does not run rapid in Swift; the port is
  exercised by a fixture comparison test that re-runs the same inputs through the Swift walker via the
  extension test harness.

## 5. Agent command executor

- [ ] 5.1 Add the `set_application_control` command type to `agent/commander/commander.go` with the
  decode-and-forward-to-extension path. Reject malformed payloads, missing `policy_id`, non-positive
  `policy_version`, and unknown `rule_type` values.
- [ ] 5.2 Update the `Executor` interface and the agent-side wiring so the new command is recognized
  and the legacy `set_blocklist` is no longer accepted (the demolition step removed its codec; this
  step removes the routing).
- [ ] 5.3 Integration tests at `agent/internal/tests/` covering the happy path, missing extension
  bridge, malformed payload, and unknown rule type.

## 6. Server REST surface

- [ ] 6.1 New REST handlers under `server/rules/internal/operator/appcontrol_handler.go` covering the
  endpoints listed in the `server-application-control` capability spec (`policies`, `rules`,
  `host-groups`, `assignments`, `bulkUpsert`).
- [ ] 6.2 Route registration under `/api/v1/app-control/` in `server/cmd/fleet-edr-server/main.go` (or
  the equivalent router-wiring file in the current layout). Reuse the existing session + CSRF
  middleware.
- [ ] 6.3 Error responses follow the existing `ErrorResponse` shape with typed codes prefixed by
  `application_control.`.
- [ ] 6.4 Audit-event emission per the `server-application-control` capability spec, including the
  single-event-per-bulk-upsert rule.
- [ ] 6.5 Fan-out path: on mutation, enqueue `set_application_control` commands for hosts that belong
  to assigned groups; record `fanout_hosts` and `fanout_failed` on the audit event. Use the existing
  command-enqueue path.
- [ ] 6.6 Cross-context integration test at `test/integration/app_control_test.go`: create a rule via
  the REST API, observe the audit event, observe the enqueued command for the test host, observe the
  extension applies the snapshot and denies the matching exec, observe the resulting alert appears via
  the alerts list endpoint with `source='application_control'`.

## 7. Detection-pipeline wiring

- [ ] 7.1 Update `server/detection/internal/rules/` to recognize the `application_control_block`
  ingest event and map it to an alert per the `server-detection-rules-engine` delta spec.
- [ ] 7.2 Extend the persisted alert schema with a `source` column constrained to
  `('detection','application_control')`. Existing catalog-rule findings backfill to `'detection'`.
- [ ] 7.3 Extend the alert dedup key to honor `(host_id, rule_id, process_id)` across sources without
  collision. The existing column-level unique key already covers this; verify with an integration
  test.
- [ ] 7.4 Update the alerts read API (`server-rest-api` `Filterable alerts list`) so the `source`
  filter parameter accepts `application_control`. This is a no-op for the requirement text in the
  REST capability since the list is already filterable; verify the handler accepts the new value.
- [ ] 7.5 Integration test: post an `application_control_block` event, observe the persisted alert,
  re-post the same event, observe dedup, fetch via `GET /api/v1/alerts?source=application_control`.

## 8. Web UI

- [ ] 8.1 Add the Application Control top-level nav entry and the `/app-control` route.
- [ ] 8.2 Implement the policies list view at `ui/src/components/ApplicationControl/PoliciesList.tsx`
  showing every policy with its rule count, assigned host-group count, and last modified time.
- [ ] 8.3 Implement the policy detail view at
  `ui/src/components/ApplicationControl/PolicyDetail.tsx` with the filterable rules table, per-row
  enable/disable/edit/delete actions, and the assignment summary.
- [ ] 8.4 Implement the add-rule modal at
  `ui/src/components/ApplicationControl/AddRuleModal.tsx` with the type selector, type-aware
  identifier validation, optional fields (`custom_msg`, `custom_url`, `severity`, `comment`), and the
  audit-reason gate.
- [ ] 8.5 Implement the paste-many flow at
  `ui/src/components/ApplicationControl/PasteManyModal.tsx` with the per-line type inference rules
  from the web-ui delta spec.
- [ ] 8.6 Typed API clients in `ui/src/api.ts` for the `/api/v1/app-control/*` endpoints.
- [ ] 8.7 React Testing Library coverage for the rules-table filter, the add-rule validation, and the
  paste-many inference logic.

## 9. End-to-end verification on edr-dev VM

- [ ] 9.1 Build and install the agent, extension, and server changes onto the `edr-dev` VM following
  the established workflow (signed extension via `codesign --force --sign - --entitlements ...`,
  agent via `sudo ./agent`, server via `task dev:server`).
- [ ] 9.2 Author one rule of each `rule_type` against a real binary on the VM, exec the binary,
  verify the AUTH_EXEC denial, the structured `application_control_block` event, and the resulting
  alert in the alerts view. Capture screenshots / logs into `tmp/qa/app-control/` per the project's
  real-tool QA convention.
- [ ] 9.3 Confirm via SigNoz (using `mcp__signoz__*` tools) that the decision spans land under
  `service.name="fleet"` and that the new event kind is queryable.

## 10. Documentation

- [ ] 10.1 Update `CLAUDE.md` to mention the new bounded subdomain (`server/rules/internal/appcontrol/`)
  and the new event kind in the appropriate place.
- [ ] 10.2 Add a developer-facing note under `docs/` describing the rule precedence, the lazy
  signing-info cache, and the deferred-failsafe caveat for Phase A.
